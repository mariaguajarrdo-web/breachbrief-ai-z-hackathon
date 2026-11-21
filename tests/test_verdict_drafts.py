"""UI batch 1 logic: the honest verdict (post-BRANE counts, plain rules), drafts per regime filled locally,
facts filtering, non-AI templates, and the demo clock."""
import json
from datetime import datetime

import pytest

from breachbrief import agent, drafts, verdict
from breachbrief.brane_client import BraneRefused, MockBrane


# ---- verdict ------------------------------------------------------------------------------
@pytest.mark.parametrize("headers, state", [
    ({"X-Brane-Routed-To": "cloud"}, "CLOUD"),
    ({"X-Brane-Routed-To": "local", "X-Brane-Local-Cause": "semantic_category_local",
      "X-Brane-Semantic-Matches": "INDIRECT_HEALTH_CONTEXT"}, "LOCAL"),
])
def test_states_from_headers(headers, state):
    class C(MockBrane):
        def complete(self, system, user):
            out = super().complete(system, user)
            out["brane"]["headers"] = headers
            return out
    r = agent.run("payroll_misdirected", client=C())
    v = verdict.compute(r, gateway="LIVE", preview=r.payload_sent)
    assert v.state == state and v.title == verdict.STATE_TITLE[state]


def test_refused_and_nothing_sent_states():
    class Refuser(MockBrane):
        def complete(self, system, user):
            raise BraneRefused("no", {"X-Brane-Routed-To": "refused",
                                      "X-Brane-Refused-By": "category:DATE_OF_BIRTH->refuse"})
    v = verdict.compute(agent.run("hospital_ransomware", client=Refuser()))
    assert v.state == "REFUSED" and v.rule == "Rule that fired: date of birth -> refuse"
    assert v.identifiers_reached == 0 and "No model received anything" in v.sentence
    v = verdict.compute(agent.run("hospital_ransomware", client=MockBrane(simulate_down=True)), gateway="MOCK")
    assert v.state == "NOTHING_SENT" and v.title == "BRANE unreachable, fail closed, no fallback"


def test_kpi_is_counted_after_brane_and_not_zero_in_guard_only():
    """guard_only + a gateway that sends names as typed: the KPI must show them, not 0."""
    full = verdict.compute(agent.run("payroll_misdirected", client=MockBrane(), premask="full"), gateway="MOCK")
    guard = verdict.compute(agent.run("payroll_misdirected", client=MockBrane(), premask="guard_only"),
                            gateway="MOCK")
    assert full.identifiers_reached == 0
    assert guard.identifiers_reached > 0 and any("name" in k for k in guard.identifier_kinds)
    assert guard.health_reached >= 1


def test_kpi_uses_brane_preview_when_brane_placeholdered():
    r = agent.run("payroll_misdirected", client=MockBrane(), premask="guard_only")
    preview = "Reported by PERSON_REF_1 (HR Operations), EMAIL_REF_1, phone PHONE_REF_1. The file went out."
    v = verdict.compute(r, gateway="LIVE", preview=preview)
    assert v.identifiers_reached == 0 and "preview" in v.basis


def test_hidden_instructions_counted():
    v = verdict.compute(agent.run("hospital_ransomware", client=MockBrane()), gateway="MOCK")
    assert v.instructions_removed == 1 and "1 hidden instruction removed" in v.sentence


@pytest.mark.parametrize("headers, line", [
    ({"X-Brane-Refused-By": "semantic:RAW_DATASET_EXFILTRATION->refuse"},
     "Rule that fired: request for the raw dataset -> refuse"),
    ({"X-Brane-Routed-To": "local", "X-Brane-Local-Cause": "prompt_injection_local"},
     "Routed locally because: suspected hidden instruction or content BRANE could not read"),
    ({"X-Brane-Routed-To": "local", "X-Brane-Local-Cause": "data_category_local", "X-Brane-Pii-Types": "PERSON,HEALTH_DATA"},
     "Routed locally because: health data"),
    ({"X-Brane-Routed-To": "cloud"}, None),
    # live BRANE also sends Policy-Triggers on a local route: still "routed locally because", not "rule that fired"
    ({"X-Brane-Routed-To": "local", "X-Brane-Local-Cause": "semantic_category_local",
      "X-Brane-Semantic-Matches": "INDIRECT_HEALTH_CONTEXT", "X-Brane-Policy-Triggers": "semantic:INDIRECT_HEALTH_CONTEXT->local"},
     "Routed locally because: indirect health context"),
    ({"X-Brane-Routed-To": "refused", "X-Brane-Policy-Triggers": "category:DATE_OF_BIRTH->refuse"},
     "Rule that fired: date of birth -> refuse"),
])
def test_plain_rules(headers, line):
    assert verdict.plain_rule(headers) == line


# ---- drafts ---------------------------------------------------------------------------------
def test_drafts_per_regime_are_requested_and_returned():
    for scenario, extra in [("payroll_misdirected", None), ("hospital_ransomware", "draft_nis2_early_warning"),
                            ("bank_ict_incident", "draft_dora_initial_notification")]:
        client = MockBrane()
        r = agent.run(scenario, client=client)
        system = client.forwarded[0]["system"]
        if extra:
            assert extra in system and extra in r.model_output
        assert "draft_nis2_early_warning" not in system or scenario == "hospital_ransomware"


def test_regime_drafts_go_through_the_same_safety_pipeline():
    client = MockBrane()
    r = agent.run("hospital_ransomware", client=client)
    sent = client.forwarded[0]["user"]
    assert "Sven Hoekstra" not in sent and "290937759" not in sent      # one payload, same guard for every draft


def test_known_fields_filled_locally_after_the_model_step():
    client = MockBrane()
    r = agent.run("bank_ict_incident", client=client)
    assert "Noordbank" not in client.forwarded[0]["user"]              # the model never got the organisation name
    auth = r.model_output["draft_authority_notification"]
    assert "Noordbank N.V." in auth and "Autoriteit Persoonsgegevens" in auth and "[" not in auth
    dora = r.model_output["draft_dora_initial_notification"]
    assert "De Nederlandsche Bank" in dora and "[" not in dora


def test_unknown_fields_stay_for_the_reviewer():
    facts = drafts.facts_from({"organisation": "X B.V.", "aware_at": "2026-11-20T06:30"}, {"record_count": 3}, [])
    text = drafts.fill_known_fields("[Organisation] was aware on [date of awareness]; DPO: [DPO email]", facts)
    assert text == "X B.V. was aware on 20 November 2026, 06:30; DPO: [DPO email]"
    assert drafts.open_placeholders(text) == ["[DPO email]"]


def test_summary_and_facts_are_reidentified_locally():
    reply = json.dumps({"incident_summary": "PERSON_001 reported the breach.",
                        "missing_facts": ["Did PERSON_001 delete the email?"], "suggested_risk_level": "high",
                        "draft_authority_notification": "a", "draft_affected_people_notice": "p"})
    r = agent.run("payroll_misdirected", client=MockBrane(responses=[reply]))
    assert r.model_output["incident_summary"] == "Marloes Kuipers reported the breach."
    assert r.model_output["missing_facts"] == ["Did Marloes Kuipers delete the email?"]


def test_facts_top5_without_what_the_app_knows():
    facts = ["When did the organisation become aware of the breach?", "How many people are affected?",
             "Which categories of data were involved?", "Was the file opened?", "Has deletion been confirmed?",
             "Were backups encrypted?", "Who else received it?", "Was law enforcement informed?",
             "Is there a written confirmation?"]
    out = drafts.useful_facts(facts)
    assert len(out) == 5 and out[0] == "Was the file opened?"
    assert not any("aware" in f or "How many" in f or "categories" in f for f in out)


def test_template_drafts_when_nothing_was_sent():
    r = agent.run("bank_ict_incident", client=MockBrane(simulate_down=True))
    t = r.fallback_drafts
    assert r.model_output is None and "Template prepared without AI" in t["template_note"]
    for key in ("draft_authority_notification", "draft_affected_people_notice", "draft_dora_initial_notification"):
        assert key in t
    assert "Noordbank N.V." in t["draft_authority_notification"]
    assert drafts.open_placeholders(t["draft_authority_notification"])   # reviewer must complete it


# ---- demo clock -----------------------------------------------------------------------------
def test_demo_clock_offsets():
    import app
    anchor = datetime(2026, 11, 21, 9, 0)
    for scenario, aware, classified in [("payroll_misdirected", "2026-11-21T07:00", None),
                                        ("hospital_ransomware", "2026-11-21T08:00", None),
                                        ("bank_ict_incident", "2026-11-21T05:40", "2026-11-21T08:30")]:
        meta = agent.load_scenario(scenario)[0]
        t = app.demo_timing(scenario, meta, anchor)
        assert t["aware_at"] == aware and t.get("classified_major_at") == classified


def test_demo_clock_moves_the_deadlines():
    r = agent.run("hospital_ransomware", client=MockBrane(), timing={"aware_at": "2026-11-21T08:00"})
    assert r.earliest_deadline == "2026-11-22T08:00"                  # NIS2 early warning: T+24h
    assert "Awareness time: 2026-11-21T08:00" in r.payload_sent


def test_estimate_is_labelled_when_brane_preview_is_unavailable():
    class C(MockBrane):
        def complete(self, system, user):
            out = super().complete(system, user)
            out["brane"]["headers"] = {"X-Brane-Routed-To": "cloud", "X-Brane-Placeholder-Types": "PERSON,EMAIL"}
            return out
    r = agent.run("hospital_ransomware", client=C(), premask="guard_only")
    v = verdict.compute(r, client=None, gateway="LIVE")                 # no preview available
    assert v.basis.startswith("estimated") and "(estimated from BRANE's headers" in v.sentence
    assert v.health_reached >= 1                                          # health text is honestly counted
    assert not any("name" in k or "email" in k for k in v.identifier_kinds)   # BRANE placeholdered those
