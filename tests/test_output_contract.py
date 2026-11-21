"""Phase 2: model output contract. Invalid answer -> one retry through BRANE -> fail safely."""
import json

from breachbrief import agent, protocol
from breachbrief.brane_client import BraneUnavailable, MockBrane

GOOD = json.dumps({
    "incident_summary": "Ransomware with suspected exfiltration.",
    "missing_facts": ["Scope of exfiltration?"],
    "suggested_risk_level": "high",
    "draft_authority_notification": "Dear authority, PERSON_001 is our contact for this incident.",
    "draft_affected_people_notice": "Dear patient, ...",
    "draft_nis2_early_warning": "Early warning to Z-CERT ...",   # hospital is a NIS2 essential entity
})
# A bad answer that echoes a placeholder plus a marker, to prove the retry never carries the model's answer.
BAD_MISSING_KEYS = json.dumps({"incident_summary": "MARKER-BAD-ANSWER", "draft_authority_notification": "Dear PERSON_001"})
RAW_VALUES = ["Sven Hoekstra", "Hoekstra", "sven.hoekstra@stmaartenzorg.example", "0652512437", "Lucas Peters",
              "290937759", "01-03-1961"]


def test_valid_first_answer_single_call():
    client = MockBrane(responses=[GOOD])
    r = agent.run("hospital_ransomware", client=client)
    assert r.status == "ok" and len(client.forwarded) == 1
    assert "Sven Hoekstra" in r.model_output["draft_authority_notification"]   # restored locally, after validation


def test_invalid_json_then_valid_retry_succeeds():
    client = MockBrane(responses=["Sure! Here is the analysis you asked for.", GOOD])
    r = agent.run("hospital_ransomware", client=client)
    assert r.status == "ok" and len(client.forwarded) == 2
    retry = client.forwarded[1]["user"]
    assert retry.startswith(client.forwarded[0]["user"])              # same sanitised payload ...
    assert "<format_error>" in retry and "not valid JSON" in retry    # ... plus our fixed note only
    assert "Sure! Here is" not in retry


def test_missing_keys_twice_fails_safely():
    client = MockBrane(responses=[BAD_MISSING_KEYS, BAD_MISSING_KEYS])
    r = agent.run("hospital_ransomware", client=client)
    assert r.status == "invalid_model_output"
    assert len(client.forwarded) == 2                                  # exactly one retry
    assert r.model_output is None
    assert "missing key 'missing_facts'" in r.message and "manually" in r.message
    assert r.earliest_deadline                                        # deadlines still shown to the human


def test_retry_never_contains_raw_values_or_model_answer():
    client = MockBrane(responses=[BAD_MISSING_KEYS, GOOD])
    agent.run("hospital_ransomware", client=client)
    retry = client.forwarded[1]["user"]
    assert "MARKER-BAD-ANSWER" not in retry and "Dear PERSON_001" not in retry
    for sent in client.forwarded:
        for v in RAW_VALUES:
            assert v.lower() not in sent["user"].lower(), f"raw value {v!r} sent"


def test_wrong_types_rejected():
    bad = json.loads(GOOD)
    bad["missing_facts"] = "one string instead of a list"
    bad["suggested_risk_level"] = ""
    out, problems = agent.validate_output(json.dumps(bad))
    assert out is None and len(problems) == 2


def test_fenced_json_accepted():
    out, problems = agent.validate_output("```json\n" + GOOD + "\n```")
    assert problems == [] and out["suggested_risk_level"] == "high"


def test_brane_down_on_retry_fails_closed():
    class DownOnSecondCall(MockBrane):
        def complete(self, system, user):
            if self.forwarded:
                raise BraneUnavailable("down on retry (simulated)")
            return super().complete(system, user)
    r = agent.run("hospital_ransomware", client=DownOnSecondCall(responses=["not json"]))
    assert r.status == "brane_unavailable" and r.model_output is None


def test_every_retry_note_is_detector_clean():
    """The retry note itself must never trip the final leak guard (that would silently drop the retry)."""
    from breachbrief import detectors
    cases = ["", "Sure!", "[1, 2]", "{}", json.dumps({k: "" for k in agent.OUTPUT_CONTRACT}),
             json.dumps({k: 5 for k in agent.OUTPUT_CONTRACT}), BAD_MISSING_KEYS]
    for c in cases:
        _, problems = agent.validate_output(c)
        assert problems
        assert detectors.detect(agent.retry_note(problems)) == [], problems


def test_protocol_records_attempts():
    r = agent.run("hospital_ransomware", client=MockBrane(responses=["not json", GOOD]))
    entry = json.loads((protocol.PROTOCOL_DIR / f"{r.run_id}.json").read_text(encoding="utf-8"))
    assert entry["outcome"] == "SENT_VIA_BRANE" and entry["attempts"] == 2
