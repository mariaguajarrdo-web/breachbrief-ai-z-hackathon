"""Phase 2: human approval. Only a named reviewer decides; the app exports drafts and never sends."""
import json

import pytest

from breachbrief import agent, approval, protocol
from breachbrief.approval import ApprovalError, approve
from breachbrief.brane_client import MockBrane


@pytest.fixture(autouse=True)
def tmp_exports(tmp_path, monkeypatch):
    monkeypatch.setattr(approval, "EXPORT_DIR", tmp_path / "exports")
    return tmp_path / "exports"


@pytest.fixture
def run():
    return agent.run("hospital_ransomware", client=MockBrane())


def protocol_entry(run_id):
    return json.loads((protocol.PROTOCOL_DIR / f"{run_id}.json").read_text(encoding="utf-8"))


def test_approve_both_exports_markdown_and_records_protocol(run, tmp_exports):
    a = approve(run, reviewer="Test Reviewer (DPO)", risk_level="high", notify="authority,csirt,affected_people")
    md = a.export_path.read_text(encoding="utf-8")
    assert a.export_path.parent == tmp_exports and a.export_path.suffix == ".md"
    assert "Not sent" in md and "Test Reviewer (DPO)" in md and "**High risk (also inform affected people, Art. 34)**" in md
    assert "## Notification to the data protection authority" in md and "## Notice to affected people" in md
    assert "## NIS2 early warning to the CSIRT" in md
    assert "NIS2" in md and "2026-11-21T06:30" in md                     # deadlines carried over
    entry = protocol_entry(run.run_id)["human_approval"]
    assert entry["reviewer"] == "Test Reviewer (DPO)" and entry["confirmed_risk_level"] == "high"
    assert entry["notify"] == ["authority", "csirt", "affected_people"] and entry["sent_by_app"] is False


def test_only_selected_drafts_exported(run):
    a = approve(run, reviewer="R", risk_level="low", notify=["authority", "csirt"], reason="")
    md = a.export_path.read_text(encoding="utf-8")
    assert "## Notification to the data protection authority" in md and "Notice to affected people" not in md


def test_none_requires_reason(run, tmp_exports):
    with pytest.raises(ApprovalError, match="reason"):
        approve(run, reviewer="R", risk_level="low", notify="none")
    assert not tmp_exports.exists() or not any(tmp_exports.iterdir())     # nothing exported
    assert "human_approval" not in protocol_entry(run.run_id)             # nothing recorded
    a = approve(run, reviewer="R", risk_level="low", notify="none", reason="Encrypted laptop, key not compromised.")
    assert protocol_entry(run.run_id)["human_approval"]["notify"] == ["none"]
    assert "**Nobody**" in a.export_path.read_text(encoding="utf-8")


def test_high_risk_without_affected_people_requires_reason(run):
    with pytest.raises(ApprovalError, match="Art. 34"):
        approve(run, reviewer="R", risk_level="high", notify="authority")


@pytest.mark.parametrize("kwargs", [
    dict(reviewer="", risk_level="high", notify="authority,affected_people"),
    dict(reviewer="R", risk_level="medium", notify="authority"),
    dict(reviewer="R", risk_level="high", notify="authority,press"),
    dict(reviewer="R", risk_level="high", notify="none,authority", reason="x"),
])
def test_invalid_approvals_rejected(run, kwargs):
    with pytest.raises(ApprovalError):
        approve(run, **kwargs)


def test_agent_never_approves_by_itself(run):
    assert run.needs_human_approval is True
    assert "human_approval" not in protocol_entry(run.run_id)


def test_approval_without_ai_uses_template_once_completed():
    """No model answered: the non-AI template is offered, and approval waits until its [fields] are completed."""
    import dataclasses
    r = agent.run("hospital_ransomware", client=MockBrane(simulate_down=True))
    assert r.model_output is None and r.fallback_drafts
    with pytest.raises(ApprovalError, match="bracketed fields"):
        approve(r, reviewer="R", risk_level="high", notify="authority,csirt,affected_people")
    completed = {k: (v.replace("[", "").replace("]", "") if isinstance(v, str) else v)
                 for k, v in r.fallback_drafts.items()}
    a = approve(dataclasses.replace(r, fallback_drafts=completed), reviewer="R", risk_level="high",
                notify="authority,csirt,affected_people")
    assert "Template drafted without AI" in a.export_path.read_text(encoding="utf-8")


def test_drafts_labelled_ai_assisted(run):
    """LEGAL.md section 4: exported drafts are labelled as AI-assisted and name the reviewer."""
    a = approve(run, reviewer="Test Reviewer", risk_level="high", notify="authority,csirt,affected_people")
    md = a.export_path.read_text(encoding="utf-8")
    assert md.count("_AI-assisted draft, reviewed and approved by Test Reviewer._") == 3


# ---- UI batch 1: three risk tiers, one recipient per applicable regime, complete drafts -----------------------
def test_three_risk_tiers_and_legacy_low():
    from breachbrief.approval import RISK_TIERS
    assert list(RISK_TIERS) == ["unlikely", "risk", "high"]
    r = agent.run("payroll_misdirected", client=MockBrane())
    assert approve(r, reviewer="R", risk_level="low", notify="authority").risk_level == "risk"
    a = approve(r, reviewer="R", risk_level="unlikely", notify="none", reason="Encrypted, key safe (Art. 33(1)).")
    assert a.risk_level == "unlikely" and a.notify == []


def test_recipients_follow_the_regimes():
    from breachbrief import drafts
    for scenario, expected in [("payroll_misdirected", ["authority", "affected_people"]),
                               ("hospital_ransomware", ["authority", "csirt", "affected_people"]),
                               ("bank_ict_incident", ["authority", "financial_supervisor", "affected_people"])]:
        r = agent.run(scenario, client=MockBrane())
        assert drafts.recipients_for(r.regimes) == expected
    r = agent.run("payroll_misdirected", client=MockBrane())
    with pytest.raises(ApprovalError, match="does not apply"):
        approve(r, reviewer="R", risk_level="risk", notify="authority,csirt")


def test_skipping_an_applicable_regime_needs_a_reason():
    r = agent.run("bank_ict_incident", client=MockBrane())
    with pytest.raises(ApprovalError, match="DORA"):
        approve(r, reviewer="R", risk_level="risk", notify="authority")
    approve(r, reviewer="R", risk_level="risk", notify="authority,financial_supervisor")


def test_open_bracket_field_blocks_approval():
    import dataclasses
    r = agent.run("payroll_misdirected", client=MockBrane())
    edited = {**r.model_output, "draft_authority_notification": "Contact our DPO at [DPO email]."}
    with pytest.raises(ApprovalError, match=r"\[DPO email\]"):
        approve(dataclasses.replace(r, model_output=edited), reviewer="R", risk_level="risk", notify="authority")


def test_seal_records_name_role_and_amsterdam_time(run):
    a = approve(run, reviewer="J. Jansen", role="DPO", risk_level="high", notify="authority,csirt,affected_people")
    assert a.approved_at_local.endswith("(Amsterdam)")
    entry = protocol_entry(run.run_id)["human_approval"]
    assert entry["role"] == "DPO" and entry["approved_at_amsterdam"].endswith("(Amsterdam)")
    assert "J. Jansen (DPO)" in a.export_path.read_text(encoding="utf-8")
