"""Leak guard tests (POLICY_MATRIX.md): the final local guard re-scans the exact outgoing payload
and stops the request if anything protected is still in it, even if an earlier step failed."""
from breachbrief import agent, policy
from breachbrief.brane_client import MockBrane


def broken_policy(text, vault, *args, **kwargs):
    """Simulates a bug in the sanitiser: returns the text untouched."""
    return policy.Applied(sanitized=text, decisions=[], local_only=[], health_involved=False, injection_blocked=False)


def test_guard_blocks_when_sanitiser_fails(monkeypatch):
    monkeypatch.setattr(policy, "apply", broken_policy)
    client = MockBrane()
    r = agent.run("payroll_misdirected", client=client)
    assert r.status == "blocked_leak"
    assert r.payload_sent is None and r.model_output is None
    assert client.forwarded == []                                   # nothing reached BRANE
    assert "Nothing sent" in r.message


def test_guard_reports_categories_not_values(monkeypatch):
    monkeypatch.setattr(policy, "apply", broken_policy)
    r = agent.run("bank_ict_incident", client=MockBrane())
    assert r.status == "blocked_leak"
    for cat in ("IBAN", "PERSON_NAME"):
        assert cat in r.message
    assert "NL60RABO3636015360" not in r.message and "Jan de Boer" not in r.message


def test_guard_clean_on_normal_runs():
    for scenario in ("payroll_misdirected", "hospital_ransomware", "bank_ict_incident"):
        r = agent.run(scenario, client=MockBrane())
        assert r.status == "ok"
        assert policy.residual_leaks(r.payload_sent) == []
