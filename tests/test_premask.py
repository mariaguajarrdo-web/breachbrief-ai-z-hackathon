"""LOCAL_PREMASK modes. full = everything masked locally (default, and what the AI-Z tests run).
guard_only = names, emails, phones and health text are left for BRANE's own policy."""
import pytest

from breachbrief import agent, policy
from breachbrief.brane_client import MockBrane


def test_default_is_full(monkeypatch):
    monkeypatch.delenv("LOCAL_PREMASK", raising=False)
    assert agent.premask_mode() == "full"
    r = agent.run("payroll_misdirected", client=MockBrane())
    assert r.premask == "full" and "Marloes Kuipers" not in r.payload_sent


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        agent.run("payroll_misdirected", client=MockBrane(), premask="off")


def test_guard_only_leaves_names_contacts_health_for_brane():
    r = agent.run("payroll_misdirected", client=MockBrane(), premask="guard_only")
    p = r.payload_sent
    assert r.status == "ok" and r.premask == "guard_only"
    assert "Marloes Kuipers" in p and "marloes.kuipers@kloostermanpayroll.nl" in p and "burn-out" in p
    # still handled locally
    assert "NL35ABNA7360155939" not in p and "6583.00" not in p and "Brightline" not in p
    assert "[IBAN_REMOVED]" in p and "[AMOUNT_REMOVED]" in p and "RECIPIENT_A" in p


def test_guard_only_still_removes_injection_and_ids():
    r = agent.run("hospital_ransomware", client=MockBrane(), premask="guard_only")
    p = r.payload_sent
    assert "[INSTRUCTION_REMOVED]" in p and "ignore previous instructions" not in p.lower()
    assert "290937759" not in p and "01-03-1961" not in p
    assert "Lucas Peters" in p                                  # left for BRANE (PERSON -> placeholder)


def test_guard_only_never_sends_the_leaked_file():
    r = agent.run("bank_ict_incident", client=MockBrane(), premask="guard_only")
    assert "500 records" in r.payload_sent
    for value in ("Hoofdstraat 122", "90338.23", "NL27TRIO1964855220"):   # rows of the leaked CSV
        assert value not in r.payload_sent


def test_guard_only_final_guard_blocks_ibans(monkeypatch):
    """If local removal fails in guard_only, the final guard still stops IBAN / ID / amount / DOB values."""
    monkeypatch.setattr(policy, "apply", lambda text, vault, *a, **k: policy.Applied(text, [], [], False, False))
    client = MockBrane()
    r = agent.run("bank_ict_incident", client=client, premask="guard_only")
    assert r.status == "blocked_leak" and client.forwarded == []


def test_guard_only_protocol_logs_masked_copy():
    import json
    from breachbrief import protocol
    r = agent.run("payroll_misdirected", client=MockBrane(), premask="guard_only")
    entry = json.loads((protocol.PROTOCOL_DIR / f"{r.run_id}.json").read_text(encoding="utf-8"))
    assert entry["premask"] == "guard_only"
    assert "Marloes Kuipers" not in entry["payload_sent"] and "burn-out" not in entry["payload_sent"]


def test_live_marker_rendering():
    text = "IBAN [IBAN_REMOVED], [HEALTH_DETAIL_KEPT_LOCAL], [INSTRUCTION_REMOVED]"
    plain = agent.render_markers(text, "plain")
    assert plain == "IBAN (iban removed), (special-category sentence withheld), (instruction removed)"
    assert agent.count_marker(plain, "[IBAN_REMOVED]") == 1 and agent.render_markers(text) == text
