"""Phase 2: names that are NOT in the leaked file, found by local NER (spaCy xx_ent_wiki_sm)."""
import pytest

from breachbrief import agent, detectors
from breachbrief.brane_client import MockBrane


def payload_for(report: str) -> str:
    r = agent.run("payroll_misdirected", report_override=report, client=MockBrane())
    assert r.status == "ok", r.message
    return r.payload_sent


def test_bare_unknown_name():
    p = payload_for("Pieter Brouwer called the helpdesk on Monday about the misdirected file.")
    assert "Brouwer" not in p and "Pieter" not in p
    assert "PERSON_" in p


def test_name_in_email_signature():
    p = payload_for("Please delete the file and confirm in writing.\n\nKind regards,\nSanne de Vries\nPrivacy Officer\n")
    assert "Sanne" not in p and "Vries" not in p
    assert "Privacy Officer" in p          # the job title is not a person and stays


def test_german_name_with_umlaut_and_later_surname_mention():
    p = payload_for("Jürgen Müller hat die Datei am Montag geöffnet. Später rief Herr Müller noch einmal an.")
    assert "Müller" not in p and "Jürgen" not in p
    assert p.count("PERSON_") >= 2


@pytest.mark.parametrize("text, kept", [
    ("We will notify the Autoriteit Persoonsgegevens before the deadline.", "Autoriteit Persoonsgegevens"),
    ("The incident was handled from our office in Utrecht.", "Utrecht"),
    ("The bank informed De Nederlandsche Bank in Amsterdam.", "Amsterdam"),
])
def test_organisations_and_places_not_masked(text, kept):
    p = payload_for(text)
    assert kept in p
    assert "PERSON_" not in p


def test_placeholders_never_detected_as_people():
    text = "Reported by: PERSON_001 (CISO), EMAIL_001, RECIPIENT_A, phone [PHONE_REMOVED]"
    assert detectors.ner_person_names(text) == []


def test_ner_unavailable_fails_closed(monkeypatch):
    def broken():
        raise detectors.NerUnavailable("model missing (simulated). Nothing sent.")
    monkeypatch.setattr(detectors, "_get_nlp", broken)
    client = MockBrane()
    r = agent.run("hospital_ransomware", client=client)
    assert r.status == "ner_unavailable"
    assert r.payload_sent is None and r.model_output is None
    assert client.last_forwarded is None   # nothing reached BRANE
