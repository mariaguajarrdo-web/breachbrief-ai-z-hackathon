"""Regime tests (POLICY_MATRIX.md): legal deadlines are computed by code, never by the model.

GDPR Art. 33: authority within 72h of awareness.
NIS2 Art. 23: early warning within 24h, incident notification within 72h.
DORA Art. 19: initial notification = min(classification as major + 4h, awareness + 24h).
"""
from datetime import datetime, timedelta

import pytest

from breachbrief import agent, regimes

AWARE = "2026-11-19T08:10"


def due(regs, regime, step_prefix):
    r = next(x for x in regs if x["regime"] == regime)
    return next(dl["due"] for dl in r["deadlines"] if dl["step"].startswith(step_prefix))


def plus(iso, hours):
    return (datetime.fromisoformat(iso) + timedelta(hours=hours)).isoformat(timespec="minutes")


def test_gdpr_72h_after_awareness():
    regs = regimes.applicable({"aware_at": AWARE}, personal_data_involved=True)
    assert [r["regime"] for r in regs] == ["GDPR"]
    assert due(regs, "GDPR", "Notify supervisory authority") == plus(AWARE, 72)


def test_gdpr_not_applicable_without_personal_data():
    assert regimes.applicable({"aware_at": AWARE}, personal_data_involved=False) == []


def test_nis2_24h_early_warning_and_72h_notification():
    regs = regimes.applicable({"aware_at": AWARE, "nis2_entity": "essential"}, personal_data_involved=False)
    assert due(regs, "NIS2", "Early warning") == plus(AWARE, 24)
    assert due(regs, "NIS2", "Incident notification") == plus(AWARE, 72)


def test_nis2_not_for_non_significant_incident():
    meta = {"aware_at": AWARE, "nis2_entity": "important", "significant_incident": False}
    assert regimes.applicable(meta, personal_data_involved=False) == []


@pytest.mark.parametrize("classified_at, expected", [
    ("2026-11-19T11:00", "2026-11-19T15:00"),   # classification + 4h comes first
    ("2026-11-20T06:00", "2026-11-20T08:10"),   # awareness + 24h caps it (classified late)
])
def test_dora_initial_is_min_of_classification_4h_and_awareness_24h(classified_at, expected):
    meta = {"aware_at": AWARE, "entity_type": "credit_institution", "major_ict_incident": True,
            "classified_major_at": classified_at}
    regs = regimes.applicable(meta, personal_data_involved=False)
    assert due(regs, "DORA", "Initial notification") == expected
    assert expected == min(plus(classified_at, 4), plus(AWARE, 24))


def test_dora_only_for_financial_entities_with_major_incident():
    assert regimes.applicable({"aware_at": AWARE, "entity_type": "hospital", "major_ict_incident": True}, False) == []
    assert regimes.applicable({"aware_at": AWARE, "entity_type": "credit_institution",
                               "major_ict_incident": False}, False) == []


@pytest.mark.parametrize("scenario, expected", [
    ("payroll_misdirected", ["GDPR"]),
    ("hospital_ransomware", ["GDPR", "NIS2"]),
    ("bank_ict_incident", ["GDPR", "DORA"]),
])
def test_scenario_regimes(scenario, expected):
    meta, _, _ = agent.load_scenario(scenario)
    regs = regimes.applicable(meta, personal_data_involved=True)
    assert [r["regime"] for r in regs] == expected


def test_earliest_deadline_per_scenario():
    expect = {"payroll_misdirected": "2026-11-22T09:40",   # GDPR 72h
              "hospital_ransomware": "2026-11-21T06:30",   # NIS2 early warning 24h
              "bank_ict_incident": "2026-11-19T15:00"}     # DORA classification 11:00 + 4h
    for scenario, earliest in expect.items():
        meta, _, _ = agent.load_scenario(scenario)
        assert regimes.earliest_deadline(regimes.applicable(meta, True)) == earliest
