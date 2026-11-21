"""Which notification regimes apply, and their deadlines. Deterministic and local:
legal deadlines are computed by code, never guessed by the model.

NOTE: verify every deadline against the sources in LEGAL.md (Phase 3).
"""
from __future__ import annotations

from datetime import datetime, timedelta

NIS2_SECTORS = {"health", "energy", "transport", "banking", "financial_market_infrastructure", "drinking_water",
                "waste_water", "digital_infrastructure", "ict_service_management", "public_administration", "space",
                "postal", "waste_management", "chemicals", "food", "manufacturing", "digital_providers", "research"}
DORA_ENTITIES = {"credit_institution", "payment_institution", "investment_firm", "insurance_undertaking",
                 "crypto_asset_service_provider", "e_money_institution", "trading_venue"}


def applicable(meta: dict, personal_data_involved: bool) -> list[dict]:
    aware = datetime.fromisoformat(meta["aware_at"])
    out = []
    if personal_data_involved:
        out.append({
            "regime": "GDPR",
            "authority": meta.get("dpa", "Data protection authority"),
            "basis": "GDPR Art. 33 (authority) / Art. 34 (affected people, if high risk)",
            "deadlines": [{"step": "Notify supervisory authority (unless unlikely to result in a risk)",
                           "due": (aware + timedelta(hours=72)).isoformat(timespec="minutes")}],
        })
    if meta.get("nis2_entity") in ("essential", "important") and meta.get("significant_incident", True):
        out.append({
            "regime": "NIS2",
            "authority": meta.get("csirt", "National CSIRT / competent authority"),
            "basis": "NIS2 Directive (EU) 2022/2555 Art. 23",
            "deadlines": [
                {"step": "Early warning", "due": (aware + timedelta(hours=24)).isoformat(timespec="minutes")},
                {"step": "Incident notification", "due": (aware + timedelta(hours=72)).isoformat(timespec="minutes")},
                {"step": "Final report", "due": "within 1 month of the incident notification"},
            ],
        })
    if meta.get("entity_type") in DORA_ENTITIES and meta.get("major_ict_incident", False):
        classified = datetime.fromisoformat(meta.get("classified_major_at", meta["aware_at"]))
        initial_due = min(classified + timedelta(hours=4), aware + timedelta(hours=24))
        out.append({
            "regime": "DORA",
            "authority": meta.get("financial_supervisor", "Competent financial supervisor"),
            "basis": "DORA Regulation (EU) 2022/2554 Art. 19 + RTS/ITS on incident reporting",
            "deadlines": [
                {"step": "Initial notification (4h after classification as major, max 24h after awareness)",
                 "due": initial_due.isoformat(timespec="minutes")},
                {"step": "Intermediate report", "due": "within 72h of the initial notification"},
                {"step": "Final report", "due": "within 1 month of the latest intermediate report"},
            ],
        })
    return out


def earliest_deadline(regimes: list[dict]) -> str | None:
    dues = [dl["due"] for r in regimes for dl in r["deadlines"] if dl["due"][:4].isdigit()]
    return min(dues) if dues else None
