"""Draft notifications: one per recipient that applies, all handled on this machine after the model step.

* fill_known_fields(): the model never sees the organisation name, dates or authority names it does not need;
  it leaves [square bracket] placeholders, which are filled here from local facts. Anything still in
  brackets afterwards must be completed by the reviewer (approval is blocked until then).
* useful_facts(): the "facts still to confirm" list, minus what the app already knows, top 5.
* template_drafts(): non-AI drafts from local facts, for when nothing was sent or BRANE refused.
"""
from __future__ import annotations

import re
from datetime import datetime

# recipient -> (draft key, label, legal basis)
RECIPIENTS = {
    "authority": ("draft_authority_notification", "Notification to the data protection authority", "GDPR Art. 33"),
    "csirt": ("draft_nis2_early_warning", "NIS2 early warning to the CSIRT", "NIS2 Art. 23(4)(a)"),
    "financial_supervisor": ("draft_dora_initial_notification", "DORA initial notification to the supervisor",
                             "DORA Art. 19 + Reg. (EU) 2025/301"),
    "affected_people": ("draft_affected_people_notice", "Notice to affected people", "GDPR Art. 34"),
}
REGIME_RECIPIENT = {"GDPR": "authority", "NIS2": "csirt", "DORA": "financial_supervisor"}
PLACEHOLDER_RE = re.compile(r"\[([^\[\]\n]{1,80})\]")


def recipients_for(regimes: list[dict]) -> list[str]:
    """Recipients that apply, in display order. Affected people only matter when GDPR applies."""
    names = [x["regime"] for x in regimes]
    out = [REGIME_RECIPIENT[n] for n in ("GDPR", "NIS2", "DORA") if n in names]
    if "GDPR" in names:
        out.append("affected_people")
    return out


def authority_name(meta: dict, recipient: str) -> str:
    return {"authority": meta.get("dpa", "the data protection authority"),
            "csirt": meta.get("csirt", "the national CSIRT"),
            "financial_supervisor": meta.get("financial_supervisor", "the competent financial supervisor"),
            "affected_people": "the people affected"}[recipient]


def _when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %B %Y, %H:%M")
    except (TypeError, ValueError):
        return iso


def facts_from(meta: dict, profile: dict | None, regimes: list[dict]) -> dict:
    profile = profile or {}
    due = {r["regime"]: r["deadlines"][0]["due"] for r in regimes if r["deadlines"]}
    return {
        "organisation": meta.get("organisation", ""),
        "sector": meta.get("sector", ""),
        "aware": _when(meta.get("aware_at", "")),
        "classified": _when(meta.get("classified_major_at", "")) if meta.get("classified_major_at") else "",
        "records": str(profile.get("record_count", "")) if profile.get("record_count") else "",
        "categories": ", ".join(c for c in profile.get("data_categories", []) if c),
        "dpa": meta.get("dpa", ""), "csirt": meta.get("csirt", ""),
        "supervisor": meta.get("financial_supervisor", ""),
        "due": {k: _when(v) for k, v in due.items()},
    }


def _value_for(label: str, facts: dict, recipient: str) -> str | None:
    t = label.lower()
    if re.search(r"organi[sz]ation|company|controller|entity name|hospital name|bank name|our name", t):
        return facts["organisation"] or None
    if "csirt" in t or "cert" in t:
        return facts["csirt"] or None
    if re.search(r"supervisor|dnb|competent authority", t) and recipient == "financial_supervisor":
        return facts["supervisor"] or None
    if re.search(r"authority|dpa|autoriteit|data protection", t):
        return facts[{"csirt": "csirt", "financial_supervisor": "supervisor"}.get(recipient, "dpa")] or None
    if re.search(r"classif", t):
        return facts["classified"] or None
    if re.search(r"aware|discover|detect", t):
        return facts["aware"] or None
    if re.search(r"number|how many|count", t) and re.search(r"record|people|person|individual|subject|affected|"
                                                          r"employee|patient|customer", t):
        return facts["records"] or None
    if "categor" in t:
        return facts["categories"] or None
    if "sector" in t:
        return facts["sector"] or None
    return None


def fill_known_fields(text: str, facts: dict, recipient: str = "authority") -> str:
    """Replace [placeholders] we can answer from local facts; leave the rest for the reviewer."""
    if not text:
        return text
    return PLACEHOLDER_RE.sub(lambda m: _value_for(m.group(1), facts, recipient) or m.group(0), text)


def open_placeholders(text: str | None) -> list[str]:
    """[placeholders] still in a draft. Our own removal markers ([IBAN_REMOVED]...) never reach drafts."""
    return [m.group(0) for m in PLACEHOLDER_RE.finditer(text or "")]


_KNOWN_FACT_PATTERNS = [
    r"\bwhen\b.*\b(aware|discover|detect|notic)",                       # awareness time is known
    r"\b(how many|number of)\b.*\b(record|people|person|individual|subject|affected|employee|patient|customer)",
    r"\bwhich\b.*\bcategor|\bcategories of\b.*\bdata\b",                 # data categories are profiled
    r"\b(which|what)\b.*\b(authority|csirt|supervisor|regulator)\b",     # authorities are known
    r"\bdeadline",                                                     # computed by code
    r"\b(essential|important) entity|\bsector\b",
]


def useful_facts(facts: list[str] | None, limit: int = 5) -> list[str]:
    """Open questions minus what the app already knows; at most `limit`."""
    out = []
    for f in facts or []:
        if isinstance(f, str) and f.strip() and not any(re.search(p, f, re.I) for p in _KNOWN_FACT_PATTERNS):
            out.append(f.strip())
    return out[:limit]


def finalise(out: dict, meta: dict, profile: dict | None, regimes: list[dict]) -> dict:
    """After the model step and local re-identification: fill known fields, trim the facts list."""
    facts = facts_from(meta, profile, regimes)
    result = dict(out)
    for recipient, (key, _, _) in RECIPIENTS.items():
        if isinstance(result.get(key), str):
            result[key] = fill_known_fields(result[key], facts, recipient)
    if isinstance(result.get("incident_summary"), str):
        result["incident_summary"] = fill_known_fields(result["incident_summary"], facts)
    result["missing_facts"] = useful_facts(result.get("missing_facts"))
    return result


def template_drafts(meta: dict, profile: dict | None, regimes: list[dict], reason: str) -> dict:
    """Non-AI drafts filled only from local facts, for when no model answered. Clearly labelled."""
    f = facts_from(meta, profile, regimes)
    org = f["organisation"] or "[Organisation name]"
    scale = f"{f['records']} records" if f["records"] else "[number of records]"
    cats = f["categories"] or "[data categories]"
    note = f"Template prepared without AI ({reason}). Complete every [bracketed] field before approval."
    drafts = {
        "incident_summary": f"{org} ({f['sector']}) became aware of a personal data breach on {f['aware']}. "
                            f"The affected file holds {scale} with these data categories: {cats}.",
        "missing_facts": ["What exactly happened, and when did the breach start and end?",
                          "Which measures have been taken to contain the breach?",
                          "What are the likely consequences for the people affected?"],
        "suggested_risk_level": "not assessed (no AI answer)",
        "template_note": note,
    }
    names = [x["regime"] for x in regimes]
    if "GDPR" in names:
        drafts["draft_authority_notification"] = (
            f"To {f['dpa'] or '[supervisory authority]'}\n\nNotification of a personal data breach (GDPR Art. 33)\n\n"
            f"Controller: {org}\nTime of awareness: {f['aware']}\nNature of the breach: [describe what happened]\n"
            f"Categories and approximate number: {cats}; {scale}\nLikely consequences: [describe]\n"
            f"Measures taken or proposed: [describe]\nContact point (DPO): [name, email, phone]\n\n"
            "Information that is not yet available will be provided in phases (Art. 33(4)).")
        drafts["draft_affected_people_notice"] = (
            f"Dear [name],\n\nOn {f['aware']} {org} found that some of your personal data may have been "
            "exposed. [Explain in plain language what happened and which of your data are involved.]\n\n"
            "What we have done: [describe]\nWhat you can do: [practical advice]\n"
            "Questions: contact our data protection officer at [contact details].")
    if "NIS2" in names:
        drafts["draft_nis2_early_warning"] = (
            f"To {f['csirt'] or '[CSIRT]'}\n\nNIS2 early warning (Art. 23(4)(a))\n\nEntity: {org} ({f['sector']}), "
            f"essential entity\nSignificant incident detected; became aware: {f['aware']}\n"
            "Suspected unlawful or malicious act: [yes / no / unknown]\nPossible cross-border impact: [yes / no / unknown]\n"
            "An incident notification will follow within 72 hours.")
    if "DORA" in names:
        drafts["draft_dora_initial_notification"] = (
            f"To {f['supervisor'] or '[competent authority]'}\n\nDORA initial notification of a major ICT-related "
            f"incident (Art. 19)\n\nFinancial entity: {org}\nBecame aware: {f['aware']}\n"
            f"Classified as major: {f['classified'] or '[time of classification]'}\n"
            "Services affected: [describe]\nInitial impact: [describe]\nIntermediate report to follow within 72 hours.")
    return drafts
