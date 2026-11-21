"""The honest verdict: what happened to this request, in one of four states, with counts computed on
what the model actually received (after BRANE), not on what we sent to BRANE.

States:
  CLOUD         sent to a cloud model (anything BRANE recognised was placeholdered first)
  LOCAL         kept inside BRANE on its local GPU model: zero cloud egress
  REFUSED       BRANE refused it (HTTP 422): nothing reached a model, a human decides
  NOTHING_SENT  nothing left this machine (BRANE unreachable, or our local guard stopped it)
"""
from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field

from . import agent, detectors as d, profiler

# What counts as an "identifier" for the KPI (values that point to a person or account)
IDENTIFIERS = {d.PERSON_NAME: "name", d.EMAIL: "email", d.PHONE: "phone", d.IBAN: "IBAN",
               d.NATIONAL_ID: "ID number", d.DATE_OF_BIRTH: "date of birth"}
# BRANE category -> our category, to estimate from headers when no preview is available
BRANE_TO_OURS = {"PERSON": d.PERSON_NAME, "EMAIL": d.EMAIL, "PHONE": d.PHONE, "IBAN": d.IBAN,
                 "SSN": d.NATIONAL_ID, "TAX_NUMBER": d.NATIONAL_ID, "PASSPORT": d.NATIONAL_ID,
                 "INSURANCE_NUMBER": d.NATIONAL_ID, "DATE_OF_BIRTH": d.DATE_OF_BIRTH}

PLAIN_CATEGORY = {
    "PERSON": "person name", "EMAIL": "email address", "PHONE": "phone number", "ADDRESS": "postal address",
    "IP_ADDRESS": "IP address", "ORG": "organisation name", "TRADE_REGISTER": "trade register number",
    "VAT_ID": "VAT number", "DATE_OF_BIRTH": "date of birth", "SSN": "social security number",
    "PASSPORT": "passport number", "TAX_NUMBER": "tax number", "INSURANCE_NUMBER": "insurance number",
    "IBAN": "bank account (IBAN)", "CREDIT_CARD": "credit card number", "ACCOUNT_NUMBER": "account number",
    "PASSWORD": "password", "SECRET_KEY": "secret key", "HEALTH_DATA": "health data",
    "ETHNIC_ORIGIN": "ethnic origin", "POLITICAL_OPINION": "political opinion", "RELIGIOUS_BELIEF": "religious belief",
    "SEXUAL_ORIENTATION": "sexual orientation", "TRADE_UNION": "trade union membership",
    "SENSITIVE_CONTEXT": "sensitive context",
    "INDIRECT_HEALTH_CONTEXT": "indirect health context", "RAW_DATASET_EXFILTRATION": "request for the raw dataset",
    "AUTONOMOUS_NOTIFICATION_DECISION": "AI asked to decide or send the notification itself",
}
PLAIN_LOCAL_CAUSE = {
    "semantic_category_local": None,   # explained by the semantic match itself
    "data_category_local": None,       # explained by the detected category
    "prompt_injection_local": "suspected hidden instruction or content BRANE could not read",
}

STATE_TITLE = {
    "CLOUD": "Sent to a cloud model with placeholders",
    "LOCAL": "Kept inside BRANE, zero cloud egress",
    "REFUSED": "BRANE refused it, nothing sent, a human decides",
    "NOTHING_SENT": "BRANE unreachable, fail closed, no fallback",
}


@dataclass
class Verdict:
    state: str                      # CLOUD | LOCAL | REFUSED | NOTHING_SENT
    title: str
    sentence: str                   # one plain-English sentence for the banner
    rule: str | None                # "Rule that fired: ..." / "Routed locally because: ..." or None
    identifiers_reached: int        # identifiers in what the model actually received
    identifier_kinds: list[str] = field(default_factory=list)
    health_reached: int = 0         # health sentences in what the model actually received
    instructions_removed: int = 0   # hidden instructions removed locally (report + leaked file)
    model_text: str | None = None   # what the model received (None if nothing)
    basis: str = ""                 # how model_text was obtained
    gateway: str = "LIVE"           # LIVE | MOCK
    by_kind: dict = field(default_factory=dict)   # our category -> count, in what the model received


def plain(code: str) -> str:
    return PLAIN_CATEGORY.get(code.strip().upper(), code.strip().lower().replace("_", " "))


def plain_rule(headers: dict) -> str | None:
    """Translate BRANE's headers into one plain-English line."""
    route = (headers.get("X-Brane-Routed-To") or "").lower()
    # Policy-Triggers is also sent on local routes ("semantic:X->local"): only a refusal is a "rule that fired"
    refused = headers.get("X-Brane-Refused-By") or (headers.get("X-Brane-Policy-Triggers") if route == "refused" else None)
    if refused:
        kind, _, rest = refused.partition(":")
        target, _, action = rest.partition("->")
        return f"Rule that fired: {plain(target or kind)} -> {action or 'refuse'}"
    if (headers.get("X-Brane-Routed-To") or "").lower() == "local":
        cause = headers.get("X-Brane-Local-Cause", "")
        reasons = [plain(s) for s in (headers.get("X-Brane-Semantic-Matches") or "").split(",") if s.strip()]
        if not reasons and cause == "data_category_local":
            reasons = [plain(t) for t in (headers.get("X-Brane-Pii-Types") or "").split(",")
                       if t.strip() in ("HEALTH_DATA", "ETHNIC_ORIGIN", "POLITICAL_OPINION", "RELIGIOUS_BELIEF",
                                        "SEXUAL_ORIENTATION", "TRADE_UNION", "SENSITIVE_CONTEXT")]
        if not reasons and PLAIN_LOCAL_CAUSE.get(cause):
            reasons = [PLAIN_LOCAL_CAUSE[cause]]
        return "Routed locally because: " + (", ".join(reasons) or cause.replace("_", " ") or "BRANE policy")
    return None


def state_of(r) -> str:
    if r.status == "refused_by_brane":
        return "REFUSED"
    if r.status in ("brane_unavailable", "blocked_leak", "ner_unavailable") or r.payload_sent is None:
        return "NOTHING_SENT"
    route = (r.brane_headers.get("X-Brane-Routed-To") or "").lower()
    return "LOCAL" if route == "local" else "CLOUD"


def _counting_context(scenario: str):
    meta, _, path = agent.load_scenario(scenario)
    prof = profiler.profile_csv(path)
    return prof["_known_people"] + meta.get("people_in_report", []), meta.get("recipients", []), prof["_known_first_names"]


def count_in(text: str, scenario: str) -> tuple[dict[str, int], int]:
    """(identifiers by category, health sentences) in a text."""
    people, recipients, firsts = _counting_context(scenario)
    findings = d.detect(text, people, recipients, known_first_names=firsts)
    ids: dict[str, int] = {}
    for f in findings:
        if f.category in IDENTIFIERS:
            ids[f.category] = ids.get(f.category, 0) + 1
    return ids, sum(1 for f in findings if f.category == d.HEALTH)


def brane_preview(client, text: str) -> str | None:
    """BRANE's dry run (/policy/test, no model call): the exact text a cloud model would receive."""
    if not hasattr(client, "_request"):
        return None
    with contextlib.suppress(Exception):
        status, raw, _ = client._request("POST", "/policy/test", {"prompt": text, "executeCompletion": False})
        if status == 200:
            prev = json.loads(raw).get("outgoingCloudPayloadPreview")
            if isinstance(prev, str):
                return prev
    return None


def compute(r, client=None, gateway: str = "LIVE", preview: str | None = None) -> Verdict:
    """Build the verdict for a run. `client` is the live BRANE client (for the dry-run preview);
    `preview` can be passed directly (tests)."""
    state = state_of(r)
    instructions = sum(1 for x in r.decisions if x["category"] == d.INJECTION)
    rule = plain_rule(r.brane_headers or {})
    if r.status == "blocked_leak":
        title = "Local guard stopped it, nothing sent"
    elif r.status == "ner_unavailable":
        title = "Local name detection unavailable, nothing sent"
    else:
        title = STATE_TITLE[state]

    model_text, basis, ids, health = None, "", {}, 0
    if state in ("CLOUD", "LOCAL"):
        if state == "LOCAL":
            model_text, basis = r.payload_sent, "BRANE's local model received the payload as sent"
        elif gateway == "MOCK":
            model_text, basis = r.payload_sent, "offline mock gateway: no BRANE policy applied"
        else:
            preview = preview if preview is not None else brane_preview(client, r.payload_sent)
            if preview is not None:
                model_text, basis = preview, "BRANE's dry-run preview of the outgoing cloud payload"
            else:
                model_text, basis = r.payload_sent, "estimated from BRANE's placeholder headers"
        ids, health = count_in(model_text, r.scenario)
        if basis.startswith("estimated") and not ids and not health:
            basis = "counted on the exact text sent to the firewall: it already contained no personal details"
        if basis.startswith("estimated"):
            replaced = {BRANE_TO_OURS[t.strip()] for t in (r.brane_headers.get("X-Brane-Placeholder-Types") or "").split(",")
                        if t.strip() in BRANE_TO_OURS}
            ids = {k: v for k, v in ids.items() if k not in replaced}

    n_ids = sum(ids.values())
    kinds = [f"{v} {IDENTIFIERS[k]}{'s' if v != 1 else ''}" for k, v in ids.items()]
    removed = f"{instructions} hidden instruction{'s' if instructions != 1 else ''} removed"
    if state == "CLOUD":
        where = "The cloud model received" + (" (offline mock gateway)" if gateway == "MOCK" else "")
        sentence = (f"{where} {n_ids} identifier{'s' if n_ids != 1 else ''}, {health} health "
                    f"sentence{'s' if health != 1 else ''}; {removed}.")
        if basis.startswith("estimated"):   # say so when BRANE's exact preview was not available
            sentence = sentence[:-1] + " (estimated from BRANE's headers: its exact preview was unavailable)."
    elif state == "LOCAL":
        sentence = (f"Nothing left BRANE: its local model received {n_ids} identifier{'s' if n_ids != 1 else ''} and "
                    f"{health} health sentence{'s' if health != 1 else ''}; {removed}.")
    elif state == "REFUSED":
        sentence = f"No model received anything; {removed} before BRANE refused the request."
    else:
        sentence = ("Nothing left this machine and no model received anything; there is no fallback to a direct "
                    f"model call. {removed[0].upper() + removed[1:]}.")
    return Verdict(state, title, sentence, rule, n_ids, kinds, health, instructions, model_text, basis, gateway, ids)


REFUSAL_REASON = {  # BRANE rule -> what it means, for a first-time reader
    "DATE_OF_BIRTH": "a date of birth", "IBAN": "a bank account number", "PASSWORD": "something that looks like a "
    "password", "SECRET_KEY": "something that looks like a secret key", "SSN": "a citizen ID number",
    "TAX_NUMBER": "a tax number", "PASSPORT": "a passport number", "CREDIT_CARD": "a credit card number",
    "ACCOUNT_NUMBER": "an account number", "INSURANCE_NUMBER": "an insurance number",
    "RAW_DATASET_EXFILTRATION": "a request to copy the whole leaked file",
    "AUTONOMOUS_NOTIFICATION_DECISION": "a request to let the AI decide or send the report by itself",
}


def refusal_reason(headers: dict) -> str:
    """'a date of birth' for 'category:DATE_OF_BIRTH->refuse'."""
    rule = headers.get("X-Brane-Refused-By") or headers.get("X-Brane-Policy-Triggers") or ""
    target = rule.partition(":")[2].partition("->")[0].strip().upper()
    return REFUSAL_REASON.get(target, f"protected data ({plain(target)})" if target else "protected data")
