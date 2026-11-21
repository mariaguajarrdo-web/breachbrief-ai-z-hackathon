"""The policy: what happens to each data category before an external model sees it.

Four decisions, as defined by the AI-Z brief:
  ALLOW       send as is
  PROTECT     pseudonymise / mask, mapping stays in the local vault
  LOCAL_ONLY  never leaves the machine (processed locally only)
  BLOCK       removed and never sent
Plus HUMAN_ONLY for decisions the agent may never take (enforced in agent.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import detectors as d

ALLOW, PROTECT, LOCAL_ONLY, BLOCK, HUMAN_ONLY = "ALLOW", "PROTECT", "LOCAL_ONLY", "BLOCK", "HUMAN_ONLY"

# category -> (decision, replacement prefix or marker, one-line rationale; legal basis lives in POLICY_MATRIX.md)
RULES: dict[str, tuple[str, str, str]] = {
    d.PERSON_NAME: (PROTECT, "PERSON", "Identity not needed to assess the breach (data minimisation)."),
    d.RECIPIENT: (PROTECT, "RECIPIENT", "Third-party identity not needed by the model."),
    d.EMAIL: (PROTECT, "EMAIL", "Contact details not needed by the model."),
    d.PHONE: (BLOCK, "[PHONE_REMOVED]", "Contact details not needed by the model."),
    d.IBAN: (BLOCK, "[IBAN_REMOVED]", "Financial identifier; only the category 'bank details' is needed."),
    d.NATIONAL_ID: (BLOCK, "[ID_NUMBER_REMOVED]", "National ID numbers carry strict use limits."),
    d.MONEY_VALUE: (BLOCK, "[AMOUNT_REMOVED]", "Actual salary/balance values are not needed, only that they were exposed."),
    d.DATE_OF_BIRTH: (BLOCK, "[DOB_REMOVED]", "Not needed by the model."),
    d.HEALTH: (LOCAL_ONLY, "[HEALTH_DETAIL_KEPT_LOCAL]", "Special category data (Art. 9) never leaves the organisation."),
    d.INJECTION: (BLOCK, "[INSTRUCTION_REMOVED]", "Instructions inside documents are data, never commands."),
    d.ENCODED: (BLOCK, "[ENCODED_CONTENT_REMOVED]", "Encoded content cannot be checked, so it is never sent (unverifiable)."),
}

# LOCAL_PREMASK modes ------------------------------------------------------------------
# full:       everything above is applied locally before BRANE sees anything (default).
# guard_only: names, emails, phones and health text are left for BRANE's own policy
#             (placeholder / local GPU). Still handled locally: injected instructions,
#             recipients (BRANE allows ORG, so third parties are pseudonymised here), and
#             IBAN / ID / amount / DOB values, which the final guard re-checks.
PREMASK_MODES = ("full", "guard_only")
GUARD_ONLY_LOCAL = {d.INJECTION, d.ENCODED, d.RECIPIENT, d.IBAN, d.NATIONAL_ID, d.MONEY_VALUE, d.DATE_OF_BIRTH}
GUARD_ONLY_GUARD = {d.IBAN, d.NATIONAL_ID, d.MONEY_VALUE, d.DATE_OF_BIRTH, d.ENCODED}
DELEGATED = "BRANE"  # decision label in guard_only for categories left to BRANE


def local_categories(premask: str) -> set[str] | None:
    """Categories masked locally for a premask mode (None = all)."""
    if premask not in PREMASK_MODES:
        raise ValueError(f"LOCAL_PREMASK must be one of {PREMASK_MODES}, got {premask!r}")
    return None if premask == "full" else GUARD_ONLY_LOCAL


DECISIONS_FOR_DISPLAY = {
    "Incident facts (time, counts, data types, actions)": ALLOW,
    **{cat: rule[0] for cat, rule in RULES.items()},
    "Risk level & whether to notify": HUMAN_ONLY,
}


@dataclass
class Vault:
    """Local-only mapping token -> real value. Never sent anywhere."""
    forward: dict[tuple[str, str], str] = field(default_factory=dict)
    reverse: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def token_for(self, category: str, value: str, prefix: str) -> str:
        key = (category, value.strip().lower())
        if key not in self.forward:
            n = self.counters.get(prefix, 0) + 1
            self.counters[prefix] = n
            token = f"{prefix}_{n:03d}" if prefix != "RECIPIENT" else f"RECIPIENT_{chr(64 + n)}"
            self.forward[key] = token
            self.reverse[token] = value
        return self.forward[key]

    def restore(self, text: str) -> str:
        for token in sorted(self.reverse, key=len, reverse=True):
            text = text.replace(token, self.reverse[token])
        return text


@dataclass
class Applied:
    sanitized: str
    decisions: list[dict]          # one entry per finding: category, decision, replacement (never the raw value)
    local_only: list[str]          # raw LOCAL_ONLY segments, kept on the machine for the human reviewer
    health_involved: bool
    injection_blocked: bool
    spans: list[dict] = field(default_factory=list)  # LOCAL ONLY: offsets into the original text, for the reviewer UI


def apply(text: str, vault: Vault, known_people=None, known_recipients=None, known_first_names=None,
          premask: str = "full") -> Applied:
    only = local_categories(premask)
    findings = d.detect(text, known_people, known_recipients, known_first_names=known_first_names,
                        use_ner=only is None or d.PERSON_NAME in only, only=only)
    out, cursor = [], 0
    decisions, local_only, spans = [], [], []
    for f in findings:
        decision, prefix, rationale = RULES[f.category]
        if decision == PROTECT:
            repl = vault.token_for(f.category, f.value, prefix)
        else:
            repl = prefix
        if decision == LOCAL_ONLY:
            local_only.append(f.value)
        out.append(text[cursor:f.start])
        out.append(repl)
        cursor = f.end
        decisions.append({"category": f.category, "decision": decision, "replacement": repl, "rationale": rationale})
        spans.append({"start": f.start, "end": f.end, "category": f.category, "decision": decision, "replacement": repl})
    out.append(text[cursor:])
    return Applied(
        sanitized="".join(out),
        decisions=decisions,
        local_only=local_only,
        health_involved=any(x["category"] == d.HEALTH for x in decisions),
        injection_blocked=any(x["category"] == d.INJECTION for x in decisions),
        spans=spans,
    )


def residual_leaks(payload: str, known_people=None, known_recipients=None, known_first_names=None,
                   premask: str = "full") -> list[d.Finding]:
    """Final guard: re-scan the outgoing payload. Anything found here must never be sent.
    In guard_only mode the guard checks only IBAN / ID / amount / DOB values (the rest is BRANE's job)."""
    if premask == "guard_only":
        return d.detect(payload, use_ner=False, only=GUARD_ONLY_GUARD)
    return d.detect(payload, known_people, known_recipients, known_first_names=known_first_names)
