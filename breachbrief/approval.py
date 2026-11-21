"""HUMAN_ONLY step: a named reviewer confirms the risk tier and which notifications go out.

BreachBrief never sends anything. approve() only turns the drafts into an approved
package (Markdown in exports/) and records the human decision in the run's protocol.
The reviewer sends the notifications through the official channels themselves.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import drafts, protocol

EXPORT_DIR = Path(__file__).resolve().parent.parent / "exports"
AMSTERDAM = ZoneInfo("Europe/Amsterdam")

# The three tiers of GDPR Art. 33/34. "low" is accepted as a legacy alias for "risk".
RISK_TIERS = {
    "unlikely": "Unlikely to result in a risk (document only, Art. 33(5))",
    "risk": "Risk (notify authority, Art. 33)",
    "high": "High risk (also inform affected people, Art. 34)",
}
RISK_LEVELS = tuple(RISK_TIERS)
_ALIASES = {"low": "risk"}
TARGETS = {"authority": "Data protection authority (GDPR Art. 33)",
           "csirt": "CSIRT (NIS2 early warning)",
           "financial_supervisor": "Financial supervisor (DORA initial notification)",
           "affected_people": "Affected people (GDPR Art. 34)"}


class ApprovalError(ValueError):
    """The approval is incomplete or inconsistent; nothing was exported."""


@dataclass
class Approval:
    run_id: str
    reviewer: str
    risk_level: str
    notify: list[str]
    reason: str
    approved_at: str            # UTC, ISO 8601 (audit log)
    export_path: Path
    role: str = ""

    @property
    def approved_at_local(self) -> str:
        return amsterdam(self.approved_at)


def amsterdam(iso_utc: str) -> str:
    """'20 Nov 2026, 19:42 (Amsterdam)' from a UTC ISO timestamp."""
    try:
        return datetime.fromisoformat(iso_utc).astimezone(AMSTERDAM).strftime("%d %b %Y, %H:%M (Amsterdam)")
    except (TypeError, ValueError):
        return iso_utc


def _normalise_targets(notify) -> list[str]:
    items = [notify] if isinstance(notify, str) else list(notify or [])
    items = [t.strip().lower().replace(" ", "_").replace("-", "_") for i in items for t in str(i).split(",") if t.strip()]
    if items == ["none"]:
        return []
    unknown = [t for t in items if t not in TARGETS]
    if unknown or "none" in items:
        raise ApprovalError(f"Unknown notification target(s) {unknown or ['none + others']}. "
                            f"Use any of {sorted(TARGETS)} or 'none'.")
    return [t for t in TARGETS if t in items]  # stable order, no duplicates


def approve(result, reviewer: str, risk_level: str, notify, reason: str = "", role: str = "") -> Approval:
    """Record the human decision and export the approved package. Raises ApprovalError if incomplete."""
    reviewer, role, reason = (reviewer or "").strip(), (role or "").strip(), (reason or "").strip()
    risk = _ALIASES.get((risk_level or "").strip().lower(), (risk_level or "").strip().lower())
    if not reviewer:
        raise ApprovalError("A named reviewer is required.")
    if risk not in RISK_TIERS:
        raise ApprovalError(f"Risk level must be one of {RISK_LEVELS}, got {risk_level!r}.")
    targets = _normalise_targets(notify)
    applicable = drafts.recipients_for(result.regimes)
    not_applicable = [t for t in targets if t not in applicable]
    if not_applicable:
        raise ApprovalError(f"{', '.join(TARGETS[t] for t in not_applicable)} does not apply to this incident.")

    # Omitting a notification is a legal judgement; it must be justified in writing.
    if not targets and not reason:
        raise ApprovalError("Notifying nobody requires a reason (e.g. GDPR Art. 33(1): unlikely to result in a risk).")
    if "authority" in applicable and "authority" not in targets and not reason:
        raise ApprovalError("Not notifying the authority requires a reason.")
    if risk == "high" and "affected_people" not in targets and not reason:
        raise ApprovalError("High risk without notifying affected people requires a reason (GDPR Art. 34(3) exception).")
    for t, law in (("csirt", "the NIS2 early warning"), ("financial_supervisor", "the DORA initial notification")):
        if t in applicable and t not in targets and not reason:
            raise ApprovalError(f"Not sending {law} requires a reason.")

    # Every approved draft must be complete: no [bracketed] field left for the reviewer to fill.
    texts = result.model_output or result.fallback_drafts or {}
    for t in targets:
        open_fields = drafts.open_placeholders(texts.get(drafts.RECIPIENTS[t][0]))
        if open_fields:
            raise ApprovalError(f"Complete the bracketed fields in '{drafts.RECIPIENTS[t][1]}' before approval: "
                                f"{', '.join(open_fields[:4])}{' ...' if len(open_fields) > 4 else ''}")

    approved_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    EXPORT_DIR.mkdir(exist_ok=True)
    path = EXPORT_DIR / f"{result.run_id}-approved.md"
    approval = Approval(result.run_id, reviewer, risk, targets, reason, approved_at, path, role)

    # protocol first: an export must never exist without its recorded approval
    protocol.record_approval(result.run_id, {
        "reviewer": reviewer, "role": role or None, "approved_at": approved_at,
        "approved_at_amsterdam": approval.approved_at_local, "confirmed_risk_level": risk,
        "notify": targets or ["none"], "reason": reason or None,
        "model_suggested_risk_level": (result.model_output or {}).get("suggested_risk_level"),
        "export_file": path.relative_to(EXPORT_DIR.parent).as_posix(), "sent_by_app": False,
    })
    path.write_text(render_markdown(result, approval), encoding="utf-8")
    return approval


def render_markdown(result, a: Approval) -> str:
    out = result.model_output or result.fallback_drafts or {}
    ai = result.model_output is not None
    who = f"{a.reviewer} ({a.role})" if a.role else a.reviewer
    lines = [
        f"# Approved breach notification package: {result.scenario}",
        "",
        "> **Not sent.** BreachBrief does not send notifications. The reviewer below approved these drafts;",
        "> send them yourself through the official channels before the deadlines.",
        "",
        "| | |", "|---|---|",
        f"| Run | `{result.run_id}` |",
        f"| Approved by | {who} |",
        f"| Approved at | {a.approved_at_local} |",
        f"| Confirmed risk | **{RISK_TIERS[a.risk_level]}** |",
        f"| Model suggestion | {out.get('suggested_risk_level', 'n/a')} |",
        f"| Notify | {', '.join(TARGETS[t] for t in a.notify) or '**Nobody**'} |",
    ]
    if a.reason:
        lines.append(f"| Reason / justification | {a.reason} |")

    lines += ["", "## Regimes and deadlines", "", "| Regime | Authority | Step | Due |", "|---|---|---|---|"]
    for r in result.regimes:
        for dl in r["deadlines"]:
            lines.append(f"| {r['regime']} | {r['authority']} | {dl['step']} | {dl['due']} |")
    if result.earliest_deadline:
        lines += ["", f"Earliest deadline: **{result.earliest_deadline}**"]

    if out.get("incident_summary"):
        lines += ["", "## Incident summary", "", out["incident_summary"]]
    if out.get("missing_facts"):
        lines += ["", "## Facts still to confirm", ""] + [f"- [ ] {f}" for f in out["missing_facts"]]

    for target in a.notify:
        key, title, basis = drafts.RECIPIENTS[target]
        text = out.get(key)
        if text:  # LEGAL.md section 4: drafts are labelled as AI-assisted (or as a non-AI template)
            label = (f"_AI-assisted draft, reviewed and approved by {who}._" if ai
                     else f"_Template drafted without AI, completed and approved by {who}._")
        else:
            text, label = f"_No draft available (status: {result.status}). Write this notification manually._", ""
        lines += ["", f"## {title} ({basis})", ""] + ([label, ""] if label else []) + [text]
    lines.append("")
    return "\n".join(lines)
