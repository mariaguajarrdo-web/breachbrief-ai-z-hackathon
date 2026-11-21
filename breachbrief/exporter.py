"""Exports for the reviewer. Nothing here sends anything.

* Word (.docx): the notification package. Editable, so the DPO can finalise the text and send it
  through the official channel (authority portal, letter, email to affected people).
* Excel (.xlsx): the audit workbook. Deadlines, protection decisions, BRANE verdict, payload and the
  human decision, for the breach register (GDPR Art. 33(5)). It holds no draft texts and no
  locally-kept health details, so it can be shared with auditors more freely than the Word file.
"""
from __future__ import annotations

import io
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from . import drafts as drafts_mod, policy
from .approval import RISK_TIERS, TARGETS, amsterdam

NAVY = "1E3A8A"
AMS = ZoneInfo("Europe/Amsterdam")
DECISION_LABEL = {policy.ALLOW: "ALLOW", policy.PROTECT: "PROTECT", policy.LOCAL_ONLY: "LOCAL ONLY",
                  policy.BLOCK: "BLOCK", policy.HUMAN_ONLY: "HUMAN ONLY", policy.DELEGATED: "LEFT TO BRANE"}


@dataclass
class Decision:
    """The human decision, if one was made (from approval.approve())."""
    reviewer: str
    risk_level: str
    notify: list[str]
    reason: str
    approved_at: str            # UTC ISO
    role: str = ""

    @property
    def who(self) -> str:
        return f"{self.reviewer} ({self.role})" if self.role else self.reviewer


def _now() -> str:
    return datetime.now(timezone.utc).astimezone(AMS).strftime("%d %b %Y, %H:%M (Amsterdam)")


def _fmt_due(due: str) -> str:
    try:
        return datetime.fromisoformat(due).strftime("%a %d %b %Y, %H:%M")
    except ValueError:
        return due


def deadline_rows(result) -> list[tuple[str, str, str, str]]:
    return [(r["regime"], r["authority"], dl["step"], _fmt_due(dl["due"]))
            for r in result.regimes for dl in r["deadlines"]]


def decision_rows(result) -> list[tuple[str, str, int, str]]:
    counts = Counter(d["category"] for d in result.decisions)
    seen, rows = set(), []
    for d in result.decisions:
        if d["category"] in seen:
            continue
        seen.add(d["category"])
        rows.append((d["category"], DECISION_LABEL.get(d["decision"], d["decision"]), counts[d["category"]],
                     d.get("rationale", "")))
    return rows


# ---- Word ----------------------------------------------------------------------------------------
def build_docx(result, meta: dict, drafts: dict, decision: Decision | None, brane_mode: str) -> bytes:
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name, style.font.size = "Calibri", Pt(11)

    title = doc.add_heading("Breach notification package", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph(meta.get("title", result.scenario)).runs[0].bold = True

    status = doc.add_paragraph()
    run = status.add_run(f"APPROVED by {decision.who}" if decision else "DRAFT: not yet approved by a reviewer")
    run.bold = True
    run.font.color.rgb = RGBColor(0x16, 0x65, 0x34) if decision else RGBColor(0xB9, 0x1C, 0x1C)
    doc.add_paragraph("BreachBrief does not send notifications. Review and finalise the text below, then send it "
                      "yourself through the official channel before the deadline.").italic = True

    doc.add_heading("1. Decision", level=1)
    out = result.model_output or result.fallback_drafts or {}
    rows = [("Run", result.run_id), ("Organisation", f"{meta.get('organisation', '')}, {meta.get('sector', '')} "
                                                      f"({meta.get('entity_type', '').replace('_', ' ')})"),
            ("Became aware", _fmt_due(meta.get("aware_at", ""))),
            ("Model's suggested risk level", out.get("suggested_risk_level", "n/a"))]
    if decision:
        rows += [("Confirmed risk", RISK_TIERS.get(decision.risk_level, decision.risk_level)),
                 ("Approved by", decision.who), ("Approved at", amsterdam(decision.approved_at)),
                 ("Notify", ", ".join(TARGETS[t] for t in decision.notify) or "Nobody")]
        if decision.reason:
            rows.append(("Reason / justification", decision.reason))
    _kv_table(doc, rows)

    doc.add_heading("2. Legal deadlines", level=1)
    if result.earliest_deadline:
        doc.add_paragraph().add_run(f"Earliest deadline: {_fmt_due(result.earliest_deadline)}").bold = True
    _table(doc, ["Regime", "Authority", "Step", "Due"], deadline_rows(result))

    if out.get("incident_summary"):
        doc.add_heading("3. Incident summary", level=1)
        doc.add_paragraph(out["incident_summary"])
    if out.get("missing_facts"):
        doc.add_heading("4. Facts still to confirm", level=1)
        for fact in out["missing_facts"]:
            doc.add_paragraph(fact, style="List Bullet")

    targets = decision.notify if decision else drafts_mod.recipients_for(result.regimes)
    kind = "AI-assisted draft" if result.model_output is not None else "Template drafted without AI"
    for n, target in enumerate(targets, start=5):
        key, heading, basis = drafts_mod.RECIPIENTS[target]
        doc.add_heading(f"{n}. {heading} ({basis})", level=1)
        label = (f"{kind}, reviewed and approved by {decision.who}." if decision else f"{kind}, not yet approved.")
        doc.add_paragraph().add_run(label).italic = True
        text = (drafts.get(key) or "").strip()
        for para in (text.split("\n") if text else ["No draft available. Write this notification manually."]):
            doc.add_paragraph(para)

    doc.add_heading("How the data was protected", level=1)
    h = result.brane_headers or {}
    for line in [
        "The leaked file never left this machine: only record counts and data categories were used.",
        f"Local protection: {len(result.decisions)} findings handled before anything was sent "
        f"(mode: {'full local pre-masking' if result.premask == 'full' else 'guard_only, names/contacts/health left to BRANE'}).",
        f"BRANE gateway ({brane_mode}): route {h.get('X-Brane-Routed-To', 'n/a')}, "
        f"redacted {h.get('X-Brane-Redacted', 'n/a')}, model {h.get('X-Brane-Model-Resolved', 'n/a')}.",
        "Legal deadlines were computed by code, not by the AI model.",
    ]:
        doc.add_paragraph(line, style="List Bullet")
    foot = doc.add_paragraph(f"Generated by BreachBrief on {_now()}. Run {result.run_id}.")
    foot.runs[0].font.size, foot.runs[0].font.color.rgb = Pt(8), RGBColor(0x64, 0x74, 0x8B)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _kv_table(doc, rows):
    t = doc.add_table(rows=0, cols=2)
    t.style = "Light Grid Accent 1"
    for k, v in rows:
        cells = t.add_row().cells
        cells[0].text, cells[1].text = k, str(v)
        cells[0].paragraphs[0].runs[0].bold = True


def _table(doc, header, rows):
    t = doc.add_table(rows=1, cols=len(header))
    t.style = "Light Grid Accent 1"
    for cell, text in zip(t.rows[0].cells, header):
        cell.text = text
    for row in rows:
        for cell, text in zip(t.add_row().cells, row):
            cell.text = str(text)


# ---- Excel ---------------------------------------------------------------------------------------
def build_xlsx(result, meta: dict, decision: Decision | None, brane_mode: str) -> bytes:
    wb = Workbook()
    out = result.model_output or result.fallback_drafts or {}

    ws = wb.active
    ws.title = "Summary"
    _sheet(ws, ["Item", "Value"], [
        ("Incident", meta.get("title", result.scenario)),
        ("Run", result.run_id),
        ("Organisation", f"{meta.get('organisation', '')}, {meta.get('sector', '')} ({meta.get('entity_type', '')})"),
        ("Became aware", _fmt_due(meta.get("aware_at", ""))),
        ("Earliest legal deadline", _fmt_due(result.earliest_deadline) if result.earliest_deadline else "none"),
        ("Leaked file (profiled locally)", result.profile_summary),
        ("Pipeline status", result.status),
        ("BRANE mode", brane_mode),
        ("Local pre-masking", result.premask),
        ("Model's suggested risk level", out.get("suggested_risk_level", "n/a")),
        ("Human decision", "APPROVED" if decision else "NOT YET APPROVED"),
        ("Exported", _now()),
    ], widths=[34, 100])

    _sheet(wb.create_sheet("Deadlines"), ["Regime", "Authority", "Step", "Due (Europe/Amsterdam)"],
           deadline_rows(result), widths=[10, 40, 60, 28])

    _sheet(wb.create_sheet("Protection decisions"), ["Data category", "Decision", "Findings", "Why"],
           decision_rows(result) or [("(none)", "", 0, "No protected data found in the report")],
           widths=[22, 16, 10, 80])

    h = result.brane_headers or {}
    _sheet(wb.create_sheet("BRANE verdict"), ["X-Brane header", "Value"],
           sorted(h.items()) or [("(none)", "No BRANE verdict: mock gateway or the request never reached BRANE")],
           widths=[32, 80])

    payload = result.payload_sent if result.premask == "full" else (
        "Not reproduced: in guard_only mode the payload contained contact data that BRANE pseudonymised. "
        "A locally masked copy is in the run protocol.")
    _sheet(wb.create_sheet("Payload sent"), ["Exact payload sent to BRANE"], [(payload or "NOTHING SENT",)],
           widths=[140], tall=True)

    facts = [(f, "") for f in out.get("missing_facts", [])] or [("(none listed)", "")]
    _sheet(wb.create_sheet("Facts to confirm"), ["Open question", "Answer / done"], facts, widths=[90, 40])

    rows = [("Reviewer", decision.who), ("Approved at", amsterdam(decision.approved_at)),
            ("Confirmed risk", RISK_TIERS.get(decision.risk_level, decision.risk_level)),
            ("Notify", ", ".join(TARGETS[t] for t in decision.notify) or "Nobody"),
            ("Reason / justification", decision.reason or "-"),
            ("Sent by BreachBrief", "No (the app never sends)")] if decision else [
            ("Status", "Waiting for a named reviewer to approve")]
    _sheet(wb.create_sheet("Human approval"), ["Item", "Value"], rows, widths=[28, 90])

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _sheet(ws, header, rows, widths, tall=False):
    ws.append(header)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=NAVY)
        cell.alignment = Alignment(vertical="center")
    for row in rows:
        ws.append(list(row))
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    if tall:
        ws.row_dimensions[2].height = 400
    ws.freeze_panes = "A2"
