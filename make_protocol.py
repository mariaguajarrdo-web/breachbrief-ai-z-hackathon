"""Run the 10 protocol cases and write TEST_PROTOCOL.md + TEST_PROTOCOL.json.
With BRANE_MODE=live it also runs the AI-Z evidence set T1-T5 + E1-E5 against live BRANE and writes
test_evidence_run.csv (exact kit/MAIN_Five_Tests_Template.csv columns) + test_evidence_run.json.

  python make_protocol.py                 # protocol (+ live evidence when BRANE_MODE=live)
  python make_protocol.py --evidence-only # only the live evidence CSV
  python make_protocol.py --no-evidence   # only the protocol

Uses the BRANE client configured in .env; the mode is stated at the top of the report.
Case R5 always forces BRANE down. Exit code 1 if any case fails. The API key is never written.
"""
import dataclasses
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from breachbrief import casebook, evidence  # noqa: E402

ROOT = Path(__file__).resolve().parent
MD_PATH, JSON_PATH = ROOT / "TEST_PROTOCOL.md", ROOT / "TEST_PROTOCOL.json"
EVIDENCE_CSV, EVIDENCE_JSON = ROOT / "test_evidence_run.csv", ROOT / "test_evidence_run.json"
DECISION_LABEL = {"ALLOW": "ALLOW", "PROTECT": "PROTECT", "LOCAL_ONLY": "LOCAL ONLY", "BLOCK": "BLOCK"}
MODE_NOTE = {
    "MOCK": "MOCK: offline stand-in for BRANE. Payloads went through the local mock gateway; no real model was called.",
    "LIVE": "LIVE: payloads were sent through the real BRANE endpoint.",
    "LIVE (not configured)": "LIVE selected but BRANE_BASE_URL / BRANE_API_KEY are missing: every request failed closed.",
}


def git_version() -> str:
    try:
        head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        return head + (" (with uncommitted changes)" if dirty else "")
    except Exception:
        return "unknown"


def cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render(results, mode: str, generated: str, version: str) -> str:
    n_pass = sum(r.passed for r in results)
    out = [
        "# BreachBrief test protocol",
        "",
        f"> **BRANE mode: {mode}**. {MODE_NOTE[mode]}",
        "",
        f"- Generated (UTC): {generated}",
        f"- Code version: `{version}`",
        f"- Python {platform.python_version()} on {platform.system()}",
        f"- **Result: {n_pass}/{len(results)} PASS**",
        "",
        "Inputs are summarised without raw protected values. Payloads are shown exactly as they left the machine.",
        "",
        "| ID | Case | Type | Result |",
        "|---|---|---|---|",
    ]
    for r in results:
        out.append(f"| [{r.id}](#{r.id.lower()}) | {cell(r.title)} | "
                   f"{'AI-Z required' if r.kind == 'required' else 'edge case'} | "
                   f"{'PASS' if r.passed else '**FAIL**'} |")
    for r in results:
        out += ["", "---", "", f'<a id="{r.id.lower()}"></a>', f"## {r.id}. {r.title}: {'PASS' if r.passed else 'FAIL'}", "",
                f"- **Goal:** {r.goal}",
                f"- **Input:** {r.input_summary}",
                f"- **BRANE:** {mode} ({r.brane_note})",
                f"- **Timestamp (UTC):** {r.timestamp}"]
        for run in r.runs:
            out += ["", f"### Run: {run.label} (status `{run.status}`)", ""]
            if run.categories:
                out += ["| Detected category | Found | Decision |", "|---|---|---|"]
                out += [f"| {cat} | {run.counts[cat]} | {DECISION_LABEL.get(run.decisions[cat], run.decisions[cat])} |"
                        for cat in run.categories]
            else:
                out.append("Detected categories: none.")
            if run.payload is not None:
                out += ["", "Incident facts: ALLOW (sent as is).", "", "Exact payload sent through BRANE:", "",
                        "```text", run.payload, "```"]
            else:
                out += ["", "**NOTHING SENT**"]
        out += ["", "| Expected | Actual | Result |", "|---|---|---|"]
        out += [f"| {cell(c.expected)} | {cell(c.actual)} | {'PASS' if c.passed else '**FAIL**'} |" for c in r.checks]
    out.append("")
    return "\n".join(out)


def run_protocol(mode: str, version: str) -> bool:
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"BRANE mode: {mode}. Running {len(casebook.CASES)} protocol cases...")
    results = casebook.run_all()
    for r in results:
        print(f"  {r.id} {'PASS' if r.passed else 'FAIL'}  {r.title}")
    MD_PATH.write_text(render(results, mode, generated, version), encoding="utf-8")
    JSON_PATH.write_text(json.dumps({
        "generated": generated, "brane_mode": mode, "code_version": version,
        "passed": sum(r.passed for r in results), "total": len(results),
        "cases": [{**dataclasses.asdict(r), "passed": r.passed} for r in results],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {MD_PATH.name} and {JSON_PATH.name}: {sum(r.passed for r in results)}/{len(results)} PASS")
    return all(r.passed for r in results)


def run_evidence(mode: str) -> bool:
    if mode != "LIVE":
        print(f"Evidence run skipped: needs BRANE_MODE=live with credentials (current: {mode}).")
        return True
    team = os.getenv("TEAM_BUILD", "Team-13 / policy-v1")
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"Running live evidence T1-T5 + E1-E5 against BRANE ({team})...")
    results = []
    for case in evidence.CASES:
        ev = case()
        results.append(ev)
        print(f"  {ev.test_id} {'PASS' if ev.passed else 'FAIL'}  route={ev.headers.get('X-Brane-Routed-To', '-')}"
              f"  {'; '.join(d for d, ok in ev.checks if not ok)}")
    evidence.write_csv(results, EVIDENCE_CSV, team)
    evidence.write_json(results, EVIDENCE_JSON, team, generated)
    print(f"Wrote {EVIDENCE_CSV.name} and {EVIDENCE_JSON.name}: {sum(e.passed for e in results)}/{len(results)} PASS")
    return all(e.passed for e in results)


def main() -> int:
    mode = casebook.brane_mode()
    version = git_version()
    ok = True
    if "--evidence-only" not in sys.argv:
        ok &= run_protocol(mode, version)
    if "--no-evidence" not in sys.argv:
        ok &= run_evidence(mode)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
