"""Test/audit protocol. Records decisions and the exact outgoing payload,
never the raw protected values themselves."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROTOCOL_DIR = Path(__file__).resolve().parent.parent / "protocol"


def record(run_id: str, scenario: str, decisions: list[dict], payload_sent: str | None, outcome: str, extra: dict | None = None) -> dict:
    entry = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenario": scenario,
        "decision_counts": dict(Counter(f"{x['category']}:{x['decision']}" for x in decisions)),
        "decisions": decisions,
        "payload_sent": payload_sent,  # None = nothing left the machine
        "outcome": outcome,
        **(extra or {}),
    }
    PROTOCOL_DIR.mkdir(exist_ok=True)
    (PROTOCOL_DIR / f"{run_id}.json").write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
    return entry


def record_ui_error(run_id: str, step: str, exc: BaseException) -> dict:
    """Add a screen error to the run's protocol entry. Only the exception type and the code frames are kept,
    never the message or local values, which could hold protected data. The console gets the full traceback."""
    import traceback
    frames = [f"{Path(f.filename).name}:{f.lineno} in {f.name}" for f in traceback.extract_tb(exc.__traceback__)]
    item = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), "step": step,
            "error_type": type(exc).__name__, "traceback": frames}
    PROTOCOL_DIR.mkdir(exist_ok=True)
    path = PROTOCOL_DIR / f"{run_id}.json"
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        entry = {"run_id": run_id}
    entry.setdefault("ui_errors", []).append(item)
    path.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
    return item


def record_approval(run_id: str, approval: dict) -> dict:
    """Add the human reviewer's decision to the run's existing protocol entry."""
    path = PROTOCOL_DIR / f"{run_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"No protocol entry for run {run_id}; cannot record an approval for an unknown run.")
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["human_approval"] = approval
    path.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
    return entry
