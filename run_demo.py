"""Quick CLI demo.

  python run_demo.py [scenario] [--down]
  python run_demo.py hospital_ransomware --approve --reviewer "J. Doe (DPO)" --risk high \
      --notify authority,csirt,affected_people
  python run_demo.py payroll_misdirected --approve --reviewer "J. Doe" --risk unlikely --notify none \
      --reason "Recipient deleted the file; written confirmation received."

--approve is the HUMAN step: it exports the approved drafts to exports/ and records the
decision in the protocol. Nothing is ever sent by the app.
"""
import argparse
import json

from dotenv import load_dotenv

from breachbrief import agent
from breachbrief.approval import ApprovalError, approve
from breachbrief.brane_client import MockBrane, get_client

load_dotenv()
ap = argparse.ArgumentParser(description="BreachBrief demo")
ap.add_argument("scenario", nargs="?", default="payroll_misdirected")
ap.add_argument("--down", action="store_true", help="simulate BRANE being unavailable")
ap.add_argument("--approve", action="store_true", help="human approval step (requires --reviewer, --risk, --notify)")
ap.add_argument("--reviewer")
ap.add_argument("--risk", choices=["unlikely", "risk", "high", "low"], help="risk tier (low = legacy alias for risk)")
ap.add_argument("--notify", help="comma-separated: authority, csirt (NIS2), financial_supervisor (DORA), affected_people; or none")
ap.add_argument("--reason", default="", help="required when a notification is omitted")
args = ap.parse_args()
if args.approve and not (args.reviewer and args.risk and args.notify):
    ap.error("--approve needs --reviewer, --risk and --notify")

client = MockBrane(simulate_down=True) if args.down else get_client()
r = agent.run(args.scenario, client=client)

print(f"\n=== {args.scenario} | status: {r.status} ===")
if r.message:
    print(r.message)
print("\nRegimes:", ", ".join(x["regime"] for x in r.regimes), "| earliest deadline:", r.earliest_deadline)
print("\nDecisions:")
for k in sorted({f"{x['category']} -> {x['decision']}" for x in r.decisions}):
    print("  ", k)
print("\nKept local (shown only to the human reviewer):", r.local_only or "-")
print("\nEXACT payload sent through BRANE:\n" + (r.payload_sent or "NOTHING SENT"))
if r.model_output:
    print("\nModel output:\n" + json.dumps(r.model_output, indent=2, ensure_ascii=False))
print("\nHuman approval required before anything is notified:", r.needs_human_approval)

if args.approve:
    try:
        a = approve(r, reviewer=args.reviewer, risk_level=args.risk, notify=args.notify, reason=args.reason)
    except ApprovalError as exc:
        raise SystemExit(f"\nAPPROVAL REJECTED: {exc}")
    print(f"\nApproved by {a.reviewer} on {a.approved_at_local}: risk {a.risk_level.upper()}, "
          f"notify {', '.join(a.notify) or 'nobody'}.")
    print(f"Approved package (not sent): {a.export_path}")
else:
    print("Run again with --approve --reviewer ... --risk ... --notify ... to record the human decision.")
