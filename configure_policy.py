"""Configure our team's BRANE policy (PUT /policy) and print the saved summary.

  python configure_policy.py            # apply POLICY below
  python configure_policy.py --dry-run  # print the request body only, send nothing

The rules mirror POLICY_MATRIX.md. BRANE is the second line of defence: BreachBrief
already masks locally (LOCAL_PREMASK=full) and only BRANE sees what is left.
Product gap: BRANE has one rule per category, so ORG is either allowed or not. We need
authority/company names in the drafts (ORG=allow) but third-party recipients pseudonymised;
BreachBrief therefore pseudonymises recipients locally (RECIPIENT -> RECIPIENT_A) before BRANE.
"""
import json
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from breachbrief.brane_client import BraneUnavailable, LiveBrane  # noqa: E402

PLACEHOLDER = ["PERSON", "EMAIL", "PHONE", "ADDRESS", "IP_ADDRESS", "VAT_ID"]
ALLOW = ["ORG", "TRADE_REGISTER"]
REFUSE = ["DATE_OF_BIRTH", "SSN", "PASSPORT", "TAX_NUMBER", "INSURANCE_NUMBER", "IBAN", "CREDIT_CARD",
          "ACCOUNT_NUMBER", "PASSWORD", "SECRET_KEY"]
LOCAL = ["HEALTH_DATA", "ETHNIC_ORIGIN", "POLITICAL_OPINION", "RELIGIOUS_BELIEF", "SEXUAL_ORIENTATION",
         "TRADE_UNION", "SENSITIVE_CONTEXT"]

SEMANTIC_CATEGORIES = [
    {
        "code": "INDIRECT_HEALTH_CONTEXT",
        "name": "Indirect health context (sick leave, burn-out, company doctor, ward, pregnancy)",
        "description": ("Any direct or indirect reference to a person's health: sick leave, burn-out, re-integration, "
                        "a company or occupational doctor, oncology or other treatment, a hospital ward, pregnancy or "
                        "maternity, or incapacity for work, in English, Dutch or German, even without a diagnosis "
                        "or a name."),
        "keywords": ["sick leave", "burn-out", "burnout", "re-integration", "reintegration", "company doctor",
                     "occupational physician", "oncology", "hospital ward", "pregnancy", "pregnant",
                     "incapacity for work", "ziekteverlof", "ziekgemeld", "re-integratie", "bedrijfsarts",
                     "arbo-arts", "oncologie", "zwanger", "arbeidsongeschikt", "krankgeschrieben",
                     "arbeitsunfähig", "betriebsarzt", "schwanger", "wiedereingliederung"],
        "legalBasis": "GDPR Art. 9(1), Art. 4(15)",
        "action": "local",
    },
    {
        "code": "RAW_DATASET_EXFILTRATION",
        "name": "Request to disclose the raw leaked dataset",
        "description": ("Requests to include, paste, attach, forward or reproduce the full, raw, complete or unredacted "
                        "leaked dataset, file, spreadsheet or records, or to undo masking or replace placeholders "
                        "with real names or values."),
        "keywords": ["unredacted", "full spreadsheet", "raw file", "complete list", "paste the list",
                     "attach the file", "do not mask", "real names", "volledige lijst", "ongemaskeerd",
                     "vollständige liste", "ungeschwärzt"],
        "legalBasis": "GDPR Art. 5(1)(f), Art. 32, Art. 4(12)",
        "action": "refuse",
    },
    {
        "code": "AUTONOMOUS_NOTIFICATION_DECISION",
        "name": "AI decides the risk level or sends notifications on its own",
        "description": ("Requests that the AI itself decides the final risk level, or sends, files or submits a breach "
                        "notification to a supervisory authority, CSIRT, regulator or affected people without human "
                        "approval."),
        "keywords": ["submit the notification", "send the notification", "file the report with",
                     "notify the authority directly", "notify all affected", "decide the final risk",
                     "without waiting for approval", "dien de melding in", "melding versturen"],
        "legalBasis": "GDPR Art. 5(2), Art. 33(1), Art. 34(1)",
        "action": "refuse",
    },
]


def policy_body() -> dict:
    categories = {**{c: "placeholder" for c in PLACEHOLDER}, **{c: "allow" for c in ALLOW},
                  **{c: "refuse" for c in REFUSE}, **{c: "local" for c in LOCAL}}
    assert len(categories) == 25, "every one of BRANE's 25 built-in categories gets an explicit rule"
    return {"routingMode": "cloud-preferred", "piiSensitivity": "high", "categories": categories,
            "semanticCategories": SEMANTIC_CATEGORIES}


def print_summary(p: dict):
    s = p.get("summary", {})
    print(f"[POLICY SAVED] {p.get('team')}: routing={p.get('routingMode')} | piiSensitivity={p.get('piiSensitivity')} | "
          f"allow={s.get('allow')} placeholder={s.get('placeholder')} local={s.get('local')} refuse={s.get('refuse')} | "
          f"semantic rules={s.get('activeSemanticCategories')} | open baseline={s.get('isOpenBaseline')} | "
          f"updated={p.get('updatedAt')}")
    by_action: dict[str, list[str]] = {}
    for label, action in p.get("categories", {}).items():
        by_action.setdefault(action, []).append(label)
    for action in ("allow", "placeholder", "local", "refuse"):
        print(f"  {action:<11}: {', '.join(by_action.get(action, [])) or '-'}")
    for sc in p.get("semanticCategories", []):
        print(f"  semantic   : {sc.get('code')} -> {sc.get('action')} ({sc.get('legalBasis')})")


def main() -> int:
    body = policy_body()
    if "--dry-run" in sys.argv:
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0
    try:
        client = LiveBrane(os.getenv("BRANE_BASE_URL", ""), os.getenv("BRANE_API_KEY", ""), os.getenv("BRANE_MODEL", "auto"))
        saved = client.put_json("/policy", body)
    except BraneUnavailable as exc:
        print(f"FAILED: {exc}")
        return 1
    print_summary(saved)
    wanted = body["categories"]
    mismatch = {k: (v, saved.get("categories", {}).get(k)) for k, v in wanted.items()
                if saved.get("categories", {}).get(k) != v}
    if mismatch:
        print(f"WARNING: BRANE saved different actions for: {mismatch}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
