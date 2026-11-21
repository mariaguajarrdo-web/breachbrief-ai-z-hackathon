"""30-second check of the real BRANE endpoint: python check_brane.py

1. GET /policy/catalog and /policy: prints our team's current policy summary.
2. Sends ONE harmless test message (no personal data) and prints the raw response
   plus every X-Brane-* header. Exits non-zero on failure. The API key is never printed.
"""
import json
import os
import sys
from collections import Counter

from dotenv import load_dotenv

load_dotenv()

from breachbrief.brane_client import BraneUnavailable, LiveBrane, get_client  # noqa: E402

TEST_SYSTEM = "You are a connectivity test. Reply with the single word OK."
TEST_USER = "Connectivity test from BreachBrief. This message contains no personal data. Reply with OK."


def policy_summary(client: LiveBrane) -> bool:
    try:
        catalog = client.get_json("/policy/catalog")
        policy = client.get_json("/policy")
    except Exception as exc:
        print(f"Policy     : could not read /policy ({exc})")
        return False
    cats = policy.get("categories", {})
    s = policy.get("summary", {})
    print(f"Catalog    : {len(catalog.get('categories', []))} built-in categories, "
          f"{len(catalog.get('semanticTemplates', []))} semantic templates")
    print(f"Policy     : {policy.get('team')} | routing={policy.get('routingMode')} | "
          f"piiSensitivity={policy.get('piiSensitivity')} | updated={policy.get('updatedAt')}")
    print(f"Summary    : allow={s.get('allow')} placeholder={s.get('placeholder')} local={s.get('local')} "
          f"refuse={s.get('refuse')} semantic={s.get('activeSemanticCategories')}"
          f"{' (OPEN BASELINE: nothing configured yet!)' if s.get('isOpenBaseline') else ''}")
    by_action: dict[str, list[str]] = {}
    for label, action in cats.items():
        by_action.setdefault(action, []).append(label)
    for action in ("allow", "placeholder", "local", "refuse"):
        if by_action.get(action):
            print(f"  {action:<11}: {', '.join(by_action[action])}")
    for sc in policy.get("semanticCategories", []):
        print(f"  semantic   : {sc.get('code')} -> {sc.get('action')} ({sc.get('legalBasis')})")
    assert sum(Counter(cats.values()).values()) == len(cats)
    return True


def main() -> int:
    try:
        client = LiveBrane(os.getenv("BRANE_BASE_URL", ""), os.getenv("BRANE_API_KEY", ""),
                           os.getenv("BRANE_MODEL", "auto"))
    except BraneUnavailable as exc:
        print(f"NOT CONFIGURED: {exc}\nFill in BRANE_BASE_URL and BRANE_API_KEY in .env.")
        return 2

    print(f"Endpoint   : {client.api.url()}")
    print(f"Model      : {client.api.model}")
    print(f"Auth       : header '{client.api.auth_header}', key set (never printed)")
    print(f"Mode       : BRANE_MODE={os.getenv('BRANE_MODE', 'mock')} (this script always calls the live endpoint)")
    print(f"Build      : {os.getenv('TEAM_BUILD', '-')}")
    policy_ok = policy_summary(client)
    print("\nSending one test message...")

    try:
        status, raw, headers = client.post_raw(TEST_SYSTEM, TEST_USER)
    except Exception as exc:
        print(f"FAILED: could not reach BRANE: {exc}")
        return 1

    print(f"HTTP {status}")
    for k, v in sorted(headers.items()):
        print(f"  {k}: {v}")
    print("--- raw response ---")
    try:
        print(json.dumps(json.loads(raw), indent=2, ensure_ascii=False))
    except ValueError:
        print(raw)
    print("--------------------")

    if status != 200:
        print("FAILED: non-200 response." + (" (422 = refused by BRANE policy)" if status == 422 else ""))
        return 1
    try:
        content, meta = client.api.parse(json.loads(raw))
    except Exception as exc:
        print(f"REACHABLE, BUT the response shape is not what BraneApi.parse() expects ({exc!r}).\n"
              "Adapt BraneApi.parse() in breachbrief/brane_client.py to this shape.")
        return 1
    print(f"OK: parsed model reply: {content!r}\nBRANE request id: {meta.get('request_id')}")
    try:
        live = isinstance(get_client(), LiveBrane)
    except BraneUnavailable:
        live = False
    print("BRANE_MODE=live: the app and run_demo.py use this endpoint." if live
          else "Set BRANE_MODE=live in .env to use this endpoint in the app.")
    return 0 if policy_ok else 1


if __name__ == "__main__":
    sys.exit(main())
