"""BRANE gateway. Every model call goes through here, and only through here.

FAIL CLOSED: if BRANE is unreachable, errors, or the local guard finds a leak,
we raise and send NOTHING. There is no fallback to a direct cloud call anywhere
in this codebase.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid

from . import detectors as d


class BraneUnavailable(Exception):
    """BRANE could not perform its check (network, timeout, 5xx, bad response). Nothing was sent. Fail closed."""


class BraneRefused(Exception):
    """BRANE's policy refused the request (HTTP 422). No model ran. Must be escalated to a human."""

    def __init__(self, message: str, headers: dict | None = None, body: str = ""):
        super().__init__(message)
        self.headers = headers or {}
        self.body = body


class LeakPrevented(Exception):
    """The local pre-send guard found protected data in the payload. Nothing was sent."""


class MockBrane:
    """Offline stand-in for BRANE so we can build before we have credentials.

    Mirrors the documented behaviour: detect, pseudonymise with placeholders,
    block, and refuse to forward when its check is unavailable.

    `responses`: optional scripted model answers returned in order (for tests of
    the output contract); after they run out the deterministic mock answer is used.
    """

    name = "mock"

    def __init__(self, simulate_down: bool = False, responses: list[str] | None = None):
        self.simulate_down = simulate_down
        self.responses = list(responses or [])
        self.last_forwarded: str | None = None
        self.forwarded: list[dict] = []  # every (system, user) pair that reached the "model"

    def complete(self, system: str, user: str) -> dict:
        if self.simulate_down:
            raise BraneUnavailable("BRANE is down (simulated outage for the demo). The request was not forwarded.")
        # BRANE's own second-line scan (pattern-level; names need context it doesn't have)
        brane_hits = [f.category for f in d.detect(user, use_ner=False) if f.category in (d.IBAN, d.NATIONAL_ID, d.EMAIL, d.PHONE)]
        self.last_forwarded = user
        self.forwarded.append({"system": system, "user": user})
        content = self.responses.pop(0) if self.responses else _mock_model_answer(user, system)
        return {
            "content": content,
            "brane": {"request_id": f"mock-{uuid.uuid4().hex[:12]}", "gateway": "mock",
                      "brane_additional_detections": brane_hits, "forwarded": True},
        }


# ---------------------------------------------------------------------------
# LIVE BRANE: everything that depends on the real endpoint's API shape lives in
# BraneApi below (URL, headers, request body, response parsing). OpenAI-compatible:
# POST {BRANE_BASE_URL}/chat/completions, where the base already ends in /api/v1.
# ---------------------------------------------------------------------------
USER_AGENT = "BreachBrief/1.0 (Team-13, MAIN Summit 2026)"


def brane_headers_of(headers) -> dict:
    """All X-Brane-* response headers, with their canonical names. This is BRANE's verdict on the request."""
    out = {}
    for k, v in (headers.items() if headers else []):
        if k.lower().startswith("x-brane-"):
            out["-".join(part.capitalize() for part in k.split("-"))] = v
    return out


class BraneApi:
    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model or "auto"
        self.chat_path = os.getenv("BRANE_CHAT_PATH", "/chat/completions")
        self.auth_header = os.getenv("BRANE_AUTH_HEADER", "Authorization")
        self.auth_scheme = os.getenv("BRANE_AUTH_SCHEME", "Bearer")      # empty = send the raw key
        self.extra_headers = json.loads(os.getenv("BRANE_EXTRA_HEADERS", "") or "{}")

    def url(self, path: str | None = None) -> str:
        return self.base_url + (path if path is not None else self.chat_path)

    def headers(self, json_body: bool = True) -> dict:
        auth = f"{self.auth_scheme} {self.api_key}".strip() if self.auth_scheme else self.api_key
        h = {"User-Agent": USER_AGENT, self.auth_header: auth, **self.extra_headers}
        if json_body:
            h["Content-Type"] = "application/json"
        return h

    def body(self, system: str, user: str) -> dict:
        return {"model": self.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}

    def parse(self, data: dict) -> tuple[str, dict]:
        """Return (model text, BRANE metadata). Raise KeyError/IndexError/TypeError if the shape is wrong."""
        content = data["choices"][0]["message"]["content"]
        meta = {"request_id": data.get("id"), "gateway": "live", "model": data.get("model"),
                "raw_meta": {k: v for k, v in data.items() if k != "choices"}}
        return content, meta


class LiveBrane:
    """Real BRANE endpoint.

    HTTP 200 -> answer + X-Brane-* verdict headers.
    HTTP 422 -> BraneRefused: BRANE's policy stopped the request; escalate to a human.
    anything else (network, timeout, 4xx/5xx, malformed body) -> BraneUnavailable: fail closed.
    """

    name = "live"
    # Removal markers go out as "(iban removed)": BRANE flags "[IBAN_REMOVED]"-style tokens as PASSWORD
    # and refuses the whole request (false positive). See agent.render_markers.
    marker_style = "plain"

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 90.0):
        if not base_url or not api_key:
            raise BraneUnavailable("BRANE_BASE_URL / BRANE_API_KEY not configured. Nothing sent.")
        self.api = BraneApi(base_url, api_key, model)
        self.timeout = timeout

    def _request(self, method: str, path: str | None, body: dict | None = None) -> tuple[int, str, dict]:
        """Returns (HTTP status, raw body, X-Brane-* headers). Raises on network errors only."""
        req = urllib.request.Request(self.api.url(path), data=json.dumps(body).encode() if body is not None else None,
                                     headers=self.api.headers(json_body=body is not None), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace"), brane_headers_of(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace"), brane_headers_of(exc.headers)

    def post_raw(self, system: str, user: str) -> tuple[int, str, dict]:
        """One chat request, uninterpreted: (HTTP status, raw body, X-Brane-* headers). Used by check_brane.py."""
        return self._request("POST", None, self.api.body(system, user))

    def get_json(self, path: str) -> dict:
        status, raw, _ = self._request("GET", path)
        if status != 200:
            raise BraneUnavailable(f"GET {path} returned HTTP {status}: {raw[:200]}")
        return json.loads(raw)

    def put_json(self, path: str, body: dict) -> dict:
        status, raw, _ = self._request("PUT", path, body)
        if status != 200:
            raise BraneUnavailable(f"PUT {path} returned HTTP {status}: {raw[:300]}")
        return json.loads(raw)

    def complete(self, system: str, user: str) -> dict:
        try:
            status, raw, headers = self.post_raw(system, user)
        except Exception as exc:  # network, DNS, TLS, timeout: fail closed
            raise BraneUnavailable(f"BRANE check unavailable: {exc}. Nothing sent.") from exc
        if status == 422:
            refused_by = headers.get("X-Brane-Refused-By", "policy")
            raise BraneRefused(f"Refused by BRANE policy ({refused_by}). No model ran; escalate to a human reviewer.",
                               headers, raw[:500])
        if status != 200:
            raise BraneUnavailable(f"BRANE returned HTTP {status}: {raw[:200]}")
        try:
            content, meta = self.api.parse(json.loads(raw))
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise BraneUnavailable(f"Unexpected BRANE response: {raw[:200]}") from exc
        meta["headers"] = headers
        return {"content": content, "brane": meta}


def get_client():
    mode = os.getenv("BRANE_MODE", "mock").lower()
    if mode == "live":
        return LiveBrane(os.getenv("BRANE_BASE_URL", ""), os.getenv("BRANE_API_KEY", ""), os.getenv("BRANE_MODEL", "auto"))
    return MockBrane(simulate_down=os.getenv("BRANE_SIMULATE_DOWN", "0") == "1")


_MOCK_MISSING_FACTS = {
    "ransomware": [
        "What is the confirmed scope of the exfiltration (which files, how many records, which time window)?",
        "Have the backups been verified as clean and complete, and when can systems be restored from them?",
        "Has anyone been in contact with the attackers or responded to the ransom note, and is law enforcement involved?",
    ],
    "bank": [
        "Has the third party provided a written deletion certificate for the data it received?",
        "Exactly which customers had not consented, and what did their consent scope cover?",
        "Were the exposed responses stored, logged or shared further by the third party?",
    ],
    "misdirected": [
        "Was the file opened or forwarded by the unintended recipient?",
        "Has deletion been confirmed in writing by the recipient?",
        "Were the affected people's data encrypted or otherwise unintelligible?",
    ],
}


def _mock_incident_kind(user: str) -> str:
    """Pick the scenario family from the sanitised payload (sector line + report wording)."""
    low = user.lower()
    if "ransom" in low or "encryption activity" in low:
        return "ransomware"
    if "sector: banking" in low or "credit_institution" in low or "open-banking" in low:
        return "bank"
    return "misdirected"


def _mock_model_answer(user: str, system: str = "") -> str:
    """Deterministic stand-in for the model so the pipeline runs end to end offline. Its drafts use the same
    [square bracket] placeholders a real model leaves for facts it was not given; they are filled locally."""
    answer = {
        "incident_summary": "Mock analysis based only on the sanitised facts provided.",
        "missing_facts": _MOCK_MISSING_FACTS[_mock_incident_kind(user)] + [
            "When did the organisation become aware of the breach?",          # known locally: filtered out
            "How many people are affected?"],                                  # known locally: filtered out
        "suggested_risk_level": "HIGH (for human confirmation)",
        "draft_authority_notification": (
            "MOCK DRAFT for [Supervisory authority]. [Organisation name] notifies a personal data breach it became "
            "aware of on [Date and time of awareness]. Approximately [Number of affected people] records are "
            "involved. (Offline mock: in live mode a model writes this text.)"),
        "draft_affected_people_notice": (
            "MOCK DRAFT. Dear reader, [Organisation name] informs you that some of your personal data may have been "
            "exposed. (Offline mock: in live mode a model writes this text.)"),
    }
    if "draft_nis2_early_warning" in system:
        answer["draft_nis2_early_warning"] = ("MOCK DRAFT early warning to [CSIRT]: [Organisation name], essential "
                                              "entity, detected a significant incident. Suspected malicious act: yes.")
    if "draft_dora_initial_notification" in system:
        answer["draft_dora_initial_notification"] = ("MOCK DRAFT initial notification to [Competent authority]: "
                                                     "[Organisation name] classified a major ICT-related incident.")
    return json.dumps(answer, indent=2)
