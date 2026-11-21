"""Phase 2: live-ready BRANE client, tested against a fake endpoint on localhost (no network)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from breachbrief import agent
from breachbrief.brane_client import BraneRefused, BraneUnavailable, LiveBrane

POLICY = {"team": "Team 13", "routingMode": "cloud-preferred", "piiSensitivity": "high",
          "categories": {"PERSON": "placeholder", "IBAN": "refuse", "HEALTH_DATA": "local", "ORG": "allow"},
          "semanticCategories": [{"code": "INDIRECT_HEALTH_CONTEXT", "action": "local", "legalBasis": "GDPR Art. 9(1)"}],
          "summary": {"allow": 1, "placeholder": 1, "local": 1, "refuse": 1, "activeSemanticCategories": 1}}
VERDICT = {"X-Brane-Routed-To": "cloud", "X-Brane-Redacted": "true", "X-Brane-Pii-Types": "PERSON,EMAIL"}


class FakeBrane(BaseHTTPRequestHandler):
    status = 200
    reply: object = {"id": "req-123", "choices": [{"message": {"content": "OK"}}]}
    verdict: dict = {}
    seen: list = []

    def _send(self, status, raw, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw.encode())

    def do_GET(self):
        FakeBrane.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "method": "GET"})
        if self.path.endswith("/policy/catalog"):
            self._send(200, json.dumps({"categories": [{"label": "PERSON"}], "semanticTemplates": []}))
        elif self.path.endswith("/policy"):
            self._send(200, json.dumps(POLICY))
        else:
            self._send(404, "{}")

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeBrane.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body,
                               "ua": self.headers.get("User-Agent")})
        raw = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        self._send(self.status, raw, self.verdict)

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_brane():
    FakeBrane.status, FakeBrane.seen, FakeBrane.verdict = 200, [], dict(VERDICT)
    FakeBrane.reply = {"id": "req-123", "choices": [{"message": {"content": "OK"}}]}
    server = HTTPServer(("127.0.0.1", 0), FakeBrane)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_live_client_openai_compatible(fake_brane):
    r = LiveBrane(fake_brane, "test-key", "test-model").complete("sys", "hello")
    assert r["content"] == "OK" and r["brane"]["request_id"] == "req-123"
    seen = FakeBrane.seen[0]
    assert seen["path"] == "/chat/completions" and seen["auth"] == "Bearer test-key"
    assert seen["body"]["model"] == "test-model" and seen["ua"].startswith("BreachBrief")
    assert seen["body"]["messages"][1] == {"role": "user", "content": "hello"}


def test_base_url_with_api_v1_and_model_auto(fake_brane):
    LiveBrane(fake_brane + "/api/v1", "test-key", "").complete("sys", "hello")
    assert FakeBrane.seen[0]["path"] == "/api/v1/chat/completions"
    assert FakeBrane.seen[0]["body"]["model"] == "auto"


def test_x_brane_headers_captured(fake_brane):
    r = LiveBrane(fake_brane, "test-key", "auto").complete("sys", "hello")
    assert r["brane"]["headers"] == VERDICT


def test_422_is_refusal_not_unavailable(fake_brane):
    FakeBrane.status, FakeBrane.reply = 422, {"error": {"type": "policy_violation"}}
    FakeBrane.verdict = {"X-Brane-Routed-To": "refused", "X-Brane-Refused-By": "category:IBAN->refuse"}
    with pytest.raises(BraneRefused) as exc:
        LiveBrane(fake_brane, "test-key", "auto").complete("sys", "hello")
    assert exc.value.headers["X-Brane-Refused-By"] == "category:IBAN->refuse"
    assert "escalate" in str(exc.value)


def test_agent_refused_by_brane_status(fake_brane):
    FakeBrane.status, FakeBrane.reply = 422, {"error": {"type": "policy_violation"}}
    FakeBrane.verdict = {"X-Brane-Routed-To": "refused", "X-Brane-Refused-By": "semantic:RAW_DATASET_EXFILTRATION->refuse"}
    r = agent.run("hospital_ransomware", client=LiveBrane(fake_brane, "test-key", "auto"))
    assert r.status == "refused_by_brane"
    assert r.payload_sent is None and r.model_output is None and r.needs_human_approval
    assert r.brane_headers["X-Brane-Refused-By"].startswith("semantic:")
    import json as _j
    from breachbrief import protocol
    entry = _j.loads((protocol.PROTOCOL_DIR / f"{r.run_id}.json").read_text(encoding="utf-8"))
    assert entry["outcome"] == "REFUSED_BY_BRANE_ESCALATE_TO_HUMAN" and entry["payload_sent"] is None
    assert entry["brane_headers"]["X-Brane-Routed-To"] == "refused"


def test_agent_ok_keeps_headers(fake_brane):
    FakeBrane.reply = {"id": "r1", "choices": [{"message": {"content": json.dumps({
        "incident_summary": "s", "missing_facts": ["f"], "suggested_risk_level": "high",
        "draft_authority_notification": "a", "draft_affected_people_notice": "p"})}}]}
    r = agent.run("payroll_misdirected", client=LiveBrane(fake_brane, "test-key", "auto"))
    assert r.status == "ok" and r.brane_headers == VERDICT


def test_api_shape_adaptable_via_env(fake_brane, monkeypatch):
    monkeypatch.setenv("BRANE_CHAT_PATH", "/gateway/chat")
    monkeypatch.setenv("BRANE_EXTRA_HEADERS", '{"X-Tenant": "ai-z"}')
    LiveBrane(fake_brane, "test-key", "m").complete("sys", "hello")
    assert FakeBrane.seen[0]["path"] == "/gateway/chat"


@pytest.mark.parametrize("status, reply", [(500, {"error": "boom"}), (503, "down"), (401, {"error": "auth"}),
                                           (200, {"unexpected": "shape"}), (200, "not json")])
def test_live_client_fails_closed_on_bad_responses(fake_brane, status, reply):
    FakeBrane.status, FakeBrane.reply = status, reply
    with pytest.raises(BraneUnavailable):
        LiveBrane(fake_brane, "test-key", "m").complete("sys", "hello")


def test_live_client_fails_closed_when_unreachable():
    with pytest.raises(BraneUnavailable):
        LiveBrane("http://127.0.0.1:9", "test-key", "m", timeout=2).complete("sys", "hello")
    r = agent.run("hospital_ransomware", client=LiveBrane("http://127.0.0.1:9", "test-key", "m", timeout=2))
    assert r.status == "brane_unavailable" and r.payload_sent is None


def test_live_client_not_configured():
    with pytest.raises(BraneUnavailable):
        LiveBrane("", "", "m")


def test_check_brane_script(fake_brane, monkeypatch, capsys):
    import check_brane
    monkeypatch.setenv("BRANE_BASE_URL", fake_brane)
    monkeypatch.setenv("BRANE_API_KEY", "test-key-1234")
    assert check_brane.main() == 0
    out = capsys.readouterr().out
    assert "HTTP 200" in out and "parsed model reply: 'OK'" in out
    assert "test-key-1234" not in out and "1234" not in out   # key is never printed, not even partly
    assert "placeholder: PERSON" in out and "refuse     : IBAN" in out and "INDIRECT_HEALTH_CONTEXT" in out
    assert "X-Brane-Routed-To: cloud" in out
    post = next(x for x in FakeBrane.seen if "body" in x)
    assert "personal data" in post["body"]["messages"][1]["content"]


def test_no_direct_model_sdk_anywhere_in_project():
    """Extends the core test to root scripts: no openai SDK / direct OpenAI URL outside the BRANE client."""
    import pathlib
    root = pathlib.Path(agent.__file__).parent.parent
    for f in [*root.glob("*.py"), *(root / "breachbrief").glob("*.py"), *(root / "scripts").glob("*.py")]:
        text = f.read_text(encoding="utf-8")
        assert "api.openai.com" not in text and "import openai" not in text and "from openai" not in text, f.name
