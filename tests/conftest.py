"""Tests never call the live BRANE endpoint, even when .env says BRANE_MODE=live and some
module (app.py, check_brane.py) has loaded it. Live runs are make_protocol.py's job."""
import pytest


@pytest.fixture(autouse=True)
def _offline_mock_brane(monkeypatch):
    monkeypatch.setenv("BRANE_MODE", "mock")
    monkeypatch.setenv("BRANE_SIMULATE_DOWN", "0")
    monkeypatch.setenv("LOCAL_PREMASK", "full")
    monkeypatch.setenv("BRANE_CHAT_PATH", "/chat/completions")
    monkeypatch.delenv("BRANE_EXTRA_HEADERS", raising=False)
