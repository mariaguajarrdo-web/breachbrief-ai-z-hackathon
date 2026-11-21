"""Stress tests for the live demo: every toggle combination, rapid scenario switching, every step, both themes.
Zero exceptions allowed (BREACHBRIEF_STRICT=1 re-raises anything the calm error card would otherwise hide).
Also guards the two state bugs: a step of None / an old id, and the scenario folder vanishing under a run."""
import itertools
import threading
from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from breachbrief import agent, approval, casebook

APP = str(Path(__file__).resolve().parent.parent / "app.py")
SCENARIOS = ["payroll_misdirected", "hospital_ransomware", "bank_ict_incident"]
STEPS = ["protect", "drafts", "decide", "evidence"]
ERROR_CARD = "Something went wrong in this step"


@pytest.fixture(autouse=True)
def offline_mock(monkeypatch, tmp_path):
    monkeypatch.setenv("BRANE_MODE", "mock")
    monkeypatch.setenv("BRANE_SIMULATE_DOWN", "0")
    monkeypatch.setenv("BREACHBRIEF_PREWARM", "0")
    monkeypatch.setenv("BREACHBRIEF_STRICT", "1")
    monkeypatch.setattr(approval, "EXPORT_DIR", tmp_path / "exports")
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def ok(at: AppTest):
    assert not at.exception, [e.value for e in at.exception]
    assert not any(ERROR_CARD in m.value for m in at.markdown)


def toggle(at, label):
    return next(t for t in at.sidebar.toggle if t.label == label)


@pytest.mark.parametrize("light", [False, True], ids=["dark", "light"])
def test_stress_every_combination_with_rapid_switching(light):
    at = AppTest.from_file(APP, default_timeout=300)
    at.run()
    ok(at)
    toggle(at, "Light mode").set_value(light).run()
    for scenario in SCENARIOS:
        at.sidebar.radio[0].set_value(scenario).run()
        ok(at)
        assert at.session_state["step"] == "protect"                 # a new scenario always starts at step 1
        for premask, down, clock in itertools.product((True, False), repeat=3):
            toggle(at, "Local pre-masking").set_value(premask).run()
            toggle(at, "Simulate BRANE down").set_value(down).run()
            toggle(at, "Demo clock").set_value(clock).run()
            ok(at)
            for other in SCENARIOS:                                  # switch scenarios rapidly in between
                if other != scenario:
                    at.sidebar.radio[0].set_value(other).run()
                    ok(at)
            at.sidebar.radio[0].set_value(scenario).run()
            for step in STEPS:
                at.session_state["step"] = step
                at.run()
                ok(at)
    assert at.session_state["light_mode"] is light


@pytest.mark.parametrize("bad", [None, "", "old_step_id", "safe-to-send"])
def test_invalid_step_falls_back_to_step_one(bad):
    # stale state from an earlier run (set before the widget exists: AppTest itself cannot serialise an invalid
    # value into an already-rendered segmented control)
    at = AppTest.from_file(APP, default_timeout=300)
    at.session_state["step"] = bad
    at.run()
    ok(at)
    assert at.session_state["step"] == "protect"
    at.run()                                                         # and the next rerun is fine too
    ok(at)


def test_invalid_step_inside_a_running_session_falls_back(monkeypatch):
    """A rerun where the step widget hands back None (seen live after toggling 'Simulate BRANE down')."""
    def script():
        import streamlit as st
        import app
        st.session_state["step"] = None
        st.write(app.current_step())
        st.session_state["step"] = "gone"
        st.write(app.current_step())
        app.go_to("not-a-step")
        st.write(st.session_state["step"])

    at = AppTest.from_function(script, default_timeout=60)
    at.run()
    assert not at.exception
    assert [m.value for m in at.markdown] == ["protect", "protect", "protect"]


def test_scenario_change_resets_the_step():
    at = AppTest.from_file(APP, default_timeout=300)
    at.run()
    at.session_state["step"] = "decide"
    at.run()
    at.sidebar.radio[0].set_value("bank_ict_incident").run()
    ok(at)
    assert at.session_state["step"] == "protect"


def test_injected_case_never_redirects_concurrent_runs():
    """BUG 1: the in-app security tests used to swap agent.SCENARIO_DIR to a temp copy and delete it, so a run
    in another thread read <tmp>/bank_ict_incident/meta.json after it was gone."""
    shipped = agent.SCENARIO_DIR
    errors: list[BaseException] = []
    stop = threading.Event()

    def injector():
        while not stop.is_set():
            with casebook.scenario_with_injected_cell("payroll_misdirected", "notes_hr", 2, "x") as tmp:
                assert (tmp / "payroll_misdirected" / "meta.json").exists()

    def reader():
        try:
            for _ in range(300):
                for s in SCENARIOS:
                    meta, _, path = agent.load_scenario(s)
                    assert path.exists() and path.is_relative_to(shipped)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=injector)] + [threading.Thread(target=reader) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads[1:]:
        t.join()
    stop.set()
    threads[0].join()
    assert not errors, errors
    assert agent.SCENARIO_DIR == shipped


def test_injected_copy_is_used_only_when_passed_explicitly():
    with casebook.scenario_with_injected_cell("payroll_misdirected", "notes_hr", 2, casebook.CSV_INJECTION) as tmp:
        r = agent.run("payroll_misdirected", scenario_dir=tmp)
        plain = agent.run("payroll_misdirected")
    assert any(x.get("source") == "leaked_file" for x in r.decisions)
    assert not any(x.get("source") == "leaked_file" for x in plain.decisions)


def test_step_error_shows_a_calm_card_and_logs_without_values(monkeypatch, tmp_path):
    from breachbrief import protocol
    monkeypatch.setenv("BREACHBRIEF_STRICT", "0")
    monkeypatch.setattr(protocol, "PROTOCOL_DIR", tmp_path)

    def script():
        import app

        class Run:
            run_id = "ui-error-test"

        def boom():
            raise RuntimeError("NL91ABNA0417164300 must never reach the protocol")

        app.safe_render("protect", Run(), boom)

    at = AppTest.from_function(script, default_timeout=60)
    at.run()
    assert not at.exception
    assert any("Something went wrong in this step. Nothing was sent." in m.value for m in at.markdown)
    entry = (tmp_path / "ui-error-test.json").read_text(encoding="utf-8")
    assert "RuntimeError" in entry and "boom" in entry
    assert "NL91ABNA0417164300" not in entry


def test_no_reviewer_bar_when_nothing_was_kept_back():
    at = AppTest.from_file(APP, default_timeout=300)
    at.run()
    for scenario in SCENARIOS:
        at.sidebar.radio[0].set_value(scenario).run()
        at.session_state["step"] = "evidence"
        at.run()
        ok(at)
        assert not any(e.label.startswith("Reviewer only: 0 ") for e in at.expander)
