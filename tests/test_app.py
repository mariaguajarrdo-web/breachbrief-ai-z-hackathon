"""Streamlit demo UI: headless runs with Streamlit's AppTest (offline, no network).
Layout: intro, then 3 steps (protect / drafts / decide) and an Evidence tab; tests jump via session_state["step"]."""
import importlib
import io
import json
from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from breachbrief import approval, brane_client

APP = str(Path(__file__).resolve().parent.parent / "app.py")
STEPS = ["protect", "drafts", "decide", "evidence"]


@pytest.fixture(autouse=True)
def offline_mock(monkeypatch, tmp_path):
    monkeypatch.setenv("BRANE_MODE", "mock")
    monkeypatch.setenv("BRANE_SIMULATE_DOWN", "0")
    monkeypatch.setenv("BREACHBRIEF_PREWARM", "0")
    monkeypatch.setenv("BREACHBRIEF_STRICT", "1")      # a crash in a step must fail the test
    monkeypatch.setattr(approval, "EXPORT_DIR", tmp_path / "exports")
    st.cache_resource.clear()          # cached runs must not leak between tests
    yield
    st.cache_resource.clear()


def start(scenario=None, down=False, step=None, premask=True) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=180)
    at.run()
    if scenario:
        at.sidebar.radio[0].set_value(scenario).run()
    if down:
        toggle(at, "Simulate BRANE down").set_value(True).run()
    if not premask:
        toggle(at, "Local pre-masking").set_value(False).run()
    if step:
        goto(at, step)
    assert not at.exception, [e.value for e in at.exception]
    return at


def toggle(at, label):
    return next(t for t in at.sidebar.toggle if t.label == label)


def goto(at, step):
    at.session_state["step"] = step
    at.run()
    assert not at.exception, [e.value for e in at.exception]


def html_blocks(at) -> list[str]:
    return [m.value for m in at.markdown] + [h.proto.body for h in at.get("html")]


def all_text(at) -> str:
    parts = html_blocks(at)
    for kind in ("success", "error", "warning", "info"):
        parts += [f"{a.proto.title}\n{a.value}" for a in getattr(at, kind)]
    parts += [c.value for c in at.caption] + [h.value for h in at.subheader] + [t.value for t in at.title]
    parts += [f"{m.label}: {m.value}" for m in at.metric]
    return "\n".join(parts)


def card(at) -> str:
    """The 'What the security firewall did' card (title + sentence)."""
    i = next(i for i, m in enumerate(at.markdown) if m.value == "**What the security firewall did**")
    title = next(h.value for h in at.subheader)                  # heading without a URL anchor
    return f"### {title}\n{at.markdown[i + 1].value}"


GOOD = {"incident_summary": "s", "missing_facts": ["Was the file opened?"], "suggested_risk_level": "high",
        "draft_authority_notification": "Notification by [Organisation name].", "draft_affected_people_notice": "p",
        "draft_nis2_early_warning": "Early warning.", "draft_dora_initial_notification": "Initial notification."}


class FakeLive(brane_client.LiveBrane):
    """A LiveBrane whose network calls are faked: proves the LIVE wording and the post-BRANE counting."""
    headers = {"X-Brane-Routed-To": "cloud", "X-Brane-Action": "placeholder", "X-Brane-Redacted": "true",
               "X-Brane-Pii-Types": "PERSON", "X-Brane-Placeholder-Types": "PERSON",
               "X-Brane-Model-Resolved": "openrouter:anthropic/claude-haiku-5.5"}

    def __init__(self):
        super().__init__("http://fake.invalid/api/v1", "test-key", "auto")

    def complete(self, system, user):
        return {"content": json.dumps(GOOD), "brane": {"headers": dict(self.headers)}}

    def _request(self, method, path, body=None):  # /policy/test dry run: the payload with names placeholdered
        return 200, json.dumps({"outgoingCloudPayloadPreview": "Reported by PERSON_REF_1. File went out."}), {}


class FakeLocal(FakeLive):
    headers = {"X-Brane-Routed-To": "local", "X-Brane-Action": "local", "X-Brane-Local-Cause": "semantic_category_local",
               "X-Brane-Semantic-Matches": "INDIRECT_HEALTH_CONTEXT", "X-Brane-Model-Resolved": "vllm:deepseek-v4.1-flash"}


class FakeRefuse(FakeLive):
    def complete(self, system, user):
        raise brane_client.BraneRefused("Refused (category:DATE_OF_BIRTH->refuse).",
                                        {"X-Brane-Routed-To": "refused",
                                         "X-Brane-Refused-By": "category:DATE_OF_BIRTH->refuse"})


# ---- structure, sidebar, intro ----------------------------------------------------------------
def test_app_imports_without_errors():
    app = importlib.import_module("app")
    assert callable(app.main) and len(app.SCENARIOS) == 3 and list(app.STEPS) == STEPS


def test_every_step_renders_for_every_scenario():
    at = start()
    for scenario in ["payroll_misdirected", "hospital_ransomware", "bank_ict_incident"]:
        at.sidebar.radio[0].set_value(scenario).run()
        for step in STEPS:
            goto(at, step)
            assert "Why this step?" in all_text(at)


def test_sidebar_is_simple():
    at = start()
    assert [o for o in at.sidebar.radio[0].options] == ["Payroll file sent to the wrong company",
                                                        "Hospital hit by ransomware", "Bank app exposed customer data"]
    assert [e.label for e in at.sidebar.expander] == ["Presenter settings"]
    labels = [t.label for t in at.sidebar.toggle]
    assert labels == ["Local pre-masking", "Simulate BRANE down", "Demo clock", "Light mode"]
    presenter = at.sidebar.expander[0]
    assert "Light mode" not in [t.label for t in presenter.toggle]       # easy to find on stage
    assert next(t for t in at.sidebar.toggle if t.label == "Demo clock").value is True
    assert any("without leaking the data again" in h.proto.body for h in at.sidebar.get("html"))


def test_intro_tells_the_story_in_plain_words():
    at = start("hospital_ransomware")
    text = all_text(at)
    assert "Hospital hit by ransomware" in text
    assert "Fictional scenario: all people, companies and data are invented." in text
    assert "300 patients" in text and "Simulated clock" in text and "290937759" not in text


@pytest.mark.parametrize("scenario, lines", [
    ("payroll_misdirected", ["Autoriteit Persoonsgegevens</b> (Dutch data protection authority)"]),
    ("hospital_ransomware", ["Z-CERT</b> (healthcare cyber team)",
                             "Autoriteit Persoonsgegevens</b> (Dutch data protection authority)"]),
    ("bank_ict_incident", ["De Nederlandsche Bank</b> (financial supervisor)",
                           "Autoriteit Persoonsgegevens</b> (Dutch data protection authority)"]),
])
def test_deadline_lines_per_authority_nearest_first(scenario, lines):
    block = next(v for v in html_blocks(start(scenario)) if 'class="bb-deadlines"' in v)
    positions = [block.index(x) for x in lines]
    assert positions == sorted(positions)                                 # nearest deadline first
    assert "hours left" in block and "Why: personal data leaked (GDPR Art. 33)." in block
    assert "The law gives this organisation" not in block


def test_scenario_change_resets_to_step_1():
    at = start(step="drafts")
    at.sidebar.radio[0].set_value("bank_ict_incident").run()
    assert at.session_state["step"] == "protect"


def test_next_and_back_buttons_move_between_steps():
    at = start()
    next(b for b in at.button if b.label.startswith("Next: 2. Draft the reports")).click().run()
    assert at.session_state["step"] == "drafts"
    next(b for b in at.button if b.label.startswith("Back: 1. Protect the data")).click().run()
    assert at.session_state["step"] == "protect"


def test_demo_clock_moves_deadlines_not_the_facts():
    at = start("payroll_misdirected", step="evidence")
    sent = next(c.value for c in at.code if "Awareness time" in c.value)
    assert "Awareness time: 2026-11-19T09:40" in sent          # the AI sees the report's real time


# ---- step 1: protect the data -----------------------------------------------------------------
def test_mock_card_safe_to_send_with_zero_counts():
    at = start("payroll_misdirected")
    assert "Safe to send." in card(at) and "0 names, 0 bank details, 0 health details" in card(at)
    assert "Offline demo mode" in all_text(at)
    assert "never left this computer" in all_text(at)


def test_live_cloud_card_has_no_mock_wording(monkeypatch):
    monkeypatch.setattr(brane_client, "get_client", lambda: FakeLive())
    at = start("payroll_misdirected")
    assert "Safe to send." in card(at)
    assert "mock" not in all_text(at).lower()


def test_live_local_card(monkeypatch):
    monkeypatch.setattr(brane_client, "get_client", lambda: FakeLocal())
    c = card(start("payroll_misdirected"))
    assert "Too sensitive for an outside AI." in c and "nothing left the secure environment" in c


def test_refused_card_and_template_drafts(monkeypatch):
    monkeypatch.setattr(brane_client, "get_client", lambda: FakeRefuse())
    at = start("hospital_ransomware")
    c = card(at)
    assert "Blocked." in c and "because it contained a date of birth" in c and "A person must decide" in c
    goto(at, "drafts")
    assert "fill-in templates" in all_text(at) and len(at.text_area) == 3


def test_nothing_sent_card():
    at = start("hospital_ransomware", down=True)
    assert "The firewall was unreachable, so nothing was sent. Safety first: no backup route." in card(at)
    assert "Nothing. No AI received anything." in all_text(at)


def test_card_not_safe_when_names_sent_as_typed():
    """Layer 1 off + a gateway that sends names as typed: the card must not say 'Safe to send'."""
    c = card(start("payroll_misdirected", premask=False))
    assert "Safe to send" not in c and "not fully protected" in c


def test_original_panel_hides_health_details():
    at = start("payroll_misdirected")
    panel = next(v for v in html_blocks(at) if 'class="bb-panel"' in v and "<s>" in v)
    assert "health detail kept private" in panel and "burn-out" not in panel
    assert "<s>Marloes Kuipers</s>" in panel                       # protected parts struck through


def test_received_panel_uses_readable_chips():
    at = start("hospital_ransomware")
    received = next(v for v in html_blocks(at) if 'class="bb-panel mono"' in v)   # payloads in monospace
    for chip in ("a name", "an email address", "phone number removed", "hidden instruction removed"):
        assert chip in received
    assert "PERSON_001" not in received and "Sven Hoekstra" not in received


# ---- step 2: draft the reports -----------------------------------------------------------------
def test_drafts_step_table_and_tabs():
    at = start("bank_ict_incident", step="drafts")
    table = at.table[0].value
    assert list(table.columns) == ["By when", "Why"]
    assert set(table.index) == {"Autoriteit Persoonsgegevens (NL)", "De Nederlandsche Bank (DNB)", "The people affected"}
    assert len(at.text_area) == 3


def test_drafts_kept_across_steps():
    at = start("bank_ict_incident", step="drafts")
    at.text_area[0].set_value("EDITED authority draft").run()
    goto(at, "decide")
    goto(at, "drafts")
    assert at.text_area[0].value == "EDITED authority draft"


def test_facts_list_drops_what_the_app_knows():
    at = start("payroll_misdirected", step="drafts")
    labels = [c.label for c in at.checkbox]
    assert 1 <= len(labels) <= 5
    assert not any("become aware" in x or "How many people" in x for x in labels)


# ---- step 3: you decide ------------------------------------------------------------------------
def _decide(at, tier=None, uncheck=()):
    rid = next(t.key for t in at.text_input if t.key.startswith("rev_name_")).removeprefix("rev_name_")
    at.text_input(key=f"rev_name_{rid}").set_value("J. Jansen")
    at.text_input(key=f"rev_role_{rid}").set_value("DPO")
    if tier:
        next(r for r in at.radio if r.label == "How serious is it?").set_value(tier).run()
    for label in uncheck:
        next(c for c in at.checkbox if c.label.startswith(label)).uncheck()
    next(b for b in at.button if b.label == "Approve").click().run()


def test_three_plain_risk_levels_and_recipients():
    at = start("hospital_ransomware", step="decide")
    tiers = next(r for r in at.radio if r.label == "How serious is it?").options
    assert tiers == ["Low: unlikely to harm anyone. Record it; no report needed.",
                     "Medium: could harm people. Report it to the authorities.",
                     "High: likely to harm people. Report it and tell the people affected."]
    labels = [c.label for c in at.checkbox]
    assert labels == ["Autoriteit Persoonsgegevens", "Z-CERT", "The people affected"]


def test_high_preticks_affected_people_and_next_is_secondary():
    at = start("payroll_misdirected", step="decide")
    assert next(b for b in at.button if b.label.startswith("Next:")).proto.type == "secondary"
    next(r for r in at.radio if r.label == "How serious is it?").set_value("high").run()
    assert next(c for c in at.checkbox if c.label == "The people affected").value is True


def test_reason_rule_and_seal():
    at = start("payroll_misdirected", step="decide")
    _decide(at, tier="high", uncheck=["The people affected"])
    assert any("Art. 34" in e.value for e in at.error)
    next(c for c in at.checkbox if c.label == "The people affected").check()
    next(b for b in at.button if b.label == "Approve").click().run()
    seal = next(v for v in html_blocks(at) if 'class="bb-seal"' in v)
    assert "Approved by J. Jansen (DPO)" in seal and "(Amsterdam)" in seal and "Nothing was sent by this app." in seal
    assert next(b for b in at.button if b.label.startswith("Next:")).proto.type == "primary"
    labels = [b.proto.label for b in at.get("download_button")]
    assert "Download reports (.docx)" in labels


def test_open_placeholder_blocks_approval():
    at = start("payroll_misdirected", step="drafts")
    at.text_area[0].set_value("Contact our DPO at [DPO email].").run()
    goto(at, "decide")
    _decide(at, tier="risk")
    assert any("[DPO email]" in e.value for e in at.error)


def test_export_before_approval_is_a_draft():
    at = start("payroll_misdirected", step="decide")
    labels = [b.proto.label for b in at.get("download_button")]
    assert labels == ["Download draft reports (.docx)", "Download record (.xlsx)"]
    assert "marked DRAFT until you approve" in all_text(at)


def test_word_export_after_approval_has_only_the_approved_recipients():
    from docx import Document
    from breachbrief import agent, exporter
    from breachbrief.brane_client import MockBrane
    r = agent.run("bank_ict_incident", client=MockBrane())
    meta = agent.load_scenario("bank_ict_incident")[0]
    dec = exporter.Decision("Test DPO", "risk", ["authority", "financial_supervisor"], "", "2026-11-20T18:00:00+00:00",
                            "DPO")
    doc = Document(io.BytesIO(exporter.build_docx(r, meta, r.model_output, dec, "MOCK")))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "APPROVED by Test DPO (DPO)" in text and "DORA initial notification" in text
    assert "Notice to affected people" not in text and "(Amsterdam)" in text


def test_excel_workbook_has_audit_sheets_and_no_drafts():
    from openpyxl import load_workbook
    from breachbrief import agent, exporter
    from breachbrief.brane_client import MockBrane
    r = agent.run("payroll_misdirected", client=MockBrane())
    meta = agent.load_scenario("payroll_misdirected")[0]
    wb = load_workbook(io.BytesIO(exporter.build_xlsx(r, meta, None, "MOCK")))
    assert wb.sheetnames == ["Summary", "Deadlines", "Protection decisions", "BRANE verdict", "Payload sent",
                             "Facts to confirm", "Human approval"]
    cells = " ".join(str(c.value) for ws in wb for row in ws.iter_rows() for c in row if c.value)
    assert "MOCK DRAFT" not in cells and "burn-out" not in cells and "Marloes Kuipers" not in cells


# ---- evidence (experts) ------------------------------------------------------------------------
def test_evidence_tab_holds_the_expert_detail(monkeypatch):
    monkeypatch.setattr(brane_client, "get_client", lambda: FakeLive())
    at = start("payroll_misdirected", step="evidence")
    frames = [t.value for t in at.table]
    assert any("Decision" in f.columns for f in frames)
    assert any(f.index.name == "X-Brane header" and "X-Brane-Routed-To" in set(f.index) for f in frames)
    assert not at.dataframe                                              # HTML tables follow the theme
    reviewer = next(e for e in at.expander if "Reviewer only" in e.label)
    assert any("burn-out" in m.value for m in reviewer.markdown)


def test_jargon_stays_out_of_the_main_steps():
    at = start("hospital_ransomware")
    for step in ("protect", "drafts", "decide"):
        goto(at, step)
        visible = "\n".join(m.value for m in at.markdown) + "\n".join(t.value for t in at.title)
        for word in ("X-Brane", "LOCAL_ONLY", "guard_only", "payload", "PERSON_001"):
            assert word not in visible, (step, word)


def test_protocol_view_shows_latest_test_protocol(monkeypatch, tmp_path):
    import app
    md, js = tmp_path / "TEST_PROTOCOL.md", tmp_path / "TEST_PROTOCOL.json"
    md.write_text("# BreachBrief test protocol\n\n| [R1](#r1) | Permitted control case |\n", encoding="utf-8")
    js.write_text(json.dumps({"passed": 10, "total": 10, "brane_mode": "MOCK", "generated": "2026-11-20T16:00:00+00:00",
                              "code_version": "abc1234"}), encoding="utf-8")
    monkeypatch.setattr(app, "TEST_PROTOCOL_MD", md)
    monkeypatch.setattr(app, "TEST_PROTOCOL_JSON", js)
    at = AppTest.from_function(_protocol_view_only)
    at.run()
    assert not at.exception
    text = all_text(at)
    assert "10/10 PASS" in text and "(Amsterdam)" in text


def _protocol_view_only():
    import app
    app.test_protocol_view()


def test_prewarm_runs_all_six_and_clears_the_status(monkeypatch):
    monkeypatch.setenv("BREACHBRIEF_PREWARM", "1")
    at = start()
    assert not [e for e in at.main if type(e).__name__ == "Status"]      # gone once ready
    first = card(at)
    toggle(at, "Local pre-masking").set_value(False).run()               # served from the cache
    assert card(at) != first


def test_no_em_dashes_in_ui_text():
    assert "—" not in Path(APP).read_text(encoding="utf-8")


# ---- regression: every step, every scenario, every presenter setting, both themes ---------------
@pytest.mark.parametrize("light", [False, True], ids=["dark", "light"])
def test_every_combination_renders(light):
    """3 scenarios x local protection on/off x BRANE up/down x 4 steps. Guards against crashes like
    "'Verdict' object has no attribute 'by_kind'"."""
    at = start()
    toggle(at, "Light mode").set_value(light).run()
    for scenario in ["payroll_misdirected", "hospital_ransomware", "bank_ict_incident"]:
        at.sidebar.radio[0].set_value(scenario).run()
        for premask in (True, False):
            toggle(at, "Local pre-masking").set_value(premask).run()
            for down in (False, True):
                toggle(at, "Simulate BRANE down").set_value(down).run()
                for step in STEPS:
                    goto(at, step)                               # asserts no exception
    assert at.session_state["light_mode"] is light               # kept across scenario switches


@pytest.mark.parametrize("light", [False, True], ids=["dark", "light"])
def test_theme_variables_switch_together(light):
    import app
    at = start()
    toggle(at, "Light mode").set_value(light).run()
    css = next(h.proto.body for h in at.get("html") if "--bb-bg" in h.proto.body)
    pal = app.PALETTES["light" if light else "dark"]
    for name in ("bg", "side", "card", "border", "text", "muted", "accent", "green", "orange", "red", "blue"):
        assert f"--bb-{name}: {pal[name]};" in css
    # our components only use the variables, never a hard-coded palette colour
    rules = app.APP_CSS
    for colour in set(app.PALETTES["dark"].values()) | set(app.PALETTES["light"].values()):
        if colour.startswith("#"):
            assert colour not in rules, colour


def test_dark_is_the_default_and_light_is_kept_across_scenarios():
    at = start()
    assert toggle(at, "Light mode").value is False
    toggle(at, "Light mode").set_value(True).run()
    at.sidebar.radio[0].set_value("bank_ict_incident").run()
    assert toggle(at, "Light mode").value is True


def test_card_survives_a_verdict_from_older_code():
    """A cached Verdict without by_kind (built before that field existed) must not crash the card."""
    import app
    from breachbrief import agent, verdict
    from breachbrief.brane_client import MockBrane
    r = agent.run("payroll_misdirected", client=MockBrane())
    v = verdict.compute(r, gateway="MOCK")
    old = type("OldVerdict", (), {k: getattr(v, k) for k in vars(v) if k != "by_kind"})()
    assert app.counts_of(old, r.scenario) == {}
    assert app.counts_of(v, r.scenario) == v.by_kind


def test_cache_is_tied_to_the_code_version(monkeypatch):
    import app
    assert app.run_store("v1") is not app.run_store("v2")
    assert app.code_version().isdigit()


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_palette_meets_wcag_aa(mode):
    import app

    def lum(h):
        c = [int(h.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]

    def ratio(a, b):
        hi, lo = sorted([lum(a), lum(b)], reverse=True)
        return (hi + 0.05) / (lo + 0.05)
    p = app.PALETTES[mode]
    for fg, bg in [("text", "bg"), ("text", "card"), ("muted", "bg"), ("muted", "card"), ("muted", "raised"),
                   ("text", "side"), ("on-accent", "accent"), ("link", "bg"), ("green", "green-bg"),
                   ("orange", "orange-bg"), ("red", "red-bg"), ("blue", "blue-bg")]:
        assert ratio(p[fg], p[bg]) >= 4.5, (mode, fg, bg, round(ratio(p[fg], p[bg]), 2))
