"""BreachBrief demo UI.  Run: streamlit run app.py

For first-time viewers: a short intro, then three steps (protect the data, draft the reports, you decide)
plus an Evidence tab for experts. Dark "cybersecurity" theme by default, light mode via a sidebar switch.
The app never sends a notification. The security pipeline lives in breachbrief/ and is unchanged by this UI.
"""
from __future__ import annotations

import dataclasses
import html
import json
import logging
import os
import re
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from breachbrief import agent, detectors as d, drafts, exporter, policy, protocol, regimes, verdict
from breachbrief.approval import RISK_TIERS, ApprovalError, amsterdam, approve
from breachbrief.brane_client import BraneUnavailable, LiveBrane, MockBrane, get_client

load_dotenv()

SCENARIOS = ["payroll_misdirected", "hospital_ransomware", "bank_ict_incident"]
FRIENDLY = {"payroll_misdirected": "Payroll file sent to the wrong company",
            "hospital_ransomware": "Hospital hit by ransomware",
            "bank_ict_incident": "Bank app exposed customer data"}
TZ = ZoneInfo("Europe/Amsterdam")  # scenario timestamps are Dutch local time
TEAM_BUILD_DEFAULT = "Team-13 / policy-v1"
PIPELINE_DIR = Path(__file__).resolve().parent / "breachbrief"

# Demo clock: T+0 = awareness. "Now" sits this long after awareness (bank: 30 min after classification).
DEMO_OFFSET = {"payroll_misdirected": timedelta(hours=2), "hospital_ransomware": timedelta(hours=1)}
DEMO_AFTER_CLASSIFICATION = {"bank_ict_incident": timedelta(minutes=30)}

STEPS = {"protect": "1. Protect the data", "drafts": "2. Draft the reports", "decide": "3. You decide",
         "evidence": "Evidence"}
STEP_IDS = list(STEPS)
STEP_ERROR = "Something went wrong in this step. Nothing was sent. Click Re-run live."
log = logging.getLogger("breachbrief.app")
WHY = {
    "protect": "An AI can help write the reports, but it must never see more personal data than it needs.",
    "drafts": "The law says who must be told and by when. The AI wrote first drafts; you check them.",
    "decide": "Only a person can decide how serious this is and who is told. The app never sends anything.",
    "evidence": "For experts: every decision, the firewall's raw response, the audit log and the security tests.",
}
# Who must be told, in plain words, per law (deadline lines in the intro, table in step 2)
AUTHORITY = {
    "GDPR": ("Dutch data protection authority", "personal data leaked (GDPR Art. 33)"),
    "NIS2": ("healthcare cyber team", "hospitals must report serious cyber incidents (NIS2)"),
    "DORA": ("financial supervisor", "banks must report major IT incidents (DORA)"),
}
REGIME_RECIPIENT = {"GDPR": "authority", "NIS2": "csirt", "DORA": "financial_supervisor"}

MARKER_CHIP = {
    d.IBAN: "bank account removed", d.NATIONAL_ID: "ID number removed", d.MONEY_VALUE: "amount removed",
    d.DATE_OF_BIRTH: "date of birth removed", d.PHONE: "phone number removed",
    d.HEALTH: "health detail kept private", d.INJECTION: "hidden instruction removed",
    d.ENCODED: "unreadable attachment removed",
}
_MARKER_TO_CAT = {}
for _cat, _rule in policy.RULES.items():
    if _rule[1].startswith("["):
        _MARKER_TO_CAT[_rule[1]] = _cat
        _MARKER_TO_CAT[agent.render_markers(_rule[1], "plain")] = _cat
_TOKEN_RE = re.compile(r"\b(PERSON|EMAIL|PHONE|RECIPIENT|[A-Z]+)_(?:REF_)?(\d{1,3}|[A-Z])\b|(\[[A-Z_]+\])|(\([a-z9 .:-]+\))")
TOKEN_CHIP = {"PERSON": "a name", "EMAIL": "an email address", "PHONE": "a phone number", "RECIPIENT": "the other company",
              "ADDRESS": "an address", "ORG": "a company name"}
WHY_IT_MATTERS = "Sending leaked data to an AI would be a second data leak."

# ---- theme: one set of CSS variables, two palettes -------------------------------------------
# Dark is the default (also in .streamlit/config.toml, so native widgets start dark). Every surface below
# reads these variables, so the "Light mode" switch changes cards, banners, chips, tables and panels together.
PALETTES = {
    "dark": {"bg": "#0B1220", "side": "#0F172A", "card": "#111A2E", "raised": "#16213A", "border": "#23314F",
             "text": "#E6EDF7", "muted": "#94A3B8", "accent": "#3B82F6", "accent-h": "#2563EB", "link": "#60A5FA",
             "on-accent": "#0B1220", "glow": "rgba(59,130,246,.45)",   # dark ink on #3B82F6: 5:1 (white is 3.7:1)
             "green": "#22C55E", "green-bg": "#0F2A1C", "orange": "#F59E0B", "orange-bg": "#2A1F0B",
             "red": "#EF4444", "red-bg": "#2A1215", "blue": "#38BDF8", "blue-bg": "#0B2533",
             "header": "linear-gradient(180deg, #13203A 0%, #0B1220 100%)"},
    "light": {"bg": "#F4F6FA", "side": "#E8ECF2", "card": "#FFFFFF", "raised": "#EEF1F6", "border": "#D6DCE5",
              "text": "#0F1B2D", "muted": "#4A5870", "accent": "#1D4ED8", "accent-h": "#1E40AF", "link": "#1D4ED8",
              "on-accent": "#FFFFFF", "glow": "rgba(29,78,216,.30)",
              "green": "#166534", "green-bg": "#E8F5EC", "orange": "#C2410C", "orange-bg": "#FDEEE4",  # green: #15803D was 4.47:1, just under AA
              "red": "#B91C1C", "red-bg": "#FCE9E9", "blue": "#0369A1", "blue-bg": "#E0F2FE",
              "header": "linear-gradient(180deg, #FFFFFF 0%, #F4F6FA 100%)"},
}

APP_CSS = """
<style>
/* surfaces */
.stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] { background: var(--bb-bg) !important; color: var(--bb-text); }
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stSidebar"], [data-testid="stSidebar"] > div { background: var(--bb-side) !important; }
[data-testid="stSidebar"] { border-right: 1px solid var(--bb-border); }
.stApp, .stApp p, .stApp li, .stApp label, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp summary,
[data-testid="stMarkdownContainer"], [data-testid="stWidgetLabel"] { color: var(--bb-text); }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p { color: var(--bb-muted) !important; }
.stApp a { color: var(--bb-link); }
/* inputs */
.stApp input, .stApp textarea, [data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="base-input"] {
  background: var(--bb-raised) !important; color: var(--bb-text) !important; border-color: var(--bb-border) !important; }
.stApp input::placeholder, .stApp textarea::placeholder { color: var(--bb-muted) !important; opacity: 1; }
/* buttons: accent, darker on hover, subtle glow on focus */
.stApp button[kind^="primary"], .stApp [data-testid^="stBaseButton-primary"] {
  background: var(--bb-accent) !important; border-color: var(--bb-accent) !important; color: var(--bb-on-accent) !important; }
.stApp button[kind^="primary"]:hover, .stApp [data-testid^="stBaseButton-primary"]:hover { background: var(--bb-accent-h) !important; }
.stApp button[kind^="secondary"], .stApp [data-testid^="stBaseButton-secondary"] {
  background: var(--bb-raised) !important; border-color: var(--bb-border) !important; color: var(--bb-text) !important; }
.stApp button:focus-visible, .stApp input:focus, .stApp textarea:focus { box-shadow: 0 0 0 3px var(--bb-glow) !important; outline: none; }
/* step selector (segmented control, key "step") */
.st-key-step button[role=radio] { background: var(--bb-raised) !important; color: var(--bb-text) !important; border-color: var(--bb-border) !important; }
.st-key-step button[role=radio] * { color: inherit !important; }
.st-key-step button[aria-checked=true] { background: var(--bb-accent) !important; color: var(--bb-on-accent) !important; border-color: var(--bb-accent) !important;
  box-shadow: 0 0 0 3px var(--bb-glow) !important; }
/* tabs, expanders, tables, code, alerts, json */
.stApp [data-baseweb="tab"] { color: var(--bb-muted) !important; background: transparent !important; }
.stApp [data-baseweb="tab"][aria-selected="true"] { color: var(--bb-link) !important; }
.stApp [data-baseweb="tab-border"] { background: var(--bb-border) !important; }
.stApp [data-baseweb="tab-highlight"] { background: var(--bb-accent) !important; }
[data-testid="stExpander"] details { background: var(--bb-card) !important; border-color: var(--bb-border) !important; }
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * { color: var(--bb-text) !important; }
[data-testid="stTable"] table { background: var(--bb-card) !important; color: var(--bb-text) !important; border-color: var(--bb-border) !important; }
[data-testid="stTable"] th { background: var(--bb-raised) !important; color: var(--bb-muted) !important; border-color: var(--bb-border) !important; }
[data-testid="stTable"] td { color: var(--bb-text) !important; border-color: var(--bb-border) !important; background: var(--bb-card) !important; }
[data-testid="stCode"] pre, [data-testid="stCode"] code { background: var(--bb-raised) !important; color: var(--bb-text) !important;
  font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace !important; }
[data-testid="stAlertContainer"] { background: var(--bb-raised) !important; color: var(--bb-text) !important; border: 1px solid var(--bb-border); }
[data-testid="stAlertContainer"] * { color: var(--bb-text) !important; }
[data-testid="stJson"] { background: var(--bb-card) !important; border-radius: 10px; }
.stApp [data-testid="stCheckbox"] label, .stApp [data-testid="stRadio"] label { color: var(--bb-text) !important; }
/* unselected radios, checkboxes and switches: follow the theme instead of the built-in dark styling */
.stApp label[data-testid="stRadioOption"]:not([data-selected="true"]) > div > div:first-child {
  background: var(--bb-raised) !important; border: 2px solid var(--bb-muted) !important; }
.stApp [data-testid="stCheckbox"] label:not([data-selected="true"]) > div:first-of-type {
  background: var(--bb-raised) !important; border: 2px solid var(--bb-muted) !important; }
.stApp [data-testid="stCheckbox"] label:has(input[role="switch"]):not([data-selected="true"]) > div:first-of-type > div {
  background: var(--bb-muted) !important; }
/* tooltip "?" icons are outline icons: colour the stroke only */
.stApp [data-testid="stTooltipIcon"] button, .stApp [data-testid="stTooltipIcon"] svg { color: var(--bb-muted) !important; opacity: 1 !important; }
.stApp [data-testid="stTooltipIcon"] svg, .stApp [data-testid="stTooltipIcon"] svg * { stroke: var(--bb-muted) !important; }
/* primary buttons: every piece of their label uses the on-accent colour */
.stApp button[kind^="primary"] *, .stApp [data-testid^="stBaseButton-primary"] * { color: var(--bb-on-accent) !important; }

/* our own components */
.st-key-hero { background: var(--bb-header); border: 1px solid var(--bb-border); border-radius: 14px; padding: 18px 22px; }
.bb-brand { display:flex; gap:12px; align-items:center; margin:2px 0 4px; }
.bb-logo { width:40px; height:40px; border-radius:10px; display:grid; place-items:center; font-size:21px; background:var(--bb-accent); flex:0 0 auto; }
.bb-brand b { font-size:1.15rem; color:var(--bb-text); } .bb-brand small { display:block; color:var(--bb-muted); font-size:.86rem; line-height:1.35; }
.bb-tag { display:inline-block; border-radius:999px; padding:3px 12px; font-size:.86rem; font-weight:600;
  background:var(--bb-raised); color:var(--bb-muted); border:1px solid var(--bb-border); }
.bb-tag.green { background:var(--bb-green-bg); color:var(--bb-green); border-color:var(--bb-green); }
.bb-tag.blue { background:var(--bb-blue-bg); color:var(--bb-blue); border-color:var(--bb-blue); }
.bb-tag.red { background:var(--bb-red-bg); color:var(--bb-red); border-color:var(--bb-red); }
.bb-deadlines { margin:8px 0 2px; display:flex; flex-direction:column; gap:6px; }
.bb-deadline { font-size:1.02rem; line-height:1.5; color:var(--bb-text); }
.bb-deadline b { color:var(--bb-text); } .bb-deadline .why { color:var(--bb-muted); }
.bb-hours { font-family:'JetBrains Mono', ui-monospace, monospace; font-weight:700; border-radius:6px; padding:1px 8px;
  background:var(--bb-raised); color:var(--bb-text); border:1px solid var(--bb-border); }
.bb-hours.soon { background:var(--bb-orange-bg); color:var(--bb-orange); border-color:var(--bb-orange); }
.bb-hours.over { background:var(--bb-red-bg); color:var(--bb-red); border-color:var(--bb-red); }
.st-key-verdict_green, .st-key-verdict_blue, .st-key-verdict_orange, .st-key-verdict_red { border-width:1px !important; border-left-width:6px !important; }
.st-key-verdict_green { background:var(--bb-green-bg); border-color:var(--bb-green) !important; }
.st-key-verdict_blue { background:var(--bb-blue-bg); border-color:var(--bb-blue) !important; }
.st-key-verdict_orange { background:var(--bb-orange-bg); border-color:var(--bb-orange) !important; }
.st-key-verdict_red { background:var(--bb-red-bg); border-color:var(--bb-red) !important; }
.st-key-verdict_green h3 { color:var(--bb-green) !important; } .st-key-verdict_blue h3 { color:var(--bb-blue) !important; }
.st-key-verdict_orange h3 { color:var(--bb-orange) !important; } .st-key-verdict_red h3 { color:var(--bb-red) !important; }
[class*="st-key-step_error_"] { background:var(--bb-orange-bg); border:1px solid var(--bb-orange) !important; border-left-width:6px !important; }
.bb-panel { border:1px solid var(--bb-border); border-radius:10px; padding:16px 18px; white-space:pre-wrap; line-height:1.75;
  background:var(--bb-card); max-height:420px; overflow:auto; overflow-wrap:anywhere; color:var(--bb-text); }
.bb-panel.mono { font-family:'JetBrains Mono', ui-monospace, Consolas, monospace; font-size:.92em; }
.bb-panel s { color:var(--bb-muted); text-decoration-thickness:2px; }
.bb-chip { display:inline-block; border-radius:6px; padding:0 8px; margin:0 2px; font-size:.86em; font-weight:600;
  font-family:Inter, system-ui, sans-serif; background:var(--bb-blue-bg); color:var(--bb-blue); border:1px solid var(--bb-blue); white-space:nowrap; }
.bb-chip.private { background:var(--bb-green-bg); color:var(--bb-green); border-color:var(--bb-green); }
.bb-chip.removed { background:var(--bb-red-bg); color:var(--bb-red); border-color:var(--bb-red); }
.bb-nothing { border:2px dashed var(--bb-red); border-radius:10px; padding:40px 18px; text-align:center; color:var(--bb-red);
  background:var(--bb-red-bg); font-weight:700; }
.bb-seal { display:flex; gap:14px; align-items:center; border-radius:10px; padding:14px 18px; border:2px solid var(--bb-green);
  background:var(--bb-green-bg); }
.bb-seal .lock { font-size:24px; } .bb-seal b { color:var(--bb-text); } .bb-seal span { display:block; color:var(--bb-muted); font-size:.95rem; }
.st-key-card_word, .st-key-card_xlsx { background:var(--bb-card); }
</style>
"""


def theme_vars(mode: str) -> str:
    """The CSS variables for one palette. Injected before APP_CSS, so the switch repaints everything."""
    pal = PALETTES[mode]
    return "<style>:root {" + " ".join(f"--bb-{k}: {v};" for k, v in pal.items()) + \
        f" color-scheme: {mode};" + "}</style>"


# ---- clients, timing, cached runs -----------------------------------------------------------
class _UnconfiguredLive:
    """LIVE mode selected but BRANE not configured: behaves like an unavailable BRANE (fail closed)."""

    def __init__(self, error: str):
        self.error = error

    def complete(self, system, user):
        raise BraneUnavailable(self.error)


def gateway_mode() -> str:
    try:
        return "LIVE" if isinstance(get_client(), LiveBrane) else "MOCK"
    except BraneUnavailable:
        return "LIVE (not configured)"


def make_client(simulate_down: bool):
    """Returns (client, mode label)."""
    mode = gateway_mode()
    if simulate_down:
        return MockBrane(simulate_down=True), mode
    try:
        return get_client(), mode
    except BraneUnavailable as exc:
        return _UnconfiguredLive(str(exc)), mode


def demo_timing(scenario: str, meta: dict, anchor: datetime) -> dict:
    """Simulated clock: awareness (T+0) placed so that 'now' is a fixed time after it. Naive local times."""
    if scenario in DEMO_AFTER_CLASSIFICATION:
        classified = anchor - DEMO_AFTER_CLASSIFICATION[scenario]
        gap = datetime.fromisoformat(meta["classified_major_at"]) - datetime.fromisoformat(meta["aware_at"])
        return {"aware_at": (classified - gap).isoformat(timespec="minutes"),
                "classified_major_at": classified.isoformat(timespec="minutes")}
    return {"aware_at": (anchor - DEMO_OFFSET.get(scenario, timedelta(hours=1))).isoformat(timespec="minutes")}


@st.cache_resource
def clock_anchor() -> datetime:
    """'Now' for the simulated clock, fixed when the app starts so every cached run agrees with it."""
    return datetime.now(TZ).replace(tzinfo=None, second=0, microsecond=0)


def code_version() -> str:
    """Changes whenever the pipeline code changes. Cached runs are tied to it, so a long-running app never
    reuses objects built by older code (that is what caused "'Verdict' object has no attribute 'by_kind'")."""
    return str(max(int(p.stat().st_mtime) for p in PIPELINE_DIR.glob("*.py")))


@st.cache_resource
def run_store(version: str) -> dict:
    """Shared cache of finished runs for one code version: key -> (Result, Verdict, meta)."""
    return {}


def run_one(scenario: str, premask: str, down: bool):
    """One full run + its verdict, on the scenario's real facts. No Streamlit calls (safe in worker threads).
    The demo clock does not change what the AI sees; it only moves the displayed deadlines (with_clock)."""
    meta = agent.load_scenario(scenario)[0]
    client, mode = make_client(down)
    r = agent.run(scenario, client=client, premask=premask)
    v = verdict.compute(r, client=client if isinstance(client, LiveBrane) else None,
                        gateway="MOCK" if mode == "MOCK" else "LIVE")
    return r, v, meta


def with_clock(r, meta: dict, scenario: str, clock: bool):
    """The run as displayed: with the demo clock on, deadlines count from a discovery time shortly before now."""
    if not clock:
        return r, meta
    shifted = {**meta, **demo_timing(scenario, meta, clock_anchor())}
    regs = regimes.applicable(shifted, personal_data_involved=bool(records_of(r)))
    return dataclasses.replace(r, regimes=regs, earliest_deadline=regimes.earliest_deadline(regs)), shifted


def prewarm(mode: str):
    """Pre-run the 6 combinations (3 scenarios x local protection on/off) once, so switching is instant."""
    store = run_store(code_version())
    todo = [(s, p) for s in SCENARIOS for p in ("full", "guard_only") if (s, p, False, mode) not in store]
    if not todo:
        return
    d._get_nlp()  # load the NER model once, before the worker threads start
    slot = st.empty()
    with slot.status(f"Preparing {len(todo)} demo runs…", expanded=False):
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(run_one, s, p, False): (s, p) for s, p in todo}
            for fut, (s, p) in futures.items():
                store[(s, p, False, mode)] = fut.result()
    slot.empty()  # nothing left on screen once ready


# ---- small helpers -------------------------------------------------------------------------
def pretty_time(iso_local: str) -> str:
    return datetime.fromisoformat(iso_local).strftime("%a %d %b, %H:%M")


def hours_left(iso_local: str) -> float:
    return (datetime.fromisoformat(iso_local).replace(tzinfo=TZ) - datetime.now(TZ)).total_seconds() / 3600


def go_to(step: str):
    st.session_state["step"] = step if step in STEP_IDS else STEP_IDS[0]


def current_step() -> str:
    """The step to show. Missing, None or an old id (stale state after a rerun) falls back to step 1."""
    step = st.session_state.get("step")
    if step not in STEP_IDS:
        step = st.session_state["step"] = STEP_IDS[0]
    return step


def safe_render(name: str, r, fn, *args) -> bool:
    """Render one part of the page. An unexpected error shows a calm card instead of a traceback; the full
    traceback goes to the console and a frames-only note to the run's protocol entry. Nothing is sent."""
    try:
        fn(*args)
        return True
    except Exception as exc:  # noqa: BLE001 - last line of defence for the live demo
        if os.getenv("BREACHBRIEF_STRICT") == "1":   # tests: never hide a crash behind the card
            raise
        log.error("Rendering %s failed:\n%s", name, "".join(traceback.format_exception(exc)))
        try:
            protocol.record_ui_error(getattr(r, "run_id", "no-run"), name, exc)
        except Exception:  # noqa: BLE001 - logging must never break the page
            log.exception("Could not write the UI error to the protocol")
        with st.container(border=True, key=f"step_error_{name}"):
            st.markdown(f"**{STEP_ERROR}**")
        return False


def why(step: str):
    st.markdown(f":material/lightbulb: **Why this step?** {WHY[step]}")


def approval_of(r) -> dict | None:
    return st.session_state.setdefault("approvals", {}).get(r.run_id)


def base_drafts(r) -> dict:
    return r.model_output or r.fallback_drafts or {}


def current_drafts(r) -> dict:
    """Drafts as the reviewer has edited them (kept while other steps are shown)."""
    out = dict(base_drafts(r))
    for recipient in drafts.recipients_for(r.regimes):
        key = drafts.RECIPIENTS[recipient][0]
        out[key] = st.session_state.get(f"draft_{key}_{r.run_id}", out.get(key, ""))
    return out


def with_drafts(r, texts: dict):
    return dataclasses.replace(r, model_output=texts) if r.model_output is not None else \
        dataclasses.replace(r, fallback_drafts=texts)


def records_of(r) -> int:
    m = re.search(r"with (\d+) records", r.profile_summary)
    return int(m.group(1)) if m else 0


def tag(text: str, colour: str = "") -> str:
    return f'<span class="bb-tag {colour}">{html.escape(text)}</span>'


def table(df: pd.DataFrame):
    """HTML table (st.table): follows the CSS theme variables, unlike canvas-drawn dataframes."""
    st.table(df)


# ---- intro ----------------------------------------------------------------------------------
STORY = {
    "payroll_misdirected": ("An employee at {org} emailed the November payroll file to the wrong company by "
                            "mistake. The file holds the names, email addresses, bank account numbers and salaries "
                            "of {n} employees. A note in it also mentions one employee's health."),
    "hospital_ransomware": ("Criminals locked the computer systems of {org} and say they copied a patient list. "
                            "The list holds the names, citizen ID numbers, dates of birth and diagnoses of {n} "
                            "patients."),
    "bank_ict_incident": ("A settings mistake at {org} let a partner company see customer data it should not have "
                          "seen. Names, bank account numbers, addresses and account balances of {n} customers were "
                          "exposed."),
}


def deadline_lines(r, meta: dict) -> list[dict]:
    """One line per authority, nearest deadline first."""
    out = []
    for reg in r.regimes:
        dated = [dl for dl in reg["deadlines"] if dl["due"][:4].isdigit()]
        if not dated or reg["regime"] not in AUTHORITY:
            continue
        due = min(dl["due"] for dl in dated)
        what, why_ = AUTHORITY[reg["regime"]]
        name = drafts.authority_name(meta, REGIME_RECIPIENT[reg["regime"]]).split(" (")[0]
        out.append({"due": due, "name": name, "what": what, "why": why_, "hours": hours_left(due)})
    return sorted(out, key=lambda x: x["due"])


def intro(r, meta: dict, scenario: str, clock: bool):
    with st.container(key="hero"):
        st.title(FRIENDLY[scenario])
        st.html(tag("Fictional scenario: all people, companies and data are invented."))
        st.markdown(STORY[scenario].format(org=meta.get("organisation", "the organisation"), n=records_of(r)))
        lines = []
        for x in deadline_lines(r, meta):
            h = x["hours"]
            cls = "over" if h < 0 else "soon" if h < 24 else ""
            left = f"{int(h)} hours left" if h >= 0 else f"deadline passed {int(-h)} hours ago"
            lines.append(f'<div class="bb-deadline"><b>{html.escape(x["name"])}</b> ({html.escape(x["what"])}): '
                         f'<span class="bb-hours {cls}">{left}</span>. <span class="why">Why: '
                         f'{html.escape(x["why"])}.</span></div>')
        if lines:
            st.html('<div class="bb-deadlines">' + "".join(lines) + "</div>")
            st.caption(f"Simulated clock: the breach was discovered {_ago(meta)} ago." if clock
                       else "Real dates from the scenario.")


def _ago(meta: dict) -> str:
    mins = int((datetime.now(TZ).replace(tzinfo=None) - datetime.fromisoformat(meta["aware_at"])).total_seconds() // 60)
    return f"{mins // 60} hour{'s' if mins // 60 != 1 else ''}" if mins >= 60 else f"{max(mins, 0)} minutes"


# ---- step 1: protect the data ---------------------------------------------------------------
def counts_of(v: verdict.Verdict, scenario: str) -> dict:
    """Identifiers per kind in what the model received. Falls back to recounting the received text if the
    Verdict was built by older code (no by_kind field), instead of crashing."""
    by_kind = getattr(v, "by_kind", None)
    if by_kind is not None:
        return by_kind
    return verdict.count_in(v.model_text, scenario)[0] if v.model_text else {}


def verdict_card(r, v: verdict.Verdict):
    """'What the security firewall did', one plain sentence per state."""
    by_kind = counts_of(v, r.scenario)
    names, bank = by_kind.get(d.PERSON_NAME, 0), by_kind.get(d.IBAN, 0)
    other = v.identifiers_reached - names - bank
    estimate = " (estimate)" if v.basis.startswith("estimated") else ""
    if v.state == "CLOUD" and v.identifiers_reached == 0 and v.health_reached == 0:
        colour, title = "green", "Safe to send."
        text = ("The AI got the facts with names replaced by codes. It received 0 names, 0 bank details, "
                f"0 health details{estimate}.")
    elif v.state == "CLOUD":
        colour, title = "orange", "Sent, but not fully protected."
        text = (f"The AI received {names} name{'s' if names != 1 else ''}, {bank} bank detail"
                f"{'s' if bank != 1 else ''} and {v.health_reached} health detail{'s' if v.health_reached != 1 else ''}"
                f"{f', plus {other} other personal details' if other else ''}{estimate}. This happens when our app's "
                "own protection is switched off.")
    elif v.state == "LOCAL":
        colour, title = "blue", "Too sensitive for an outside AI."
        text = "It was handled by a private AI inside the firewall; nothing left the secure environment."
    elif v.state == "REFUSED":
        colour, title = "orange", "Blocked."
        text = (f"The firewall stopped the request because it contained {verdict.refusal_reason(r.brane_headers)}. "
                "A person must decide what to do.")
    elif r.status == "blocked_leak":
        colour, title = "red", "Nothing was sent."
        text = "Our app's final check found something that must not leave, so it stopped the request."
    else:
        colour, title = "red", "Nothing was sent."
        text = "The firewall was unreachable, so nothing was sent. Safety first: no backup route."
    with st.container(border=True, key=f"verdict_{colour}"):
        st.markdown("**What the security firewall did**", help=f"Why does this matter? {WHY_IT_MATTERS}")
        st.subheader(title, anchor=False)   # no #safe-to-send style URL anchors
        st.markdown(text)
        if v.gateway == "MOCK" and v.state in ("CLOUD", "LOCAL"):
            st.caption("Offline demo mode: a stand-in plays the firewall and the AI.")


def _chip(label: str, kind: str = "") -> str:
    return f'<span class="bb-chip {kind}">{html.escape(label)}</span>'


def _title(text: str) -> str:
    """'# Incident report: ...' in the raw report becomes a bold title, not a stray '#'."""
    return re.sub(r"^#\s+(.+)$", r"<b>\1</b>", text.lstrip("\n"), count=1, flags=re.M)


def original_html(r) -> str:
    """The report as it came in: protected parts struck through. Health details are not shown at all."""
    out, cursor, rep = [], 0, r.report
    for s in sorted(r.spans, key=lambda x: x["start"]):
        out.append(html.escape(rep[cursor:s["start"]]))
        if s["decision"] == policy.LOCAL_ONLY:
            out.append(_chip("health detail kept private", "private"))
        else:
            out.append(f"<s>{html.escape(rep[s['start']:s['end']])}</s>")
        cursor = s["end"]
    out.append(html.escape(rep[cursor:]))
    return _title("".join(out))


def received_html(text: str) -> str:
    """What the AI received, with every code and removal marker shown as a readable chip."""
    body = text.split("<incident_report>")[-1].split("</incident_report>")[0].strip("\n")

    def repl(m: re.Match) -> str:
        if m.group(3) or m.group(4):
            cat = _MARKER_TO_CAT.get(m.group(0))
            if cat is None:
                return m.group(0)
            return _chip(MARKER_CHIP[cat], "private" if cat == d.HEALTH else "removed")
        label = TOKEN_CHIP.get(m.group(1))
        return _chip(label) if label else m.group(0)
    return _title(_TOKEN_RE.sub(repl, html.escape(body)))


def step_protect(r, v: verdict.Verdict):
    why("protect")
    verdict_card(r, v)
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        st.markdown(":material/filter_alt: **Layer 1.** Our app removes what the AI doesn't need.",
                    help="Names become codes, bank accounts and ID numbers are removed, health details stay on this "
                         "computer, and hidden instructions in the text are removed. The key to the codes never "
                         "leaves this computer.")
    with c2:
        st.markdown(":material/security: **Layer 2.** BRANE, a security firewall, double-checks every message "
                    "before it reaches the AI.",
                    help="BRANE applies our policy again: it can replace names with codes, keep a message on a "
                         "private AI, or block it. If BRANE cannot be reached, nothing is sent.")
    left, right = st.columns(2, gap="medium")
    with left:
        st.markdown("**The incident report** (stays on this computer)")
        st.html(f'<div class="bb-panel">{original_html(r)}</div>')
    with right:
        st.markdown("**What the AI received**")
        received = v.model_text or r.payload_sent
        if v.state in ("CLOUD", "LOCAL") and received:
            st.html(f'<div class="bb-panel mono">{received_html(received)}</div>')
        else:
            st.html('<div class="bb-nothing">Nothing. No AI received anything.</div>')
    st.caption(f":material/lock: The leaked file itself ({records_of(r)} rows) never left this computer. "
               "The AI only learned how many rows and what kinds of data it holds.")


# ---- step 2: draft the reports --------------------------------------------------------------
LAW_WHY = {
    "authority": "GDPR: personal data leaked, so the privacy regulator must be told (Art. 33).",
    "csirt": "NIS2: hospitals must report serious cyber attacks to their security team (Art. 23).",
    "financial_supervisor": "DORA: banks must report major IT incidents to their supervisor (Art. 19).",
    "affected_people": "GDPR: if the risk to them is high, the people themselves must be told (Art. 34).",
}


def deadline_rows(r, meta: dict) -> list[dict]:
    rows = []
    first_due = {reg["regime"]: reg["deadlines"][0]["due"] for reg in r.regimes if reg["deadlines"]}
    for recipient in drafts.recipients_for(r.regimes):
        regime = {"authority": "GDPR", "csirt": "NIS2", "financial_supervisor": "DORA"}.get(recipient)
        due = first_due.get(regime) if regime else None
        if due:
            h = hours_left(due)
            when = f"{pretty_time(due)} ({int(h)} hours left)" if h >= 0 else f"{pretty_time(due)} (overdue)"
        else:
            when = "Without delay, if the risk is high"
        who = "The people affected" if recipient == "affected_people" else drafts.authority_name(meta, recipient)
        rows.append({"Who must be told": who, "By when": when, "Why": LAW_WHY[recipient]})
    return rows


def step_drafts(r, meta: dict):
    why("drafts")
    table(pd.DataFrame(deadline_rows(r, meta)).set_index("Who must be told"))
    out = base_drafts(r)
    if r.model_output is None:
        st.warning("No AI drafts this time, so these are fill-in templates made on this computer.",
                   icon=":material/edit_document:")
    facts = drafts.useful_facts(out.get("missing_facts"))
    if facts:
        with st.expander(f"Facts to check before sending ({len(facts)})", icon=":material/checklist:"):
            for i, fact in enumerate(facts):
                st.checkbox(fact, key=f"fact_{r.run_id}_{i}", persist_state="page")
    recipients = drafts.recipients_for(r.regimes)
    tabs = st.tabs([("The people affected" if t == "affected_people" else drafts.authority_name(meta, t).split(" (")[0])
                    for t in recipients])
    for tab_, recipient in zip(tabs, recipients):
        key, title, _ = drafts.RECIPIENTS[recipient]
        with tab_:
            text = st.text_area(title, out.get(key, ""), height=260, key=f"draft_{key}_{r.run_id}",
                                persist_state="page", label_visibility="collapsed")
            open_fields = list(dict.fromkeys(drafts.open_placeholders(text)))
            if open_fields:
                st.caption(f":material/edit: Fill in before approving: {', '.join(open_fields)}")
            else:
                st.caption(":material/check_circle: Ready: nothing left to fill in.")


# ---- step 3: you decide ---------------------------------------------------------------------
TIER_PLAIN = {
    "unlikely": "Low: unlikely to harm anyone. Record it; no report needed.",
    "risk": "Medium: could harm people. Report it to the authorities.",
    "high": "High: likely to harm people. Report it and tell the people affected.",
}


def _on_tier_change(run_id: str):
    if st.session_state.get(f"tier_{run_id}") == "high":
        st.session_state[f"notify_affected_people_{run_id}"] = True


def seal(done: dict):
    who = f"{done['who']} ({done['role']})" if done.get("role") else done["who"]
    st.html(f"""<div class="bb-seal"><div class="lock">🔒</div><div>
      <b>Approved by {html.escape(who)}, {html.escape(amsterdam(done['at']))}.</b>
      <span>Nothing was sent by this app. Risk: {html.escape(TIER_PLAIN[done['risk']].split(':')[0])}. Report to:
      {html.escape(', '.join(done['notify_labels']) or 'nobody')}.</span></div></div>""")


def step_decide(r, meta: dict, mode: str):
    why("decide")
    done = approval_of(r)
    if done:
        seal(done)
    else:
        rid = r.run_id
        c1, c2 = st.columns(2)
        with c1:
            name = st.text_input("Your name", placeholder="e.g. J. Jansen", key=f"rev_name_{rid}")
        with c2:
            role = st.text_input("Your role", placeholder="e.g. Data protection officer", key=f"rev_role_{rid}")
        tier = st.radio("How serious is it?", list(RISK_TIERS), index=None, format_func=TIER_PLAIN.get,
                        key=f"tier_{rid}", on_change=_on_tier_change, args=(rid,),
                        help="Low = GDPR Art. 33(5), document only. Medium = Art. 33, notify the authority. "
                             "High = Art. 34, also inform the people affected.")
        st.markdown("**Who gets a report?**")
        chosen = []
        with st.container(horizontal=True):
            for recipient in drafts.recipients_for(r.regimes):
                label = ("The people affected" if recipient == "affected_people"
                         else drafts.authority_name(meta, recipient).split(" (")[0])
                if st.checkbox(label, value=recipient != "affected_people", key=f"notify_{recipient}_{rid}",
                               help=drafts.RECIPIENTS[recipient][2]):
                    chosen.append(recipient)
        reason = st.text_area("Why are you skipping someone? (only needed if you skip a report)", height=80,
                              key=f"reason_{rid}",
                              help="The law requires a written reason when a report that applies is not made "
                                   "(GDPR Art. 33/34, NIS2 Art. 23, DORA Art. 19).")
        if st.button("Approve", type="primary", icon=":material/how_to_reg:", key=f"approve_{rid}"):
            try:
                a = approve(with_drafts(r, current_drafts(r)), reviewer=name, role=role, risk_level=tier or "",
                            notify=chosen or "none", reason=reason)
            except ApprovalError as exc:
                st.error(str(exc), icon=":material/error:")
            else:
                st.session_state["approvals"][rid] = {
                    "md": a.export_path.read_text(encoding="utf-8"), "name": a.export_path.name, "who": a.reviewer,
                    "role": a.role, "at": a.approved_at, "risk": a.risk_level, "notify": a.notify, "reason": a.reason,
                    "notify_labels": [("the people affected" if t == "affected_people"
                                       else drafts.authority_name(meta, t).split(" (")[0]) for t in a.notify]}
                st.rerun()
    export_buttons(r, meta, mode, approval_of(r))


def export_buttons(r, meta: dict, mode: str, done: dict | None):
    decision = exporter.Decision(done["who"], done["risk"], done["notify"], done["reason"], done["at"],
                                 done.get("role", "")) if done else None
    texts = with_drafts(r, current_drafts(r))
    base = f"breachbrief_{r.run_id}"
    c1, c2 = st.columns(2, gap="medium")
    with c1, st.container(border=True, key="card_word"):
        st.markdown(":material/article: **The reports** (Word): ready to check and send yourself.")
        st.download_button("Download reports (.docx)" if decision else "Download draft reports (.docx)",
                           exporter.build_docx(texts, meta, current_drafts(r), decision, mode), file_name=f"{base}.docx",
                           mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                           type="primary" if decision else "secondary", icon=":material/download:", on_click="ignore")
    with c2, st.container(border=True, key="card_xlsx"):
        st.markdown(":material/table_view: **The record** (Excel): what happened and who decided, "
                    "for the breach register.")
        st.download_button("Download record (.xlsx)", exporter.build_xlsx(texts, meta, decision, mode),
                           file_name=f"{base}_record.xlsx",
                           mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                           icon=":material/download:", on_click="ignore")
    if not decision:
        st.caption("Downloads are marked DRAFT until you approve.")


# ---- evidence (experts) -------------------------------------------------------------------
DECISION_LABEL = {policy.ALLOW: "ALLOW", policy.PROTECT: "PROTECT", policy.LOCAL_ONLY: "LOCAL ONLY",
                  policy.BLOCK: "BLOCK", policy.HUMAN_ONLY: "HUMAN ONLY", policy.DELEGATED: "LEFT TO BRANE"}
TEST_PROTOCOL_MD = Path(__file__).resolve().parent / "TEST_PROTOCOL.md"
TEST_PROTOCOL_JSON = TEST_PROTOCOL_MD.with_suffix(".json")


def step_evidence(r, v: verdict.Verdict):
    why("evidence")
    t1, t2, t3, t4, t5 = st.tabs(["Protection decisions", "Firewall response", "Legal deadlines", "Audit log",
                                  "Security tests"])
    with t1:
        counts: dict[str, int] = {}
        for x in r.decisions:
            counts[x["category"]] = counts.get(x["category"], 0) + 1
        local = policy.local_categories(r.premask)
        rows = [{"Data category": cat.replace("_", " ").title(),
                 "Decision": DECISION_LABEL[rule[0] if local is None or cat in local else policy.DELEGATED],
                 "Found here": counts.get(cat, 0), "Why": rule[2]} for cat, rule in policy.RULES.items()]
        table(pd.DataFrame(rows).set_index("Data category"))
        st.caption(f"Local protection: {'on (full)' if r.premask == 'full' else 'off (guard_only, demo)'}. "
                   f"Identifiers that reached the model: {v.identifiers_reached}; health sentences: {v.health_reached}.")
        if r.local_only:
            with st.expander(f"Reviewer only: {len(r.local_only)} detail(s) kept on this computer",
                             icon=":material/lock:"):
                for item in r.local_only:
                    st.markdown(f"- {item}")
    with t2:
        st.markdown(f"**{v.title}.** {v.sentence}")
        if v.rule:
            st.markdown(f"**{v.rule}**")
        if r.brane_headers:
            table(pd.DataFrame(sorted(r.brane_headers.items()), columns=["X-Brane header", "Value"]).set_index("X-Brane header"))
        else:
            st.caption("No X-Brane headers: " + ("offline mock gateway." if v.gateway == "MOCK"
                                                 else "the request never reached BRANE."))
        if r.payload_sent:
            with st.expander("Exact text sent to the firewall"):
                st.code(r.payload_sent, language=None, wrap_lines=True)
        if v.model_text:
            with st.expander(f"Exact text the model received ({v.basis})"):
                st.code(v.model_text, language=None, wrap_lines=True)
    with t3:
        rows = [{"Regime": x["regime"], "Step": item["step"], "To": x["authority"],
                 "Due (Amsterdam)": pretty_time(item["due"]) if item["due"][:4].isdigit() else item["due"]}
                for x in r.regimes for item in x["deadlines"]]
        table(pd.DataFrame(rows).set_index("Regime"))
        st.caption("Computed by code from the time of discovery, never by the AI.")
    with t4:
        path = protocol.PROTOCOL_DIR / f"{r.run_id}.json"
        if path.exists():
            st.caption(f"protocol/{path.name}: decisions and the exact outgoing text, never the raw protected values")
            st.code(json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2, ensure_ascii=False)[:6000],
                    language="json", wrap_lines=True)
        else:
            st.info("No audit log for this run.")
    with t5:
        test_protocol_view()


def test_protocol_view():
    """The latest TEST_PROTOCOL.md written by make_protocol.py (5 AI-Z cases + 5 edge cases)."""
    if st.button("Run the 10 security tests now", key="run_protocol", icon=":material/play_arrow:"):
        import make_protocol
        with st.spinner("Running 5 required + 5 edge cases…"):
            make_protocol.main()
    if not TEST_PROTOCOL_MD.exists():
        st.info("No test protocol yet. Click the button above or run `python make_protocol.py`.")
        return
    try:
        meta = json.loads(TEST_PROTOCOL_JSON.read_text(encoding="utf-8"))
        ok = meta["passed"] == meta["total"]
        (st.success if ok else st.warning)(
            f"Generated {amsterdam(meta['generated'])} · code {meta['code_version']}",
            title=f"{meta['passed']}/{meta['total']} PASS · BRANE mode: {meta['brane_mode']}",
            icon=":material/fact_check:")
    except (OSError, ValueError, KeyError):
        pass
    md = TEST_PROTOCOL_MD.read_text(encoding="utf-8")
    md = re.sub(r'^<a id="[^"]+"></a>\n', "", md, flags=re.M)        # in-page anchors don't work in Streamlit
    md = re.sub(r"\[(R\d|E\d)\]\(#[re]\d\)", r"\1", md)
    with st.expander("Full test protocol"):
        st.markdown(md)


# ---- page ----------------------------------------------------------------------------------
def brane_chip(mode: str, down: bool):
    """One truthful status chip for the gateway."""
    if down:
        st.html(tag("Firewall down (simulated)", "red"))
    elif mode == "LIVE":
        st.html(tag(f"BRANE live · {os.getenv('TEAM_BUILD', TEAM_BUILD_DEFAULT)}", "green"))
    elif mode == "MOCK":
        st.html(tag("BRANE mock (offline)", "blue"))
    else:
        st.html(tag("BRANE not configured", "red"))


def step_nav(step: str, r):
    i = STEP_IDS.index(step)
    with st.container(horizontal=True, horizontal_alignment="distribute"):
        if i > 0:
            st.button(f"Back: {STEPS[STEP_IDS[i - 1]]}", icon=":material/arrow_back:", on_click=go_to,
                      args=(STEP_IDS[i - 1],), key=f"back_{step}")
        else:
            st.space("small")
        if i < len(STEP_IDS) - 1:
            nxt = STEP_IDS[i + 1]
            primary = step != "decide" or approval_of(r) is not None
            st.button(f"Next: {STEPS[nxt]}", icon=":material/arrow_forward:", icon_position="right",
                      type="primary" if primary else "secondary", on_click=go_to, args=(nxt,), key=f"next_{step}")


def main():
    st.set_page_config(page_title="BreachBrief", page_icon=":material/shield:", layout="wide",
                       initial_sidebar_state="expanded")
    current_step()                                               # normalise before any widget reads it
    st.session_state.setdefault("light_mode", False)            # dark is the default; kept across scenarios
    st.html(theme_vars("light" if st.session_state["light_mode"] else "dark") + APP_CSS)
    mode = gateway_mode()

    with st.sidebar:
        st.html('<div class="bb-brand"><div class="bb-logo">🛡️</div><div><b>BreachBrief</b>'
                '<small>AI help for data breaches, without leaking the data again</small></div></div>')
        scenario = st.radio("Choose a scenario", SCENARIOS, format_func=FRIENDLY.get, key="scenario",
                            on_change=go_to, args=(STEP_IDS[0],))   # new scenario: back to step 1
        with st.expander("Presenter settings", icon=":material/tune:"):
            premask_on = st.toggle("Local pre-masking", value=agent.premask_mode() == "full", key="premask",
                                   help="Layer 1 on: our app removes personal data before the firewall. Off: the "
                                        "firewall alone decides (demonstration only).")
            down = st.toggle("Simulate BRANE down", value=False, key="down")
            clock = st.toggle("Demo clock", value=True, key="demo_clock",
                              help="On: the breach was discovered shortly before now, so deadlines are realistic.")
            brane_chip(mode, down)
            rerun = st.button("Re-run live" if mode == "LIVE" else "Re-run", icon=":material/refresh:", width="stretch")
        st.space("medium")
        st.toggle("Light mode", key="light_mode", help="Switch between the dark and the light theme.")

    premask = "full" if premask_on else "guard_only"
    if os.getenv("BREACHBRIEF_PREWARM", "1") != "0":   # unit tests switch the 6-run pre-warm off
        prewarm(mode)
    store = run_store(code_version())
    key = (scenario, premask, down, mode)
    if rerun or key not in store:
        with st.spinner("Running…"):
            store[key] = run_one(scenario, premask, down)
    r, v, meta = store[key]
    r, meta = with_clock(r, meta, scenario, clock)

    safe_render("intro", r, intro, r, meta, scenario, clock)
    current_step()
    st.segmented_control("Step", STEP_IDS, key="step", required=True, label_visibility="collapsed",
                         format_func=STEPS.get)
    step = current_step()                                        # the widget can hand back None after a rerun
    body = {"protect": (step_protect, r, v), "drafts": (step_drafts, r, meta),
            "decide": (step_decide, r, meta, mode), "evidence": (step_evidence, r, v)}[step]
    safe_render(step, r, *body)
    safe_render(f"nav_{step}", r, step_nav, step, r)


if __name__ == "__main__":  # `streamlit run app.py` executes the script as __main__
    main()
