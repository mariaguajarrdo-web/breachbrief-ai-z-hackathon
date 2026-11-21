"""Local detection of sensitive data. Runs BEFORE anything leaves the machine.

Defence in depth: BRANE also scans, but we never rely on it alone.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass

# ---- data categories (keep in sync with POLICY_MATRIX.md) -------------------
PERSON_NAME = "PERSON_NAME"
EMAIL = "EMAIL"
PHONE = "PHONE"
IBAN = "IBAN"
NATIONAL_ID = "NATIONAL_ID"
MONEY_VALUE = "MONEY_VALUE"
DATE_OF_BIRTH = "DATE_OF_BIRTH"
RECIPIENT = "RECIPIENT"
HEALTH = "HEALTH"
INJECTION = "INJECTION"
ENCODED = "ENCODED_CONTENT"  # base64 / hex blobs: cannot be inspected, so never sent


@dataclass(frozen=True)
class Finding:
    category: str
    value: str
    start: int
    end: int


# ---- validators -------------------------------------------------------------
def iban_valid(raw: str) -> bool:
    s = re.sub(r"\s+", "", raw).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    return int(digits) % 97 == 1


def bsn_valid(raw: str) -> bool:
    """Dutch citizen service number, '11-proof'."""
    s = re.sub(r"\D", "", raw)
    if len(s) != 9:
        return False
    total = sum(int(d) * w for d, w in zip(s[:8], range(9, 1, -1))) - int(s[8])
    return total % 11 == 0 and s != "000000000"


# ---- patterns ---------------------------------------------------------------
_IBAN_START_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}")
_IBAN_SEPARATORS = " \t\r\n-"
IBAN_LENGTHS = {"NL": 18, "DE": 22, "BE": 16, "FR": 27, "GB": 22, "ES": 24, "IT": 27, "LU": 20, "AT": 20, "IE": 22,
                "PT": 25, "CH": 21, "DK": 18, "FI": 18, "SE": 24, "NO": 15, "PL": 28, "CZ": 24, "GR": 27}
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+31|\+49|\+32|0031|0)[ -]?\d(?:[ -]?\d){7,9}\b")
_BSN_RE = re.compile(r"\b\d{3}[. ]?\d{3}[. ]?\d{3}\b")
_TAXID_RE = re.compile(r"\b(?:DE\d{11}|\d{2}/\d{3}/\d{5})\b")
_MONEY_RE = re.compile(
    r"(?:€|EUR)\s?-?\d+(?:[.,\s]\d{3})*(?:[.,]\d{1,2})?|(?<![\w.])-?\d+(?:[.,]\d{3})*(?:[.,]\d{1,2})?\s?(?:€|EUR|euro)\b",
    re.IGNORECASE,
)
_DOB_RE = re.compile(r"\b(?:born|geboren|DOB|date of birth)[:\s]+\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}", re.IGNORECASE)

HEALTH_TERMS = [
    # EN
    "diagnosis", "diagnosed", "illness", "sick leave", "burn-out", "burnout", "depression",
    "pregnan", "cancer", "diabetes", "hiv", "medication", "therapy", "surgery", "hospitalised",
    "hospitalized", "medical", "reintegration", "disability", "chronic", "oncology", "psychiatr",
    "cardiolog", "orthopaed", "orthoped", "maternity", "internal medicine", "neurolog", "fracture", "fibrillation",
    # NL
    "ziek", "diagnose", "zwanger", "re-integratie", "arbo-arts", "bedrijfsarts", "medisch",
    # DE
    "krank", "arbeitsunfähig", "schwanger", "behandlung",
]
_HEALTH_RE = re.compile("|".join(re.escape(t) for t in HEALTH_TERMS), re.IGNORECASE)

INJECTION_PATTERNS = [
    r"ignore (?:all |any |the )?(?:previous|prior|above|your) (?:instructions|rules|policy|policies)",
    r"disregard (?:all |the )?(?:previous|prior|above|your)? ?(?:instructions|rules|policy)",
    r"(?:attach|include|send|forward|paste) (?:the )?(?:full|entire|complete|whole|raw) (?:spreadsheet|file|list|data|dataset|records)",
    r"you are now",
    r"system (?:note|prompt|override)\s*:",
    r"do not (?:mask|redact|pseudonymi[sz]e|anonymi[sz]e)",
    # indirect / polite requests to undo the protection
    r"(?:requires?|needs?|wants?|requests?|asks? for|must (?:have|receive|see|get))\b[^.\n]{0,60}?\b"
    r"(?:unredacted|unmasked|un-?pseudonymi[sz]ed|unanonymi[sz]ed|uncensored|non-?redacted|clear-?text)\b",
    r"\b(?:kindly|please)\s+(?:paste|reveal|dump|print|output|copy|insert)\b",
    r"\b(?:paste|reveal|dump|print|output|insert|copy)\s+(?:it|them|all|everything|the (?:\w+ ){0,2}"
    r"(?:list|data|names|values|records|file))\s+(?:below|here|in (?:the|your) (?:answer|reply|response|draft|output))",
    r"(?:replace|swap) (?:the )?(?:placeholders|pseudonyms|tokens) with (?:the )?(?:real|actual|original)",
    r"(?:reveal|show|print|output|repeat) (?:the |your )?(?:system prompt|hidden instructions)",
    r"negeer (?:alle )?(?:vorige )?instructies",
    r"ignoriere (?:alle )?(?:vorherigen )?anweisungen",
]
_INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)

# Obfuscation: zero-width characters, look-alike letters / leetspeak, s p a c e d letters.
_ZERO_WIDTH = set("\u200b\u200c\u200d\u2060\ufeff\u00ad")
_CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "і": "i", "у": "y", "х": "x",
                              "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED_RUN_RE = re.compile(r"(?<![a-z])[a-z](?:(?:[ ._-]| {2,})[a-z](?![a-z])){3,}")


def _normalise_for_injection(text: str) -> tuple[str, list[int]]:
    """Return a normalised copy of `text` plus, for each normalised char, its index in the original."""
    chars, idx = [], []
    for i, c in enumerate(text):
        if c in _ZERO_WIDTH:
            continue
        chars.append(c.lower().translate(_CONFUSABLES))
        idx.append(i)
    norm = "".join(chars)
    out_c, out_i, cursor = [], [], 0
    for m in _SPACED_RUN_RE.finditer(norm):           # "i g n o r e  a l l" -> "ignore all"
        out_c.extend(chars[cursor:m.start()]); out_i.extend(idx[cursor:m.start()])
        j = m.start()
        while j < m.end():
            if norm[j].isalpha():
                out_c.append(norm[j]); out_i.append(idx[j]); j += 1
            else:
                k = j
                while k < m.end() and not norm[k].isalpha():
                    k += 1
                if k - j >= 2:                        # a wider gap separates words
                    out_c.append(" "); out_i.append(idx[j])
                j = k
        cursor = m.end()
    out_c.extend(chars[cursor:]); out_i.extend(idx[cursor:])
    return "".join(out_c), out_i


def _find_injections(text: str) -> list[tuple[int, int]]:
    norm, idx = _normalise_for_injection(text)
    spans = []
    for m in _INJECTION_RE.finditer(norm):
        if m.end() > m.start():
            spans.append((idx[m.start()], idx[m.end() - 1] + 1))
    return spans


# A sentence ends at a line break, or at . ! ? followed by whitespace / end of text.
# (So "6583.00" or "burnout_followup_list.xlsx" do not end a sentence.)
_SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)|\n")


def _sentence_span(text: str, start: int, end: int) -> tuple[int, int]:
    """Expand a match to the full sentence / line it sits in."""
    left = 0
    for m in _SENTENCE_END_RE.finditer(text, 0, start):
        left = m.end()
    m = _SENTENCE_END_RE.search(text, end)
    right = m.end() if m else len(text)
    while left < right and text[left] in " \t":
        left += 1
    return left, right


def _find_ibans(text: str) -> list["Finding"]:
    """IBANs written in any common way: spaced, dashed, lowercase, or split across a line break.
    Only reported when the mod-97 check passes for the country's IBAN length."""
    found = []
    for m in _IBAN_START_RE.finditer(text):
        chars, ends, i, sep_run = [], [], m.start(), 0
        while i < len(text) and len(chars) < 34:
            c = text[i]
            if c.isascii() and c.isalnum():
                chars.append(c.upper())
                ends.append(i + 1)
                sep_run = 0
            elif c in _IBAN_SEPARATORS and sep_run < 3:
                sep_run += 1
            else:
                break
            i += 1
        country = chars[0] + chars[1]
        lengths = [IBAN_LENGTHS[country]] if country in IBAN_LENGTHS else range(34, 14, -1)
        for n in lengths:
            end = ends[n - 1] if n <= len(ends) else None
            if end and not (end < len(text) and text[end].isalnum()) and iban_valid("".join(chars[:n])):
                found.append(Finding(IBAN, text[m.start():end], m.start(), end))
                break
    return found


# ---- local NER (spaCy, fully offline) ---------------------------------------
NER_MODEL = "xx_ent_wiki_sm"
_nlp = None
_NER_LOCK = threading.Lock()

# A PER entity containing one of these words is an organisation, not a person.
_ORG_HINTS = {"b.v.", "bv", "n.v.", "nv", "gmbh", "ag", "ltd", "inc", "llc", "s.a.", "sa", "plc", "bank", "analytics",
              "supplies", "services", "group", "holding", "ziekenhuis", "hospital", "autoriteit", "authority",
              "ministerie", "ministry", "gemeente", "cert", "payroll", "systems", "solutions", "consulting"}
# Placeholders and markers we inserted ourselves must never be re-detected as people.
# Also BRANE's own tokens, e.g. PERSON_REF_1, as they appear in its dry-run preview.
_PLACEHOLDER_RE = re.compile(r"\b(?:PERSON|EMAIL|RECIPIENT|PHONE)_[A-Z0-9_]+\b|\[[A-Z_]+\]")


class NerUnavailable(Exception):
    """The local NER model could not be loaded. Fail closed: nothing may be sent."""


def _get_nlp():
    global _nlp
    if _nlp is None:
        try:
            import spacy
            _nlp = spacy.load(NER_MODEL, disable=["parser", "tagger", "lemmatizer"])
        except Exception as exc:  # missing package, missing model, blocked DLL, ...
            raise NerUnavailable(
                f"Local NER model '{NER_MODEL}' unavailable ({exc}). Install it with "
                f"'python -m spacy download {NER_MODEL}'. Nothing sent.") from exc
    return _nlp


def ner_person_names(text: str, known_recipients: list[str] | None = None) -> list[str]:
    """Person names found by the local NER model. Runs per line, so a signature block
    ('Sanne de Vries' / 'Privacy Officer' / 'Company B.V.') is not merged into one entity."""
    nlp = _get_nlp()
    recipients = [r.lower() for r in (known_recipients or [])]
    lines = [ln for ln in text.splitlines() if ln.strip()]
    names: set[str] = set()
    with _NER_LOCK:  # the UI pre-runs scenarios in threads; one spaCy call at a time
        docs = list(nlp.pipe(lines))
    for doc in docs:
        for ent in doc.ents:
            if ent.label_ != "PER":
                continue
            if len(ent) == 1 and (ent.start == 0 or doc[ent.start - 1].text in {".", "!", "?", ":", ">", "-", "*", ")", "]"}):
                continue  # sentence-initial single word: "Please delete...", "Reply to..." (known first names are matched separately)
            name = _PLACEHOLDER_RE.sub("", ent.text).strip(" ,.;:()'\"-")
            if len(name) < 3 or not name[0].isupper() or not any(c.islower() for c in name):
                continue  # placeholders, acronyms, fragments
            words = {w.lower().strip(",.") for w in name.split()}
            if words & _ORG_HINTS or any(name.lower() in r or r in name.lower() for r in recipients):
                continue
            names.add(name)
    return sorted(names)


def detect(text: str, known_people: list[str] | None = None, known_recipients: list[str] | None = None,
           use_ner: bool = True, known_first_names: list[str] | None = None,
           only: set[str] | None = None) -> list[Finding]:
    """Return all sensitive findings in `text`. Every occurrence, not just the first.

    Names come from three sources, merged: people listed in the leaked file / scenario
    (known_people), local NER on the text itself, and title + surname patterns.
    NER-found names are added to the known list, so every later occurrence and every
    'Mr. <surname>' mention of them is caught too."""
    findings: list[Finding] = []
    if use_ner:
        known_people = list(known_people or []) + ner_person_names(text, known_recipients)

    def add_all(pattern: re.Pattern, category: str, validator=None):
        for m in pattern.finditer(text):
            if validator is None or validator(m.group(0)):
                findings.append(Finding(category, m.group(0), m.start(), m.end()))

    # sentence-level categories first (they swallow whole sentences)
    for start, end in _find_injections(text):
        s, e = _sentence_span(text, start, end)
        findings.append(Finding(INJECTION, text[s:e], s, e))
    for m in _HEALTH_RE.finditer(text):
        s, e = _sentence_span(text, m.start(), m.end())
        findings.append(Finding(HEALTH, text[s:e], s, e))

    findings.extend(_find_ibans(text))
    add_all(_ENCODED_RE, ENCODED, _looks_encoded)
    add_all(_EMAIL_RE, EMAIL)
    add_all(_TAXID_RE, NATIONAL_ID)
    add_all(_BSN_RE, NATIONAL_ID, bsn_valid)
    add_all(_PHONE_RE, PHONE)
    add_all(_MONEY_RE, MONEY_VALUE)
    add_all(_DOB_RE, DATE_OF_BIRTH)

    for name in sorted(known_people or [], key=len, reverse=True):
        for m in re.finditer(rf"(?<!\w){re.escape(name)}(?!\w)", text, re.IGNORECASE):
            findings.append(Finding(PERSON_NAME, m.group(0), m.start(), m.end()))
        # also catch surname-only mentions ("Mr. Jansen")
        parts = name.split()
        if len(parts) >= 2 and len(parts[-1]) > 3:
            for m in re.finditer(rf"\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Hr\.?|Fr\.?|mevrouw|meneer|Herr|Frau)\s+{re.escape(parts[-1])}\b", text):
                findings.append(Finding(PERSON_NAME, m.group(0), m.start(), m.end()))

    # first name alone ("Sanne called HR"): only first names of people in the leaked file, capitalised, whole word
    for first in sorted(set(known_first_names or []), key=len, reverse=True):
        if len(first) >= 3:
            for m in re.finditer(rf"(?<![\w@.]){re.escape(first)}(?![\w@])", text):
                findings.append(Finding(PERSON_NAME, m.group(0), m.start(), m.end()))

    # generic: title + capitalised surname, even for people not in the leaked file
    for m in re.finditer(r"\b(?:Mr|Mrs|Ms|Dr|Prof|Hr|Fr|Herr|Frau|mevrouw|meneer|mevr|dhr)\.?\s+(?:(?:van|de|der|den|von|ter)\s+)*[A-ZÄÖÜ][a-zäöüß]+(?:[- ][A-ZÄÖÜ][a-zäöüß]+)?", text):
        findings.append(Finding(PERSON_NAME, m.group(0), m.start(), m.end()))

    for org in sorted(known_recipients or [], key=len, reverse=True):
        for m in re.finditer(rf"(?<!\w){re.escape(org)}(?!\w)", text, re.IGNORECASE):
            findings.append(Finding(RECIPIENT, m.group(0), m.start(), m.end()))

    if only is not None:  # e.g. LOCAL_PREMASK=guard_only: other categories are left for BRANE
        findings = [f for f in findings if f.category in only]
    return _resolve_overlaps(findings)


_PRIORITY = {INJECTION: 0, ENCODED: 0, HEALTH: 1, IBAN: 2, NATIONAL_ID: 3, EMAIL: 4, DATE_OF_BIRTH: 5,
             PHONE: 6, MONEY_VALUE: 7, PERSON_NAME: 8, RECIPIENT: 9}

# Long runs of base64 / hex: content we cannot inspect (an encoded attachment could hold names or
# health data). Unverifiable content is never sent; the reviewer sees it locally.
_ENCODED_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{48,}={0,2}|(?:0x)?[0-9a-fA-F]{40,})"
                         r"(?![A-Za-z0-9+/=_-])")


def _looks_encoded(s: str) -> bool:
    """Mixed letters and digits (or base64 padding): not an ordinary long word or number."""
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    return (has_digit and has_alpha) or s.endswith("=")


def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Keep the widest / highest-priority finding where spans overlap."""
    ordered = sorted(findings, key=lambda f: (_PRIORITY[f.category], -(f.end - f.start), f.start))
    kept: list[Finding] = []
    for f in ordered:
        if any(not (f.end <= k.start or f.start >= k.end) for k in kept):
            continue
        kept.append(f)
    return sorted(kept, key=lambda f: f.start)
