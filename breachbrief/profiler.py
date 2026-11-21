"""Profiles the leaked file LOCALLY. The file itself is never sent anywhere:
only counts and data-category labels leave the machine."""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from . import detectors as d

# header keyword -> category label sent to the model (wording avoids raw health terms on purpose)
HEADER_MAP = [
    (("name", "naam", "first", "last", "surname", "patient", "employee", "customer"), "names"),
    (("email", "e-mail", "mail"), "email addresses"),
    (("phone", "tel", "mobile"), "phone numbers"),
    (("iban", "account", "rekening", "bank"), "bank account numbers (IBAN)"),
    (("bsn", "ssn", "tax", "national_id", "steuer", "passport"), "national identification numbers"),
    (("salary", "gross", "net", "salaris", "loon", "gehalt", "balance", "saldo"), "salary or balance amounts"),
    # "age data", not "dates of birth": BRANE's detector refuses any mention of the DOB category, even as a label
    (("birth", "dob", "geboorte"), "age data"),
    (("address", "adres", "street", "postcode", "city"), "postal addresses"),
    (("diagnos", "medical", "health", "sick", "ziek", "notes_hr", "condition", "ward", "treatment"), "SPECIAL_CATEGORY"),
]


def _label(header: str) -> str | None:
    h = header.lower()
    for keys, label in HEADER_MAP:
        if any(k in h for k in keys):
            return label
    return None


def profile_csv(path: Path) -> dict:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    headers = list(rows[0].keys()) if rows else []
    categories: Counter[str] = Counter()
    special_rows = 0
    injection_cells = 0
    people: set[str] = set()
    first_names: set[str] = set()

    name_cols = [h for h in headers if _label(h) == "names"]
    for row in rows:
        row_special = False
        for h in headers:
            v = (row.get(h) or "").strip()
            if not v:
                continue
            label = _label(h)
            if label == "SPECIAL_CATEGORY":
                row_special = True
            elif label:
                categories[label] += 1
            # value-level detection catches sensitive data (and planted instructions) in unexpected columns
            cats = {f.category for f in d.detect(v, use_ner=False)}
            if d.HEALTH in cats:
                row_special = True
            if d.INJECTION in cats:
                injection_cells += 1
        special_rows += row_special
        full = " ".join((row.get(c) or "").strip() for c in name_cols if "id" not in c.lower()).strip()
        if full:
            people.add(full)
        for c in name_cols:
            if "first" in c.lower() and (row.get(c) or "").strip():
                first_names.add(row[c].strip())

    labels = sorted(categories)
    if special_rows:
        labels.append("special-category data under GDPR Art. 9")
    return {
        "file_name_type": path.suffix.lstrip(".").upper(),
        "record_count": len(rows),
        "data_categories": labels,
        "special_category_records": special_rows,
        "injection_cells": injection_cells,          # cells whose text looks like instructions to an AI; never sent
        "_known_people": sorted(people),  # LOCAL ONLY: used to detect names in free text, never sent
        "_known_first_names": sorted(first_names),  # LOCAL ONLY: first-name-only mentions ("Sanne called HR")
    }


def safe_summary(profile: dict) -> str:
    """The only description of the leaked file the model ever receives."""
    cats = ", ".join(profile["data_categories"]) or "no identified personal data"
    s = f"A {profile['file_name_type']} file with {profile['record_count']} records. Data categories present: {cats}."
    if profile["special_category_records"]:
        s += f" {profile['special_category_records']} records contain special-category data."
    if profile.get("injection_cells"):
        s += (f" {profile['injection_cells']} cell(s) contain text that looks like instructions to an AI system;"
              " their content was not processed.")
    return s
