"""The BRANE team policy we PUT (configure_policy.py) matches POLICY_MATRIX.md. Offline: checks the request body."""
import configure_policy as cp

BODY = cp.policy_body()
CATS = BODY["categories"]
SEMANTIC = {s["code"]: s for s in BODY["semanticCategories"]}


def test_all_25_builtin_categories_have_an_explicit_rule():
    assert len(CATS) == 25 and set(CATS.values()) <= {"allow", "placeholder", "local", "refuse"}
    assert BODY["routingMode"] == "cloud-preferred" and BODY["piiSensitivity"] == "high"


def test_contact_data_placeholder_and_org_allowed():
    for c in ("PERSON", "EMAIL", "PHONE", "ADDRESS", "IP_ADDRESS", "VAT_ID"):
        assert CATS[c] == "placeholder"
    assert CATS["ORG"] == "allow" and CATS["TRADE_REGISTER"] == "allow"   # authorities must appear in drafts


def test_identifiers_financial_and_credentials_refused():
    for c in ("DATE_OF_BIRTH", "SSN", "PASSPORT", "TAX_NUMBER", "INSURANCE_NUMBER", "IBAN", "CREDIT_CARD",
              "ACCOUNT_NUMBER", "PASSWORD", "SECRET_KEY"):
        assert CATS[c] == "refuse"


def test_special_categories_stay_local():
    for c in ("HEALTH_DATA", "ETHNIC_ORIGIN", "POLITICAL_OPINION", "RELIGIOUS_BELIEF", "SEXUAL_ORIENTATION",
              "TRADE_UNION", "SENSITIVE_CONTEXT"):
        assert CATS[c] == "local"


def test_semantic_rules():
    assert SEMANTIC["INDIRECT_HEALTH_CONTEXT"]["action"] == "local"
    assert SEMANTIC["RAW_DATASET_EXFILTRATION"]["action"] == "refuse"
    assert SEMANTIC["AUTONOMOUS_NOTIFICATION_DECISION"]["action"] == "refuse"
    assert SEMANTIC["INDIRECT_HEALTH_CONTEXT"]["legalBasis"] == "GDPR Art. 9(1), Art. 4(15)"
    assert SEMANTIC["RAW_DATASET_EXFILTRATION"]["legalBasis"] == "GDPR Art. 5(1)(f), Art. 32, Art. 4(12)"
    assert SEMANTIC["AUTONOMOUS_NOTIFICATION_DECISION"]["legalBasis"] == "GDPR Art. 5(2), Art. 33(1), Art. 34(1)"
    kw = SEMANTIC["INDIRECT_HEALTH_CONTEXT"]["keywords"]
    assert "bedrijfsarts" in kw and "arbeitsunfähig" in kw                # NL and DE, as tested live in E3
