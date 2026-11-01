"""
Unit Tests for Privacy Guard (Feature 2: PII & Password Redaction).
"""

import pytest
from privacy_guard import PrivacyGuard, luhn_checksum_valid


def test_password_redaction():
    pg = PrivacyGuard()
    res = pg.redact("My password is SuperSecret123! and username is admin.")
    assert "[REDACTED_PASSWORD]" in res.redacted_text
    assert "SuperSecret123!" not in res.redacted_text
    assert res.has_sensitive_data is True
    assert "Password" in res.redacted_categories


def test_api_keys_redaction():
    pg = PrivacyGuard()
    res1 = pg.redact("Using Groq API key: gsk_12345678901234567890123456789012")
    assert "[REDACTED_API_KEY:GROQ]" in res1.redacted_text

    res2 = pg.redact("OpenAI token sk-abcdef1234567890abcdef12")
    assert "[REDACTED_API_KEY:OPENAI]" in res2.redacted_text

    res3 = pg.redact("Gemini key AQ.TEST_MOCK_GEMINI_API_KEY_STRING_12345")
    assert "[REDACTED_API_KEY:GEMINI]" in res3.redacted_text


def test_email_and_phone_redaction():
    pg = PrivacyGuard()
    text = "Please reach me at support@example.com or phone +1-555-123-4567."
    res = pg.redact(text)
    assert "[REDACTED_EMAIL]" in res.redacted_text
    assert "[REDACTED_PHONE]" in res.redacted_text
    assert "support@example.com" not in res.redacted_text


def test_credit_card_luhn_validation():
    pg = PrivacyGuard()
    # 4000-1234-5678-9017 is a valid Luhn test number
    assert luhn_checksum_valid("4000123456789017") is True
    assert luhn_checksum_valid("4000123456789010") is False

    res = pg.redact("Charge my visa card 4000-1234-5678-9017 for order #99")
    assert "[REDACTED_CREDIT_CARD]" in res.redacted_text
    assert "4000-1234-5678-9017" not in res.redacted_text


def test_disabled_privacy_guard():
    pg = PrivacyGuard(enabled=False)
    raw = "My password is Secret123"
    res = pg.redact(raw)
    assert res.redacted_text == raw
    assert res.has_sensitive_data is False


def test_modern_api_keys_and_tokens():
    """Verify modern multi-hyphen OpenAI, Anthropic, and Gemini keys."""
    pg = PrivacyGuard()
    # 1. OpenAI project key
    res_oai = pg.redact("Here is my OpenAI project key: sk-proj-1234567890abcdef1234567890")
    assert "[REDACTED_API_KEY:OPENAI]" in res_oai.redacted_text
    assert "sk-proj-" not in res_oai.redacted_text

    # 2. Anthropic api03 key
    res_ant = pg.redact("Anthropic client token sk-ant-api03-1234567890abcdef1234567890")
    assert "[REDACTED_API_KEY:ANTHROPIC]" in res_ant.redacted_text
    assert "sk-ant-api03-" not in res_ant.redacted_text

    # 3. Google AI Studio key
    res_gem = pg.redact("Google Gemini AI Studio key AIzaSy1234567890abcdef1234567890123")
    assert "[REDACTED_API_KEY:GEMINI]" in res_gem.redacted_text
    assert "AIzaSy" not in res_gem.redacted_text


def test_natural_language_passwords_and_benign_preservation():
    """Verify natural-language password forms and benign false-positive resistance."""
    pg = PrivacyGuard()

    # Required forms from Step 5.4 prompt:
    # 1. "My password is Secret123."
    r1 = pg.redact("My password is Secret123.")
    assert "[REDACTED_PASSWORD]" in r1.redacted_text
    assert "Secret123" not in r1.redacted_text
    assert r1.redacted_text == "My password is [REDACTED_PASSWORD]."

    # 2. "The password is Secret123."
    r2 = pg.redact("The password is Secret123.")
    assert "[REDACTED_PASSWORD]" in r2.redacted_text
    assert "Secret123" not in r2.redacted_text
    assert r2.redacted_text == "The password is [REDACTED_PASSWORD]."

    # 3. "Use Secret123 as my password."
    r3 = pg.redact("Use Secret123 as my password.")
    assert "[REDACTED_PASSWORD]" in r3.redacted_text
    assert "Secret123" not in r3.redacted_text
    assert r3.redacted_text == "Use [REDACTED_PASSWORD] as my password."

    # 4. "My login password is Secret123."
    r4 = pg.redact("My login password is Secret123.")
    assert "[REDACTED_PASSWORD]" in r4.redacted_text
    assert "Secret123" not in r4.redacted_text
    assert r4.redacted_text == "My login password is [REDACTED_PASSWORD]."

    # Benign resistance: ordinary sentences must NOT be redacted
    benign_sentences = [
        "The password is required for account security.",
        "The password is valid.",
        "My password is expired.",
        "Use python as my primary language for machine learning."
    ]
    for s in benign_sentences:
        res = pg.redact(s)
        assert "[REDACTED_PASSWORD]" not in res.redacted_text
        assert res.redacted_text == s

