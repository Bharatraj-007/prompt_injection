"""
Privacy Guard: PII & Password Redaction Module for AI Security Platform.

Protects sensitive data from being leaked or transmitted to upstream AI providers:
- Personal Identifiable Information (Emails, Phone Numbers, Social IDs)
- Authentication Secrets (Passwords, API Keys, JWT Tokens, Private Keys)
- Financial Data (Credit Card Numbers with Luhn check, Bank Account Numbers)

Architectural Invariant:
- Security inspection occurs on original prompt FIRST to preserve attack detection.
- Redacted prompt is forwarded to external AI providers.
- Raw secrets are never stored in databases, logs, or analytics.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class RedactionResult:
    """Container for redacted text and detected sensitive entities."""
    original_text: str
    redacted_text: str
    has_sensitive_data: bool
    total_redactions: int
    redaction_counts: Dict[str, int]
    redacted_categories: List[str]
    # Sanitized audit details: category and length only, NEVER the secret value itself
    redaction_details: List[Dict[str, Any]] = field(default_factory=list)


def luhn_checksum_valid(card_number: str) -> bool:
    """Validates credit card number checksum using Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class PrivacyGuard:
    """
    Deterministic regex and algorithmic redaction engine for personal,
    authentication, and financial identifiers.
    """

    # 1. Authentication Secrets
    PRIVATE_KEY_PATTERN = re.compile(
        r"-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?(?:PRIVATE\s+KEY|RSA\s+PRIVATE\s+KEY|EC\s+PRIVATE\s+KEY|OPENSSH\s+PRIVATE\s+KEY)-----[\s\S]+?-----END\s+(?:[A-Z0-9_-]+\s+)?(?:PRIVATE\s+KEY|RSA\s+PRIVATE\s+KEY|EC\s+PRIVATE\s+KEY|OPENSSH\s+PRIVATE\s+KEY)-----",
        re.IGNORECASE
    )

    JWT_TOKEN_PATTERN = re.compile(
        r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
    )

    API_KEY_PATTERNS = [
        # Groq
        (re.compile(r"\bgsk_[a-zA-Z0-9_-]{20,}\b"), "[REDACTED_API_KEY:GROQ]"),
        # Anthropic (evaluated before OpenAI to prevent sk- prefix collision)
        (re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b"), "[REDACTED_API_KEY:ANTHROPIC]"),
        # OpenAI (handles legacy sk- and modern multi-hyphen sk-proj- keys)
        (re.compile(r"\bsk-(?!ant-)[a-zA-Z0-9_-]{20,}\b"), "[REDACTED_API_KEY:OPENAI]"),
        # Google Gemini API key formats (OAuth/Token AQ. and Google AI Studio AIzaSy)
        (re.compile(r"\bAQ\.[a-zA-Z0-9_-]{30,}\b"), "[REDACTED_API_KEY:GEMINI]"),
        (re.compile(r"\bAIzaSy[a-zA-Z0-9_-]{28,36}\b"), "[REDACTED_API_KEY:GEMINI]"),
        # GitHub tokens
        (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"), "[REDACTED_API_KEY:GITHUB]"),
        (re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{40,}\b"), "[REDACTED_API_KEY:GITHUB_PAT]"),
        # Slack / AWS
        (re.compile(r"\bxox[baprs]-[0-9]{10,}-[a-zA-Z0-9-]+\b"), "[REDACTED_API_KEY:SLACK]"),
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_API_KEY:AWS_ACCESS_KEY]"),
        # Generic API key assignments
        (re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?"), "[REDACTED_API_KEY]")
    ]

    PASSWORD_PATTERNS = [
        # Standard configuration key-value assignments
        re.compile(r"(?i)\b(?:password|passwd|pwd|passcode|secret_key|secret)\s*[:=]\s*['\"]?([^\s'\",;]+)['\"]?"),
        # Natural language declarative forms ("My password is Secret123", "The password is...", "My login password is...")
        re.compile(r"(?i)\b(?:my\s+(?:login\s+)?password|the\s+(?:login\s+)?password|user\s+password|login\s+password)\s+(?:is|was|set\s+to)\s+['\"]?([^\s'\",;\.]{3,})['\"]?"),
        # Natural language imperative forms ("Use Secret123 as my password", "Set Secret123 as the password")
        re.compile(r"(?i)\b(?:use|set)\s+['\"]?([^\s'\",;\.]{3,})['\"]?\s+as\s+(?:my\s+|the\s+)?(?:login\s+)?password\b"),
        # Prepositional/instructional forms ("with password Secret123", "enter password Secret123")
        re.compile(r"(?i)\b(?:with|using|enter)\s+(?:the\s+|my\s+)?(?:login\s+)?password\s*[:=]?\s*['\"]?([^\s'\",;\.]{3,})['\"]?")
    ]

    # 2. Personal Information
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"
    )

    PHONE_PATTERNS = [
        # International with country code (+1, +44, +91, etc.)
        re.compile(r"(?:\+\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]\d{3,4}(?![-\d])"),
        # Explicit phone indicators
        re.compile(r"(?i)\b(?:phone|mobile|tel|contact)\s*(?:is|:)?\s*([6-9]\d{9})\b"),
        # Standalone 10-digit mobile number
        re.compile(r"(?<![-\d])(?:[6-9]\d{9})(?![-\d])")
    ]

    # US SSN (Social Security Number)
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    # 3. Financial Information
    # Standard 16-digit formatted card: 4 groups of 4 digits separated by spaces or dashes
    CREDIT_CARD_FORMATTED_PATTERN = re.compile(
        r"\b(?:\d{4}[-\s]){3}\d{4}\b"
    )
    # Generic unformatted 13-19 digit card candidate
    CREDIT_CARD_UNFORMATTED_PATTERN = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    )

    BANK_ACCOUNT_PATTERN = re.compile(
        r"(?i)\b(?:account|acct|iban)\s*(?:no|number|#)?\s*[:=]?\s*([a-zA-Z0-9]*\d[a-zA-Z0-9]{7,23})\b"
    )

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def redact(self, text: str) -> RedactionResult:
        """
        Scans and redacts sensitive information from input text.
        Returns RedactionResult containing sanitized text and telemetry.
        """
        if not self.enabled or not text:
            return RedactionResult(
                original_text=text or "",
                redacted_text=text or "",
                has_sensitive_data=False,
                total_redactions=0,
                redaction_counts={},
                redacted_categories=[],
                redaction_details=[]
            )

        redacted = text
        counts: Dict[str, int] = {}
        details: List[Dict[str, Any]] = []

        def record(category: str, length: int):
            counts[category] = counts.get(category, 0) + 1
            details.append({"category": category, "char_length": length})

        # --- A. Private Keys ---
        for match in list(self.PRIVATE_KEY_PATTERN.finditer(redacted)):
            val = match.group(0)
            redacted = redacted.replace(val, "[REDACTED_PRIVATE_KEY]")
            record("Private Key", len(val))

        # --- B. JWT Tokens ---
        for match in list(self.JWT_TOKEN_PATTERN.finditer(redacted)):
            val = match.group(0)
            redacted = redacted.replace(val, "[REDACTED_JWT_TOKEN]")
            record("JWT Token", len(val))

        # --- C. Specific & Generic API Keys ---
        for pattern, placeholder in self.API_KEY_PATTERNS:
            for match in list(pattern.finditer(redacted)):
                if match.groups():
                    val = match.group(1)
                    full = match.group(0)
                    rep = full.replace(val, placeholder)
                    redacted = redacted.replace(full, rep)
                    record("API Key", len(val))
                else:
                    val = match.group(0)
                    redacted = redacted.replace(val, placeholder)
                    record("API Key", len(val))

        # --- D. Passwords ---
        benign_password_stopwords = {
            "the", "a", "an", "is", "are", "was", "were", "required", "correct",
            "valid", "invalid", "unknown", "missing", "expired", "reset", "changed",
            "none", "null", "not", "empty", "hidden", "confidential", "secret",
            "protected", "secure", "encrypted", "hashed", "strong", "weak", "simple",
            "complex", "temporary", "mandatory", "optional", "verified"
        }
        for pattern in self.PASSWORD_PATTERNS:
            for match in list(pattern.finditer(redacted)):
                val = match.group(1)
                full = match.group(0)
                # Avoid redacting if value looks like a common English word in benign context
                if val.lower() not in benign_password_stopwords:
                    rep = full.replace(val, "[REDACTED_PASSWORD]")
                    redacted = redacted.replace(full, rep)
                    record("Password", len(val))

        # --- E. Credit Card Numbers (Formatted or Validated via Luhn algorithm) ---
        for pat in [self.CREDIT_CARD_FORMATTED_PATTERN, self.CREDIT_CARD_UNFORMATTED_PATTERN]:
            for match in list(pat.finditer(redacted)):
                candidate = match.group(0)
                raw_digits = re.sub(r"\D", "", candidate)
                if len(raw_digits) in [13, 14, 15, 16, 19]:
                    if luhn_checksum_valid(raw_digits) or pat == self.CREDIT_CARD_FORMATTED_PATTERN:
                        redacted = redacted.replace(candidate, "[REDACTED_CREDIT_CARD]")
                        record("Credit Card", len(candidate))

        # --- F. Bank Account Numbers ---
        for match in list(self.BANK_ACCOUNT_PATTERN.finditer(redacted)):
            val = match.group(1)
            full = match.group(0)
            rep = full.replace(val, "[REDACTED_BANK_ACCOUNT]")
            redacted = redacted.replace(full, rep)
            record("Bank Account", len(val))

        # --- G. Social Security Numbers ---
        for match in list(self.SSN_PATTERN.finditer(redacted)):
            val = match.group(0)
            redacted = redacted.replace(val, "[REDACTED_SSN]")
            record("SSN", len(val))

        # --- H. Email Addresses ---
        for match in list(self.EMAIL_PATTERN.finditer(redacted)):
            val = match.group(0)
            redacted = redacted.replace(val, "[REDACTED_EMAIL]")
            record("Email", len(val))

        # --- I. Phone Numbers ---
        for pattern in self.PHONE_PATTERNS:
            for match in list(pattern.finditer(redacted)):
                val = match.group(1) if match.groups() else match.group(0)
                raw_digits = re.sub(r"\D", "", val)
                # Verify digit count is legitimate for phone (7-15 digits)
                if 7 <= len(raw_digits) <= 15:
                    full = match.group(0)
                    rep = full.replace(val, "[REDACTED_PHONE]")
                    redacted = redacted.replace(full, rep)
                    record("Phone Number", len(val))

        total_count = sum(counts.values())
        has_sensitive = total_count > 0

        return RedactionResult(
            original_text=text,
            redacted_text=redacted,
            has_sensitive_data=has_sensitive,
            total_redactions=total_count,
            redaction_counts=counts,
            redacted_categories=sorted(list(counts.keys())),
            redaction_details=details
        )


_DEFAULT_PRIVACY_GUARD = None

def get_privacy_guard() -> PrivacyGuard:
    """Returns a module-level cached PrivacyGuard instance."""
    global _DEFAULT_PRIVACY_GUARD
    if _DEFAULT_PRIVACY_GUARD is None:
        _DEFAULT_PRIVACY_GUARD = PrivacyGuard()
    return _DEFAULT_PRIVACY_GUARD


def scrub_secrets_from_text(text: str) -> str:
    """
    Comprehensive privacy scrubber for logs, exceptions, and telemetry payloads.
    Guarantees that credentials, tokens, passwords, and sensitive PII are stripped.
    """
    if not text or not isinstance(text, str):
        return "" if text is None else str(text)

    # 1. Strip basic URI credentials (e.g. https://user:pass@host)
    scrubbed = re.sub(r"://([^:\s]+):([^@\s]+)@", r"://\1:[REDACTED_AUTH]@", text)

    # 2. Strip Bearer tokens
    scrubbed = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]{15,}", "Bearer [REDACTED_TOKEN]", scrubbed)

    # 3. Apply full PrivacyGuard redaction (API keys, passwords, JWT, PII, etc.)
    guard = get_privacy_guard()
    res = guard.redact(scrubbed)
    return res.redacted_text

