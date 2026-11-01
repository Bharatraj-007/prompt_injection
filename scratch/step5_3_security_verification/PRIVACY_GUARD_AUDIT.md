# FEATURE B — PII & PASSWORD REDACTION AUDIT REPORT

**Audit Date:** 2026-10-30  
**Target Module:** `privacy_guard.py`  
**Classification:** READ-ONLY INDEPENDENT VERIFICATION  
**Auditor:** Step 5.3 Automated & Architecture Security Verification  

---

## 1. Executive Summary

Feature B (`privacy_guard.py`) provides deterministic PII, credential, and financial information redaction designed to protect user secrets from leaking to upstream AI providers, databases, and logs. It incorporates regular expression matching for 10+ token types and algorithmic credit card validation via the Luhn checksum algorithm.

Our audit verified that sensitive credentials matching standard patterns (passwords with prefixes, phone numbers, Groq API keys, GitHub tokens, Slack tokens, AWS keys, JWT tokens, RSA private keys, and bank accounts) are cleanly masked. However, regex coverage gaps were identified for modern API key formats containing hyphens (`sk-proj-...`, `sk-ant-api03-...`), AI Studio keys (`AIzaSy...`), natural-language password phrases, and new top-level domains (>7 characters).

---

## 2. Verification Checklist & Empirical Results

| Verification Category | Synthetic Test Input | Expected Behavior | Observed Result | Audit Status |
| :--- | :--- | :--- | :--- | :--- |
| **Passwords (Explicit syntax)** | `password: SecretPass123!` | Redacted to `[REDACTED_PASSWORD]` | Redacted cleanly | **VERIFIED** |
| **Passwords (Natural syntax)** | `User password is Password123!_Secret in database.` | Redacted to `[REDACTED_PASSWORD]` | Unmasked (requires `my password is` or `:`) | **FINDING B-01** |
| **Phone Numbers** | `+1-555-123-4567` | Redacted to `[REDACTED_PHONE]` | Redacted cleanly | **VERIFIED** |
| **Standard Emails** | `analyst.audit@security-eval.org` | Redacted to `[REDACTED_EMAIL]` | Redacted cleanly | **VERIFIED** |
| **Long TLD Emails** | `analyst.audit@security-eval.internal` | Redacted to `[REDACTED_EMAIL]` | Unmasked (TLD regex limited to `{2,7}`) | **FINDING B-02** |
| **Groq API Keys** | `gsk_` + 52 alphanumeric | Redacted to `[REDACTED_API_KEY:GROQ]` | Redacted cleanly | **VERIFIED** |
| **OpenAI Legacy Keys** | `sk-` + 48 alphanumeric | Redacted to `[REDACTED_API_KEY:OPENAI]` | Redacted cleanly | **VERIFIED** |
| **OpenAI Project Keys** | `sk-proj-` + 48 alphanumeric | Redacted to `[REDACTED_API_KEY:OPENAI]` | Unmasked (hyphen in `sk-proj-` rejected) | **FINDING B-03** |
| **Anthropic Legacy Keys** | `sk-ant-` + 48 alphanumeric | Redacted to `[REDACTED_API_KEY:ANTHROPIC]` | Redacted cleanly | **VERIFIED** |
| **Anthropic Sub-Keys** | `sk-ant-api03-` + 48 alphanumeric | Redacted to `[REDACTED_API_KEY:ANTHROPIC]` | Unmasked (second hyphen rejected) | **FINDING B-03** |
| **Gemini AQ Keys** | `AQ.` + 35 alphanumeric/dash | Redacted to `[REDACTED_API_KEY:GEMINI]` | Redacted cleanly | **VERIFIED** |
| **Gemini AIzaSy Keys** | `AIzaSy` + 33 alphanumeric | Redacted to `[REDACTED_API_KEY:GEMINI]` | Unmasked (only `AQ.` prefix registered) | **FINDING B-04** |
| **GitHub Tokens** | `ghp_` + 36 alphanumeric | Redacted to `[REDACTED_API_KEY:GITHUB]` | Redacted cleanly | **VERIFIED** |
| **Slack Tokens** | `xoxb-123456789012-1234567890123-...` | Redacted to `[REDACTED_API_KEY:SLACK]` | Redacted cleanly | **VERIFIED** |
| **AWS Access Keys** | `AKIAIOSFODNN7EXAMPLE` | Redacted to `[REDACTED_API_KEY:AWS_ACCESS_KEY]` | Redacted cleanly | **VERIFIED** |
| **JWT Tokens** | Standard 3-part Base64 URL token | Redacted to `[REDACTED_JWT_TOKEN]` | Redacted cleanly | **VERIFIED** |
| **Private Keys** | `-----BEGIN RSA PRIVATE KEY-----...` | Redacted to `[REDACTED_PRIVATE_KEY]` | Redacted cleanly | **VERIFIED** |
| **Valid Credit Card** | `4532-0151-1283-0366` (Luhn valid) | Redacted to `[REDACTED_CREDIT_CARD]` | Redacted cleanly | **VERIFIED** |
| **Bank Account / IBAN** | `GB82WEST12345698765432` | Redacted to `[REDACTED_BANK_ACCOUNT]` | Redacted cleanly | **VERIFIED** |
| **Benign Preserv.** | `Binary search runs in O(log n) time complexity.` | Text unmodified | Unmodified (`True`) | **VERIFIED** |

---

## 3. Detailed Audit Findings

### Finding B-01: Natural Language Password Pattern Gap (MEDIUM)
- **Severity:** MEDIUM
- **Affected File:** `privacy_guard.py`, Lines 88-91
- **Evidence:** `PASSWORD_PATTERNS` matches `password\s*[:=]` and `my password is`. Phrases such as `"User password is Secret123"` or `"Reset password to Secret123"` are not caught.
- **Security Impact:** Plain-text passwords provided in third-person descriptive sentences can leak to upstream providers.
- **Recommended Correction:** Expand regex:
  ```python
  re.compile(r"(?i)\b(?:user\s+)?password\s+(?:is|set\s+to|was)\s+['\"]?([^\s'\",;\.]{4,})['\"]?")
  ```

### Finding B-02: Email Regex Rejects Modern Top-Level Domains (LOW)
- **Severity:** LOW
- **Affected File:** `privacy_guard.py`, Line 96
- **Evidence:** `EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")` restricts TLD to 7 characters. Domains like `.internal`, `.corporation`, `.engineering` fail redaction.
- **Security Impact:** Internal enterprise email addresses may remain unredacted.
- **Recommended Correction:** Update `{2,7}` to `{2,24}`.

### Finding B-03: Modern OpenAI and Anthropic Multi-Hyphen Key Regex (MEDIUM)
- **Severity:** MEDIUM
- **Affected File:** `privacy_guard.py`, Lines 73-75
- **Evidence:**
  `r"\bsk-[a-zA-Z0-9]{20,}\b"` fails on `sk-proj-` because of hyphens.
  `r"\bsk-ant-[a-zA-Z0-9]{20,}\b"` fails on `sk-ant-api03-` because of the second hyphen.
- **Security Impact:** Current-generation OpenAI project keys and Anthropic production keys are not masked before upstream provider forwarding.
- **Recommended Correction:**
  ```python
  (re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"), "[REDACTED_API_KEY:OPENAI]"),
  (re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b"), "[REDACTED_API_KEY:ANTHROPIC]"),
  ```

### Finding B-04: Google AI Studio Key Format Support (LOW)
- **Severity:** LOW
- **Affected File:** `privacy_guard.py`, Line 77
- **Evidence:** Only matches `AQ\.[a-zA-Z0-9_-]{30,}`. The traditional Google Gemini API key format `AIzaSy[0-9A-Za-z_-]{33}` is not covered.
- **Security Impact:** Traditional Google AI Studio keys will not be redacted.
- **Recommended Correction:** Add pattern `(re.compile(r"\bAIzaSy[a-zA-Z0-9_-]{33}\b"), "[REDACTED_API_KEY:GEMINI]")`.

---

## 4. Privacy Invariants Verification

1. **Original Prompt Inspected Before Redaction:** **VERIFIED** — In `guarded_chat.py` and `app.py`, prompt injection detection runs on the unaltered prompt first to avoid masking malicious syntax.
2. **Redacted Prompt Forwarded to AI Provider:** **VERIFIED** — Upstream provider dispatch uses `redacted_prompt`.
3. **No Raw Secrets in Database or Exports:** **VERIFIED** — `SecurityDatabase.log_event` receives `user_prompt_sanitized` containing redacted tokens.

---

## 5. Architectural Verdict for Feature B
**Status:** **FUNCTIONAL WITH REGEX COVERAGE LIMITATIONS (B-01 through B-04)**  
Core engine operates securely and preserves benign text without false positive corruptions. Regex pattern updates recommended for modern key formats.
