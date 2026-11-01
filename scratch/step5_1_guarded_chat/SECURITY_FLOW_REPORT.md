# Phase 3: Guarded Prompt Processing Security Flow Report

**Milestone:** Step 5.1 — Guarded AI Chat Implementation  
**Project:** Multi-layer Prompt Injection Detection & Defense System (`D:\prompt_injection`)  
**Date:** October 30, 2026  
**Status:** COMPLETE & VERIFIED

---

## 1. Six-Step Guarded Execution Sequence

The `GuardedChatEngine.process_turn()` implementation enforces a strict 6-step lifecycle for every user prompt:

```
[ Step 1: Input Validation ]
      │ (Length check <= MAX_INPUT_LENGTH, Empty/Whitespace rejection)
      ▼
[ Step 2: Input Security Inspection ]
      │ (PromptGuardPipeline: L1 Normalization, L2 Regex Rules, 
      │  L3 DistilBERT, L4 Noisy-OR Fusion, L5 Dynamic Canary, L7 LLM Judge)
      ▼
[ Step 3: Security Decision Gating ]
     / \
    /   \  Decision == "BLOCKED" (Risk Score >= 0.60)
   /     \ ───────────────────────────────────────────┐
  │ ALLOW │                                           │
  ▼       ▼                                           ▼
[ Step 4: AI Generation ]                     [ AI NEVER INVOKED ]
  │ (Groq, OpenAI, Anthropic, Local)                  │
  ▼                                                   ▼
[ Step 5: Output Guard Inspection ]           [ Instant Neutralization ]
  │ (Layer 6: Canary leak & System Prompt check)      │ (Red security alert badge)
  ▼                                                   │
[ Step 6: Safe Delivery ]                             │
  │ (Present answer or redacted alert)                │
  └────────────────────────┬──────────────────────────┘
                           ▼
              [ Stateful Turn Completed ]
```

---

## 2. Detailed Step Specifications

### Step 1: Input Validation
- Strips leading and trailing whitespace.
- Empty or whitespace-only inputs are safely rejected immediately without executing neural inference or API calls.
- Enforces maximum character bounds (`MAX_INPUT_LENGTH = 10000`).

### Step 2: Input Security Inspection
- Invokes `PromptGuardPipeline.inspect_and_defend()`.
- Preprocesses and decodes obfuscations (Base64, Hex, URL, Leetspeak, Unicode).
- Evaluates Heuristic Rule filters (direct overrides, DAN jailbreaks, instruction extraction).
- Performs transformer classification using production DistilBERT weights (`Arm C Seed 42`).
- Fuses probabilistic scores via Noisy-OR combination.
- Calculates dynamic HMAC/hex canary token for Layer 5.
- Intercepts with Layer 7 LLM Judge if enabled.
- Records fine-grained timing in milliseconds.

### Step 3: Security Decision Gating
- Gating condition: `is_blocked = (decision == "BLOCKED")` (Risk $\ge 0.60$).
- **CRITICAL INVARIANT:** If `is_blocked` is True:
  - `ai_provider.generate()` is **never called** (`mock_ai.call_count == 0`).
  - The malicious prompt is completely isolated.
  - A formatted security alert card is constructed detailing the responsible defense layer, risk score, and threshold.
  - Returns `GuardedChatTurn` immediately.

### Step 4: Upstream AI Generation (Allowed Only)
- Forwarded only when input is deemed benign (`decision == "ALLOWED"`).
- Context is assembled from system prompt + up to 6 recent conversation history turns + the sanitized user prompt.
- Canary token is transmitted in generation parameters.
- Catches timeouts, rate limits, network outages, and credential errors without application crashes.

### Step 5: Layer 6 Output Guard Inspection
- Raw model completion text is inspected by `Layer6OutputGuard.verify()`.
- Verifications performed:
  1. **Dynamic Canary Token Exposure:** Checks if the secret canary token was exfiltrated into output text.
  2. **System Prompt Leakage:** N-gram matching checks for verbatim disclosures of confidential base instructions.
  3. **Adversarial Execution Markers:** Scans for tokens such as `SYSTEM_OVERRIDDEN`, `ACCESS_GRANTED`, or `HACKED`.
- If a leak is detected, `out_sec.is_safe = False`.

### Step 6: Safe Delivery & UI Presentation
- If output passed: Final assistant text is set to the generated content.
- If output failed: Final assistant text is redacted with an `[OUTPUT GUARD: SECURITY LEAK PREVENTED]` notice, protecting system internals from extraction attacks.

---

## 3. Fail-Closed Error Handling

If an unexpected exception occurs inside the security inspection pipeline (e.g. CUDA device timeout, memory bus error, unexpected tokenizer token):
- The exception is trapped in a `try...except` block.
- An alert is logged: `logger.error(...)`.
- `SecurityAnalysis` defaults to:
  - `decision = "BLOCKED"`
  - `is_blocked = True`
  - `risk_score = 1.0`
  - `responsible_layer = "Security Pipeline Fail-Safe"`
- The upstream AI provider is **never called**.
- A safe error notification is shown to the user without exposing python stack traces.
