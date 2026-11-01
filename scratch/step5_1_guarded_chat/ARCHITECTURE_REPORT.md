# Phase 1: Application Architecture Assessment & Integration Plan

**Milestone:** Step 5.1 — Guarded AI Chat Implementation  
**Project:** Multi-layer Prompt Injection Detection & Defense System (`D:\prompt_injection`)  
**Date:** October 30, 2026  
**Status:** COMPLETE & VERIFIED

---

## 1. Executive Summary

This architecture assessment evaluates the transition of the Prompt Injection Detection & Defense System from a single-prompt diagnostic inspection utility into an interactive, end-to-end **Guarded AI Security Chat** application. The existing 7-layer defense pipeline remains the primary gatekeeper: all untrusted user inputs are inspected before they can reach upstream Large Language Models (LLMs), and all generated outputs are audited by Layer 6 Output Guard before being presented to the user.

---

## 2. Existing System Architecture

The existing system consists of the following components:

```
Untrusted User Prompt
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ 7-Layer Hybrid Security Pipeline (PromptGuardPipeline)      │
│                                                             │
│  Layer 1: Preprocessing & Obfuscation Normalization         │
│           (Unicode NFKC, Whitespace repair, Base64/Hex/URL) │
│                                                             │
│  Layer 2: Heuristic Regex Rule Filter                       │
│           (Override, Jailbreak DAN, Extraction, Delimiters) │
│                                                             │
│  Layer 3: DistilBERT Sequence Classifier (Fine-Tuned)       │
│           (Arm C Seed 42 Production Checkpoint)             │
│                                                             │
│  Layer 4: Probabilistic Noisy-OR Fusion Engine             │
│           (Threshold = 0.60, Block vs Allow Decision)       │
│                                                             │
│  Layer 5: Dynamic Canary Token Hardener                     │
│           (Embeds HMAC/Hex canary into system prompt)       │
│                                                             │
│  Layer 7: LLM as a Judge (Secondary/Arbiter)               │
│           (Groq Cloud, xAI Grok, Local RTX 4050 GPU)        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                Decision Gating: is_blocked?
               ┌───────────────┴───────────────┐
             BLOCKED                         ALLOWED
               │                               │
               ▼                               ▼
       Neutralize Prompt             Forward to AI Provider
       (AI NEVER CALLED)              (Groq, OpenAI, Anthropic, Local)
                                               │
                                               ▼
                                      Generated Response
                                               │
                                               ▼
                                  ┌─────────────────────────┐
                                  │ Layer 6: Output Guard   │
                                  │  - Canary Leak Check    │
                                  │  - System Prompt Audit  │
                                  │  - Execution Markers    │
                                  └────────────┬────────────┘
                                               │
                                       is_safe?
                                      ┌────────┴────────┐
                                    SAFE             LEAK DETECTED
                                      │                 │
                                      ▼                 ▼
                                Deliver Safe       Redact & Alert
                                 AI Answer          (Data Shield)
```

### Key Modules:
- `guard.py`: Implements `PromptGuardPipeline.inspect_and_defend()`. Coordinates Layers 1–5, 7.
- `llm_judge.py`: Implements `create_llm_judge()` with Groq, xAI Grok, Local GPU, and Fallback backends.
- `config.py`: Single source of truth for `BLOCK_THRESHOLD = 0.60`, `MODEL_DIR`, and API keys.
- `app.py`: Streamlit frontend.

---

## 3. Integration Points

To avoid duplicate security pipelines or unnecessary module rewrites, three clean integration touchpoints were designed:

1. **AI Provider Interface (`ai_provider.py`)**:
   - `BaseAIProvider`: Abstract base class defining `generate(messages, model, **kwargs) -> AIResponse`.
   - Implementations: `GroqProvider`, `OpenAIProvider`, `AnthropicProvider`, `LocalLLMProvider`, `MockAIProvider`.
   - `AIProviderFactory`: Instantiates configured providers and verifies readiness without executing live calls.

2. **Guarded Chat Orchestration Engine (`guarded_chat.py`)**:
   - `GuardedChatEngine`: Ties together `PromptGuardPipeline`, `BaseAIProvider`, and `Layer6OutputGuard`.
   - Manages stateful conversation turns (`GuardedChatTurn`).
   - Guarantees fail-closed behavior: if any layer raises an unexpected exception, the request is blocked and the AI provider is never called.

3. **Streamlit Multi-Mode Navigation (`app.py`)**:
   - Preserves 100% of existing deep diagnostic views in Tab 2 ("🔬 Deep Pipeline Inspection").
   - Implements the new user-facing chat in Tab 1 ("💬 AI Security Chat").
   - Shared cached resources (`load_guard`, `get_cached_judge`) eliminate duplicate memory allocation.

---

## 4. Security Invariants Preserved

1. **Fail-Closed Execution**: If any inspection module errors, the decision defaults to `BLOCKED` (`risk_score = 1.0`).
2. **Strict Pre-Execution Gating**: If `decision == "BLOCKED"`, `ai_provider.generate()` is bypassed entirely.
3. **Layer 6 Output Verification**: Allowed model responses must pass canary check and system prompt leakage audit.
4. **Frozen Model Protection**: Production checkpoint weights (`models/prompt_injection_detector/model.safetensors`, SHA-256 `B5D574FF13F79A7D3B6BD76E387B216644C47BCE1AF761D15C58FD868519D1BA`) and threshold (`0.60`) remain strictly unmodified.
