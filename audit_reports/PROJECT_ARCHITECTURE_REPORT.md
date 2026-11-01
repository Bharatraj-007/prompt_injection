# STEP 4D.18 — PROJECT ARCHITECTURE REPORT

**Project**: Multi-layer Prompt Injection Detection & Defense System  
**Directory**: `D:\prompt_injection`  
**Audit Timestamp**: 2026-10-30T12:00:53+0530  
**Architecture Status**: **AUDITED & VERIFIED**  

---

## 1. Executive Architectural Overview

The repository implements a defensive, multi-layer security architecture designed to detect, analyze, and neutralize both direct and obfuscated prompt injection attacks targeting Large Language Models (LLMs). The project combines deterministic heuristics, normalization layers, a fine-tuned sequence classification transformer, cryptographic canary token exfiltration guards, and an optional LLM-as-a-Judge escalation layer.

```
+--------------------------------------------------------------------------+
|                        Raw Input Prompt / Payload                        |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| Layer 1: Normalization & Preprocessing (NFKC, Hidden Chars, Base64/Hex)  |
+--------------------------------------------------------------------------+
                  |                         |                         |
                  v                         v                         v
+-------------------------+   +-------------------------+   +-------------------------+
| Layer 2: Rule Filter    |   | Layer 3: Transformer    |   | Layer 7: LLM as a Judge |
| (9 Regex Heuristics)    |   | (DistilBERT Sequence    |   | (Groq / xAI / Local GPU)|
| w >= 0.85               |   |  Classification on CUDA)|   | (High-Intelligence)    |
+-------------------------+   +-------------------------+   +-------------------------+
                  \                         |                         /
                   \                        |                        /
                    v                       v                       v
+--------------------------------------------------------------------------+
| Layer 4: Multi-Layer Score Fusion (Noisy-OR Probabilistic Ensemble)      |
| Decision Rule: score >= BLOCK_THRESHOLD (0.60) -> BLOCKED / ALLOWED      |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| Layer 5: Dynamic Canary Hardening (Demarcation & Cryptographic Token)    |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| Target LLM Generation Step (Protected Prompt Execution)                 |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| Layer 6: Output Guard Verifier (Canary Egress & System Prompt Audit)     |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| Final System Response (Sanitized Output / Security Alert)                |
+--------------------------------------------------------------------------+
```

---

## 2. Component & Technology Inventory

| Layer / Subsystem | Primary Technologies | Architecture Pattern | Source Files |
| :--- | :--- | :--- | :--- |
| **Frontend UI** | Streamlit 1.25+, HTML5, CSS3 | Single-Page Application (SPA) with reactive component rerendering | `app.py`, `.streamlit/config.toml` |
| **Backend Core** | Python 3.11, PyTorch, Transformers | Pipeline Pattern, Layered Defense-in-Depth | `guard.py`, `config.py` |
| **Transformer Classifier** | DistilBERT (66M params), CUDA | Sliding-Window Sequence Classification with Multi-View max pooling | `models/prompt_injection_detector/model.safetensors` |
| **LLM Judge Client** | Groq SDK, OpenAI SDK, HuggingFace | Multi-Backend Strategy / Factory Pattern | `llm_judge.py`, `evaluate_llm_judge.py` |
| **Dataset & Contamination** | DataSketch (MinHash LSH), Pandas, Scikit-learn | LSH Deduplication & Cross-Split Quarantine | `minhash_audit.py`, `data_prep.py` |
| **Evaluation Suite** | Pytest, Wilson Score CI, KaTeX | Automated Regression & Statistical Significance Testing | `tests/*.py`, `evaluate.py` |
| **Build & Environment** | Pip, Conda (`environment.yml`), `package.json` | Pinned Dependency Lockfiles | `requirements.txt`, `requirements-frozen.txt` |

---

## 3. Subsystem Breakdown

### 3.1 Frontend Web Layer (`app.py`)
- Built using **Streamlit**, providing a responsive dashboard.
- Main layout contains an interactive input column and a real-time defense analysis column.
- Features 7 distinct inspection tabs representing each defense layer (L1 Preprocessing, L2 Rules, L3 Classifier, L4 Score Fusion, L5 Canary, L6 Output Guard, L7 LLM Judge).

### 3.2 Backend Pipeline (`guard.py`)
- Encapsulates `PromptGuardPipeline` which instantiates and coordinates:
  - `Layer1Preprocessor`: NFKC Unicode normalization, zero-width character stripping, spaced-letter collapsing, leetspeak mapping, and recursive Base64/Hex payload extraction.
  - `Layer2RuleFilter`: 9 compiled regex rules targeting system overrides, jailbreak roleplay, instruction extraction, delimiter manipulation, and multilingual attacks.
  - `Layer3TransformerClassifier`: DistilBERT model operating with sliding-window inference (128 token windows, 32 stride) and multi-view representation pooling ($\max(p_{\text{raw}}, p_{\text{norm}}, p_{\text{aug}})$).
  - `Layer4ScoreFusion`: Probabilistic Noisy-OR formula: $S = 1 - (1 - r)(1 - m)$ evaluated against calibrated decision threshold $\tau = 0.60$.
  - `Layer5CanaryHardener`: Generates 128-bit cryptographic hex canary tokens embedded in strict XML demarcation blocks (`<system_instructions>`, `<untrusted_user_input>`).
  - `Layer6OutputGuard`: Detects canary leaks, token substring exfiltration, and system prompt marker exposure in LLM responses.
  - `Layer7LLMJudge`: Escalation engine supporting cloud inference (Groq `qwen/qwen3.8-27b`, xAI Grok `grok-2-latest`), local GPU, or offline heuristic fallback.

### 3.3 Configuration Subsystem (`config.py`)
- Centralized configuration enforcing type constraints, deterministic seed constants, model directories, and fallback policies without environment variable mutation.
