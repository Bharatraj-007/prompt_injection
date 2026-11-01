# STEP 5.1A — BENIGN PROMPT FALSE POSITIVE INVESTIGATION FINAL REPORT

**Milestone:** Step 5.1A — Benign Prompt False Positive Investigation  
**Project Directory:** `D:\prompt_injection`  
**Date & Time:** October 30, 2026 — 13:16:00 UTC+05:30  
**Mode:** READ-ONLY INVESTIGATION (Strictly zero code, model, or config modifications)  
**Overall Status:** **INVESTIGATION COMPLETE & ROOT CAUSE IDENTIFIED**

---

## 1. Problem Statement

Harmless mathematical and conversational inputs (e.g. `1+1`) were observed being blocked in the Guarded AI Chat application with a risk score of `0.9685` attributed to Layer 3 DistilBERT Transformer. Simultaneously, a visual discrepancy was observed in the UI between the production threshold (`0.60`) and the sidebar slider (`0.15`).

---

## 2. Root Cause Classification

$$\mathbf{ROOT \quad CAUSE: \quad Model \quad Classification \quad Issue \quad (Micro-Sequence \quad Length \quad Bias)}$$

### Primary Factors:
1. **Model Classification Issue (Primary Driver):**
   - The production DistilBERT sequence classifier (`models/prompt_injection_detector/model.safetensors`, SHA-256 `b5d574ff...`) was trained on benign datasets (Alpaca, Dolly, SQuAD) where **100% of benign training samples were complete natural English sentences (minimum length: 11 characters, mean: 132.5 characters)**.
   - Micro-tokens, isolated operators, and short symbolic expressions in the training data appeared exclusively as adversarial delimiters (e.g. `<PQ> <NED>`, `<|im_end|>`) or inside injection samples (such as few-shot injection prompts containing `"input: 1 + 1\noutput: 2..."` and obfuscated attacks `"wh?t ?s the result of ????????(""1+1"")"`, all labeled `1`).
   - Consequently, when the model evaluates isolated strings under 6 characters (e.g. `1+1`, `2+2`, `hi`, `x+y`), it lacks conversational context and projects the sequence into the adversarial embedding space, producing a probability of `0.9685` for Class 1.
   - When natural context is present (e.g. `What is 2+2?`, `Calculate 15 multiplied by 4.`, `What is artificial intelligence?`), the model correctly predicts benign with scores $\le 0.0064$.

2. **Threshold Inconsistency (Secondary UI Ambiguity):**
   - The sidebar slider in `app.py` directly mutates `guard.layer4.threshold` in memory at runtime.
   - When the user moved the slider to `0.15`, subsequent chat turns captured `threshold = 0.15` in `st.session_state["chat_turns"]`, while earlier turns retained `threshold = 0.60`.
   - The underlying production configuration `config.py` remained unchanged at `BLOCK_THRESHOLD = 0.60`.

---

## 3. Deliverables Summary

All five requested deliverables have been generated in `scratch\step5_1a_false_positive_investigation\`:
1. [FALSE_POSITIVE_ROOT_CAUSE.md](file:///d:/prompt_injection/scratch/step5_1a_false_positive_investigation/FALSE_POSITIVE_ROOT_CAUSE.md): Comprehensive step-by-step trace of `1+1` through all 7 pipeline layers.
2. [THRESHOLD_INCONSISTENCY_REPORT.md](file:///d:/prompt_injection/scratch/step5_1a_false_positive_investigation/THRESHOLD_INCONSISTENCY_REPORT.md): In-depth reconciliation of the `0.60` vs `0.15` threshold discrepancy and session-state mechanics.
3. [BENIGN_PROMPT_DIAGNOSTICS.csv](file:///d:/prompt_injection/scratch/step5_1a_false_positive_investigation/BENIGN_PROMPT_DIAGNOSTICS.csv): Structured results table for the 10 diagnostic benign prompts.
4. [MODEL_SCORE_ANALYSIS.md](file:///d:/prompt_injection/scratch/step5_1a_false_positive_investigation/MODEL_SCORE_ANALYSIS.md): Checkpoint verification, probability calibration check, and micro-sequence sensitivity analysis.
5. [STEP5_1A_FINAL_REPORT.md](file:///d:/prompt_injection/scratch/step5_1a_false_positive_investigation/STEP5_1A_FINAL_REPORT.md): This summary report.

---

## 4. Verification of Strict Safety Constraints

- **Production code:** 0 modifications.
- **Model weights:** 0 modifications. SHA-256 confirmed unchanged: `B5D574FF13F79A7D3B6BD76E387B216644C47BCE1AF761D15C58FD868519D1BA`.
- **Production threshold:** `BLOCK_THRESHOLD = 0.60` confirmed unchanged.
- **Protected datasets:** Zero access to `sealed_benchmark_v2.csv` or protected test sets.
- **Git state:** Zero commits, staging (`git diff --cached` empty), stashing, or history modifications.
- **External API calls:** Zero external API calls made.

---

## 5. Next Steps

In accordance with strict safety instructions:
- **No fixes or code modifications have been made.**
- All evidence has been documented and verified.
- Awaiting explicit authorization before implementing any remediation.
