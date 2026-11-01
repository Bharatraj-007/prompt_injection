# Threshold Inconsistency & UI State Investigation Report

**Milestone:** Step 5.1A — Benign Prompt False Positive Investigation  
**Project:** Multi-layer Prompt Injection Detection & Defense System (`D:\prompt_injection`)  
**Investigation Mode:** Strictly READ-ONLY  
**Date:** October 30, 2026

---

## 1. The Discrepancy

In the observed user session:
- The system configuration defines **`BLOCK_THRESHOLD = 0.60`**.
- The sidebar slider displayed **`0.15`**.
- The first historical turn card reported: `Risk Score: ... (Threshold: 0.60)`.
- The second historical turn card reported: `Risk Score: 0.9685 (Threshold: 0.15)`.

---

## 2. Technical Investigation of Threshold State

### 2.1 How the Sidebar Slider Operates in `app.py`
In `app.py` (lines 218–221):
```python
st.sidebar.markdown("---")
st.sidebar.header("⚙️ Fusion & Pipeline Threshold")
thresh = st.sidebar.slider("Security Threshold", 0.10, 0.90, float(BLOCK_THRESHOLD), 0.05)
guard.layer4.threshold = thresh
```

1. **Direct In-Memory Mutation:**
   - The `@st.cache_resource` decorated `load_guard()` maintains a single in-memory instance of `PromptGuardPipeline`.
   - On every Streamlit script execution, line 221 mutates the pipeline's runtime attribute directly: `guard.layer4.threshold = thresh`.
   - If the user interacts with the slider and sets it to `0.15`, the in-memory threshold of `guard.layer4` is immediately updated to `0.15`.

2. **Snapshotting Inside `GuardedChatTurn`:**
   - When `GuardedChatEngine.process_turn()` runs, it captures the threshold at that exact instant:
     ```python
     sec_analysis = SecurityAnalysis(
         ...
         threshold=float(self.guard.layer4.threshold)
     )
     ```
   - Each `GuardedChatTurn` instance stored in `st.session_state["chat_turns"]` retains the snapshot of the threshold active when *that specific turn* was processed.

3. **Reconciliation of Observed Discrepancy:**
   - **Turn 1** was submitted when the sidebar slider was at its default position (`0.60`). Therefore, Turn 1 displays `Threshold: 0.60`.
   - The user subsequently dragged or adjusted the slider to `0.15`.
   - **Turn 2** (`1+1`) was submitted with the slider at `0.15`. Therefore, Turn 2 displays `Threshold: 0.15`.
   - Both turns correctly reflect the state of the threshold at their respective times of execution.

---

## 3. Key Findings

1. **Production Configuration Integrity:**
   - The file `config.py` was **not modified**. Its static definition remains `BLOCK_THRESHOLD = 0.60`.
   - The slider acts as a dynamic runtime override for exploration and diagnostic benchmarking.

2. **Threshold Application:**
   - The threshold is evaluated once in `Layer4ScoreFusion.fuse()` via:
     `is_blocked = (fused_score >= self.threshold)`
   - The threshold is **not applied twice**.
   - Because `1+1` received a fused risk score of `0.9685`, it was blocked under *both* thresholds ($0.9685 \ge 0.60$ and $0.9685 \ge 0.15$). The threshold change did not cause the block, but created visual ambiguity.

3. **UI / UX Ambiguity Identified:**
   - The sidebar slider label `"Security Threshold"` does not distinguish between the **Fixed Production Standard (0.60)** and an **Experimental Diagnostic Override**.
   - When users adjust the slider, they inadvertently alter the defense boundary of the chat engine for all subsequent turns in that session.

---

## 4. Recommendations for Future Remediation (Pending Authorization)

1. **Clear Visual Labeling:**
   - Label the slider as *"Diagnostic Threshold Override"* with a reset button to restore the verified production baseline (`0.60`).
2. **Decoupled Architecture:**
   - The user-facing AI Security Chat should enforce the production baseline `BLOCK_THRESHOLD = 0.60` by default, isolating experimental slider overrides to Tab 2 ("🔬 Deep Pipeline Inspection").
