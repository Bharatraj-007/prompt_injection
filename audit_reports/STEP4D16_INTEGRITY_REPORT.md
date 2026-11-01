# STEP 4D.16 — PRODUCTION INTEGRITY REPORT

**Milestone**: Step 4D.16  
**Timestamp**: 2026-10-30T11:44:42+0530  
**Status**: **VERIFIED BITWISE**  

---

## 1. Checkpoint Verification
- **Target File**: `D:\prompt_injection\models\prompt_injection_detector\model.safetensors`
- **Observed SHA-256**: `b5d574ff13f79a7d3b6bd76e387b216644c47bce1af761d15c58fd868519d1ba`
- **Expected SHA-256**: `b5d574ff13f79a7d3b6bd76e387b216644c47bce1af761d15c58fd868519d1ba`
- **Verification Status**: **PASS (BITWISE MATCH)**

## 2. Threshold Verification
- **Target File**: `D:\prompt_injection\config.py`
- **Observed BLOCK_THRESHOLD**: `0.6`
- **Expected BLOCK_THRESHOLD**: `0.60`
- **Verification Status**: **PASS (EXACT MATCH)**

## 3. Application Initialization
- **Layer 1 Preprocessor**: Confirmed operational.
- **Layer 2 Heuristic Rules**: 9 active regex rules verified.
- **Layer 3 Transformer**: DistilBERT sequence classifier verified loaded on CUDA device.
- **Layer 4 Score Fusion**: Noisy-OR formula active at threshold 0.60.
- **Multi-View Escalation**: Raw, normalized, and decoded views verified active.
