# STEP 4D.18 — AUTOMATED TEST RESULTS REPORT

**Project**: Multi-layer Prompt Injection Detection & Defense System  
**Test Framework**: Pytest 9.1.1, Python 3.11.9  
**Audit Timestamp**: 2026-10-30T12:00:53+0530  
**Summary**: **111 PASSED / 0 FAILED (100.0% Pass Rate)**  

---

## 1. Test Module Breakdown

| Test File | Test Area | Passed | Failed | Execution Time |
| :--- | :--- | :---: | :---: | :---: |
| `tests/test_boundary_defense.py` | Input length bounds & token boundaries | 4 | 0 | 0.8s |
| `tests/test_evaluation_metrics.py`| Wilson score interval & calibration ECE | 5 | 0 | 0.4s |
| `tests/test_fusion.py` | Noisy-OR mathematical fusion & bounding | 6 | 0 | 0.3s |
| `tests/test_leakage_and_splits.py` | Train/Test split isolation & no duplicates | 4 | 0 | 1.1s |
| `tests/test_llm_judge.py` | LLM Judge backends, JSON recovery, factory | 16 | 0 | 4.2s |
| `tests/test_normalization.py` | Whitespace manipulation & Unicode cleaning | 22 | 0 | 2.1s |
| `tests/test_normalization_fixes.py`| Leetspeak, obfuscation, mixed content | 8 | 0 | 1.8s |
| `tests/test_output_guard.py` | Canary token exfiltration detection | 4 | 0 | 0.6s |
| `tests/test_rules.py` | Layer 2 heuristic regex rules | 8 | 0 | 0.5s |
| `tests/test_stage1_preprocessing_remediation.py` | Technical identifiers, IPv6, ARNs | 14 | 0 | 3.5s |
| `tests/test_step4c4_remediation.py` | Hyphenated attacks & PDF text filtering | 18 | 0 | 6.2s |
| `tests/test_training_safety.py` | Checkpoint weight verification & weights | 2 | 0 | 4.0s |
| **TOTAL** | | **111** | **0** | **25.53s** |
