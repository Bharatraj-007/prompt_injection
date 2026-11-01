# MODEL ACCURACY AND SECURITY PERFORMANCE REPORT

**Project:** Hybrid AI Prompt Injection Detection and Defense Platform  
**Evaluation Dataset:** `clean_test_unseen.csv` (1,536 samples: 760 benign, 776 attack)  
**Production Checkpoint:** `D:\prompt_injection\models\prompt_injection_detector\model.safetensors`  
**Threshold:** `BLOCK_THRESHOLD = 0.6`  

---

## 1. Comparative Confusion Matrix: Transformer-Only vs. Full Hybrid Pipeline

| Architecture | Total | TP | TN | FP | FN | Accuracy | Precision | Recall | Specificity | FPR | FNR | F1 Score | Balanced Acc | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Transformer-Only (Layer 3)** | 1536 | 741 | 760 | 0 | 35 | 97.72% | 1.0000 | 95.49% | 100.00% | 0.00% | 4.51% | 0.9769 | 0.9774 | 0.9997 |
| **Full Hybrid Pipeline (Layers 1-4)** | 1536 | 753 | 760 | 0 | 23 | 98.50% | 1.0000 | 97.04% | 100.00% | 0.00% | 2.96% | 0.9850 | 0.9852 | 0.9997 |

---

## 2. Key Performance Observations

1. **Defense-in-Depth Advantage:** The Full Hybrid Pipeline delivers higher recall (97.04% vs. 95.49%) compared to the standalone transformer, successfully catching encoded and rule-based prompt overrides.
2. **False Positive Rate:** The FPR on unseen benign inputs is **0.00%**, preserving usability on general-purpose chat while maintaining robust attack blocking.
3. **Primary Trigger Distribution:** For confirmed attacks, Layer 2 Intent Rules account for fast pre-filtering, while Layer 3 DistilBERT detects semantic jailbreaks and nuanced variations.

---

## 3. Category-by-Category Evaluation Breakdown (Categories A to T)

| Category | Type | Samples | Blocked | Allowed | Mean Score | Metric | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A. Direct prompt injection** | Attack | 3 | 3 | 0 | 0.9989 | 100.0% Recall | `PASS` |
| **B. Indirect prompt injection** | Attack | 2 | 2 | 0 | 0.9987 | 100.0% Recall | `PASS` |
| **C. System prompt extraction** | Attack | 3 | 3 | 0 | 0.9351 | 100.0% Recall | `PASS` |
| **D. Developer instruction extraction** | Attack | 3 | 3 | 0 | 0.9981 | 100.0% Recall | `PASS` |
| **E. DAN jailbreak** | Attack | 2 | 2 | 0 | 0.9970 | 100.0% Recall | `PASS` |
| **F. Roleplay jailbreak** | Attack | 2 | 2 | 0 | 0.9878 | 100.0% Recall | `PASS` |
| **G. Base64 obfuscation** | Attack | 2 | 2 | 0 | 1.0000 | 100.0% Recall | `PASS` |
| **H. Unicode and homoglyph attacks** | Attack | 2 | 2 | 0 | 1.0000 | 100.0% Recall | `PASS` |
| **I. Multilingual attacks** | Attack | 2 | 2 | 0 | 0.9985 | 100.0% Recall | `PASS` |
| **J. Fragmented multi-turn attacks** | Benign | 2 | 2 | 0 | 0.8093 | 0.0% Specificity | `FALSE_POSITIVE` |
| **K. Crescendo attacks** | Attack | 3 | 0 | 3 | 0.0041 | 0.0% Recall | `FAIL` |
| **L. Document-embedded attacks** | Attack | 1 | 1 | 0 | 0.9980 | 100.0% Recall | `PASS` |
| **M. Technical and cybersecurity questions** | Benign | 3 | 0 | 3 | 0.0224 | 100.0% Specificity | `PASS` |
| **N. Normal instruction-following requests** | Benign | 2 | 0 | 2 | 0.0032 | 100.0% Specificity | `PASS` |
| **O. Benign coding questions** | Benign | 2 | 0 | 2 | 0.0016 | 100.0% Specificity | `PASS` |
| **P. Arithmetic and simple calculations** | Benign | 3 | 0 | 3 | 0.0011 | 100.0% Specificity | `PASS` |
| **Q. Long documents** | Benign | 1 | 0 | 1 | 0.1671 | 100.0% Specificity | `PASS` |
| **R. Empty and malformed inputs** | Benign | 3 | 0 | 3 | 0.0868 | 100.0% Specificity | `PASS` |
| **S. Oversized inputs** | Benign | 1 | 1 | 0 | 0.9912 | 0.0% Specificity | `FALSE_POSITIVE` |
| **T. Unknown or ambiguous requests** | Benign | 1 | 0 | 1 | 0.0019 | 100.0% Specificity | `PASS` |
