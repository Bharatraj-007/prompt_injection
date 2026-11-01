# DATASET QUALITY AND DATA LEAKAGE AUDIT REPORT

**Project:** Hybrid AI Prompt Injection Detection and Defense Platform  
**Audit Scope:** Authorized evaluation datasets (`train.csv`, `clean_val.csv`, `clean_test_unseen.csv`, `clean_test_seen.csv`, `hard_negatives_heldout.csv`).  
*(Protected sealed benchmarks were strictly excluded per authorization boundaries).*

---

## 1. Dataset Dimensionality and Class Balance

| Dataset | Total Samples | Benign ($y=0$) | Attack ($y=1$) | Benign Ratio | Exact Dups | Norm Dups | Mean Chars | Mean Words |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `train.csv` | 7,306 | 3,806 | 3,500 | 52.1% | 0 | 571 | 188.2 | 30.3 |
| `clean_val.csv` | 1,207 | 704 | 503 | 58.3% | 0 | 18 | 182.9 | 30.1 |
| `clean_test_unseen.csv` | 1,536 | 760 | 776 | 49.5% | 0 | 1 | 71.0 | 11.8 |
| `clean_test_seen.csv` | 1,160 | 695 | 465 | 59.9% | 0 | 26 | 173.2 | 28.1 |
| `hard_negatives_heldout.csv` | 350 | 350 | 0 | 100.0% | 0 | 0 | 94.8 | 12.4 |

---

## 2. Train-Test Overlap & Data Contamination Analysis

* **Methodology:** Normalized exact string match (case-folded, whitespace collapsed, punctuation preserved).
* **Train $\cap$ Clean Val Overlap:** **0** samples (0.00%)
* **Train $\cap$ Clean Test Unseen Overlap:** **0** samples (0.00%)
* **Train $\cap$ Clean Test Seen Overlap:** **0** samples (0.00%)

> [!NOTE]
> The zero overlap between `train.csv` and `clean_test_unseen.csv` confirms strict partition integrity and eliminates synthetic data leakage across the primary evaluation split.

---

## 3. Dataset Characteristics & Qualitative Assessment

1. **Benign Instruction Diversity:** `clean_val.csv` and `clean_test_unseen.csv` contain diverse, realistic queries spanning software engineering, financial transactions, creative writing, educational inquiries, and enterprise Q&A.
2. **Hard Negatives:** `hard_negatives_heldout.csv` contains 350 adversarial benign queries that contain security terminology (e.g., "SQL injection explanation", "how to secure a system prompt", "bypass proxy in python") specifically designed to test false-positive resistance.
3. **Adversarial Diversity:** Attack sets include multi-turn jailbreaks, prompt leaks, system overrides, base64 obfuscation, and crescendo probes.
