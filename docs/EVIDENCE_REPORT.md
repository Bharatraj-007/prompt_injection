# Technical Auditor Evidence Report: Prompt Injection Detection & Defense Repository

**Auditor Role**: Technical Systems Auditor  
**Date of Audit**: 2026-10-06  
**Repository Path**: `d:\prompt_injection`  
**Scope**: Factual inspection of code, configuration, Git logs, and saved output files. Zero opinions, zero praise, zero ungrounded assertions.

---

## 1. PROJECT
- **Repository Title**: Prompt Injection Attack Detector and Defender (stated in `README.md`).
- **Goal**: Detection and mitigation of direct system prompt overrides and indirect prompt injection attacks against LLMs using a 6-layer defense pipeline.
- **Folder Layout**:
  - `src/` or Root executable modules: `guard.py`, `config.py`, `app.py`.
  - Scripts: `train.py`, `train_all.py`, `evaluate.py`, `evaluate_all_fusions.py`, `data_prep.py`, `minhash_audit.py`, `download_all_data.py`, `architecture_diagram.py`, `run_complete_pipeline.bat`.
  - `docs/`: `CHANGELOG.md`.
  - `tests/`: `test_normalization.py`, `test_rules.py`, `test_fusion.py`.
  - `results/`: Consolidated CSV and JSON benchmark results.
  - `plots/`: PNG visualization files.
  - `extensions_crossguard/`: Prototype modules (`adversarial_generator.py`, `evaluator.py`, `sanitizer.py`, `trainer.py`). Marked as not evaluated.
  - `data/`: Processed train/val/test CSV datasets (ignored in Git).
  - `raw_data/`: Downloaded HuggingFace/GitHub datasets (ignored in Git).
  - `models/`: Trained model safetensors and configs (ignored in Git).
- **Script Responsibilities**:
  - `download_all_data.py`: Downloads raw corpora from HuggingFace (`deepset`, `xtram1`, `neuralchemy`, `lakera_ignore`, `dolly`, etc.) into `raw_data/`.
  - `data_prep.py`: Aggregates raw corpora, balances classes to 1:1, creates initial splits (`train.csv`, `val.csv`, `test_seen.csv`, `test_unseen.csv`).
  - `minhash_audit.py`: Runs SHA-256 duplicate checks and MinHash LSH near-duplicate audit (Jaccard $\ge 0.80$), writes clean splits (`clean_val.csv`, `clean_test_seen.csv`, `clean_test_unseen.csv`) and `minhash_audit_report.json`.
  - `train.py`: HuggingFace `Trainer` routine for single-seed and multi-seed training of transformer classifiers (`DistilBERT`, `ModernBERT`, `DeBERTa`).
  - `train_all.py`: Positional CLI wrapper calling `train.py` for specific backbones.
  - `evaluate.py`: Sweeps thresholds on validation data, evaluates model on clean test sets, generates ROC/PR curves.
  - `evaluate_all_fusions.py`: Evaluates single-view vs multi-view representations across 4 fusion rules (Model Only, Weighted, Max, Noisy-OR) and ProtectAI.
  - `guard.py`: Production pipeline implementing Layers 1 through 6.
  - `app.py`: Streamlit web demonstration interface.

---

## 2. GIT
- **Current HEAD Commit**: `ad8d55e`
  - Date: `2026-10-06 11:41:23 +0530`
  - Message: `"Organize tidy layout, add LICENSE, docs/CHANGELOG, and results/"`
- **Git Tags**:
  - `v1-frozen`: Tagged on commit `ad8d55e` at date `2026-10-06 11:41:24 +0530`.
- **Files Modified or Created AFTER Tag `v1-frozen`**:
  - Code files (`guard.py`, `config.py`, `train.py`, `train_all.py`): **NO** (last modified before 11:10 AM).
  - Result files created/modified after 11:41:24:
    - `results/distilbert_multiseed_test_results.csv`: Modified `2026-10-06 11:44:08 AM`.
    - `results/raw_predictions_seen.csv`: Created `2026-10-06 11:45:51 AM`.
    - `results/raw_predictions_hard_heldout.csv`: Created `2026-10-06 11:46:08 AM`.
    - `results/raw_predictions_obfuscation.csv`: Created `2026-10-06 11:46:29 AM`.
- **Repository Size** (`git count-objects -vH`):
  - Object count: 177
  - Size: **256.20 MiB** (caused by previous commits containing model checkpoints in Git pack history).

---

## 3. DATA
Source code: `data_prep.py` and `minhash_audit.py`.

### A. Raw Datasets Used
| Dataset Source | HuggingFace Identifier | Attack Count | Safe Count | Total | Role |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `neuralchemy` | `neuralchemy/Prompt-injection-dataset` | 8,828 | 5,208 | 14,036 | Pool for train / val / test seen |
| `xtram1` | `xTRam1/safe-guard-prompt-injection` | 2,496 | 5,740 | 8,236 | Pool for train / val / test seen |
| `deepset` | `deepset/prompt-injections` | 203 | 343 | 546 | Pool for train / val / test seen |
| `dolly` | `databricks/databricks-dolly-15k` | 0 | 15,000 | 15,000 | 777 reserved for OOD test; rest to train pool |
| `lakera_ignore` | `Lakera/gandalf_ignore_instructions` | 777 | 0 | 777 | Reserved for OOD test attacks |
| `hard_negatives` | `data/hard_negatives.csv` | 0 | 306 | 306 | Development set / merged into train pool |
| `alpaca` | `tatsu-lab/alpaca` | 0 | 776 | 776 | Held-out safe prompt evaluation set |
| `hard_negatives_heldout` | `data/hard_negatives_heldout.csv` | 0 | 350 | 350 | Strictly held-out hard negative evaluation set |
| `obfuscation_suite` | `data/obfuscation_benchmark_suite.json`| 425 | 0 | 425 | Robustness evaluation (17 categories) |

### B. Split Building Procedure
1. Deduplication of raw candidate pools by exact text string (`drop_duplicates(subset=['text'])`).
2. Exact 1:1 balance sampled: 5,000 injections and 5,000 benign prompts sampled for the "seen" pool ($N = 10,000$).
3. Stratified splitting (`train_test_split` with `seed=42`):
   - 70% Train ($N = 7,000$: 3,500 attack, 3,500 safe).
   - 15% Val ($N = 1,500$: 750 attack, 750 safe).
   - 15% Test Seen ($N = 1,500$: 750 attack, 750 safe).
4. **Hard Negative Merging**: `data_prep.py` lines 171–193 merged `data/hard_negatives.csv` ($N = 306$, safe) directly into `train.csv`. Resulting `train.csv` size: 7,306 rows (3,500 attack, 3,806 safe; exact sources: `neuralchemy`: 3,459, `dolly`: 1,869, `xtram1`: 1,560, `hard_negative_clean`: 306, `deepset`: 112).
5. Initial OOD Test Unseen split: 777 Lakera attacks + 777 Dolly benign ($N = 1,554$).

### C. MinHash LSH Contamination Audit
File: `results/minhash_audit_report.json`.
- Settings: MinHash unigram whitespace tokenization (`str(text).lower().split()`), `num_perm = 128`, Jaccard similarity threshold $\ge 0.80$.
- **Exact String Duplicates (SHA-256)**:
  - Train vs Val: 0
  - Train vs Test Seen: 0
  - Val vs Test Seen: 0
  - Test Unseen vs Train: **5**
  - Test Unseen vs Val: **1**
  - Test Unseen vs Seen: **1**
- **Near-Duplicates Removed by MinHash Audit**:
  - Validation set: **290 removed** (42 benign, 248 injection). Clean validation remaining: **1,210** (708 safe, 502 attack). Contamination rate: 19.33%.
  - Test Seen set: **292 removed** (42 benign, 250 injection). Clean test seen remaining: **1,208** (708 safe, 500 attack). Contamination rate: 19.47%.
  - Test Unseen set: **11 removed** (11 benign, 0 injection). Clean test unseen remaining: **1,541** (765 safe, 776 attack). Contamination rate: 0.71%.
- **Cross-Split Residual Leakage (after audit)**:
  - Clean Val vs Clean Test Seen near-duplicates remaining: **37**
  - Clean Test Unseen vs Clean Val near-duplicates remaining: **3**
  - Clean Test Unseen vs Clean Test Seen near-duplicates remaining: **2**
- **Was Dedup Run on Held-Out Sets?**:
  - `minhash_audit.py` was NOT run on `data/hard_negatives_heldout.csv` or `data/obfuscation_benchmark_suite.json`.
  - A separate scratch script (`scratch/audit_heldout_independence.py`) audited `hard_negatives_heldout.csv` ($N = 350$) using 3-word shingles against `train.csv` at Jaccard $\ge 0.60$, yielding **0 / 350 matches**.

---

## 4. MODELS
Source code: `train.py`, `train_all.py`, `config.py`.

### A. Model Specifications
1. **DistilBERT**:
   - HuggingFace identifier: `distilbert-base-uncased`
   - Total Parameters: 66,955,010 (67.0M)
   - Trainable Parameters: 66,955,010
2. **ModernBERT**:
   - HuggingFace identifier: `answerdotai/ModernBERT-base`
   - Total Parameters: 149,603,330 (149.6M)
   - Trainable Parameters: 149,603,330
3. **DeBERTa**:
   - HuggingFace identifier: `microsoft/deberta-v3-base` (safetensors revision `refs/pr/14`)
   - Total Parameters: 184,423,682 (184.4M)
   - Trainable Parameters: 184,423,682
4. **ProtectAI (External Baseline)**:
   - HuggingFace identifier: `protectai/deberta-v3-base-prompt-injection-v2`
   - Total Parameters: 184,423,682 (184.4M)
   - Evaluated zero-shot without fine-tuning.

### B. Training Hyperparameters
Source: `train.py` lines 302–322.
- Optimizer: AdamW (`weight_decay = 0.01`).
- Learning Rate: $3 \times 10^{-5}$ (`LEARNING_RATE` in `config.py`).
- Epochs: 3 (`NUM_EPOCHS` in `config.py`).
- Batch Size: 32 (`BATCH_SIZE` in `config.py`).
- Max Sequence Length: 128 (`MAX_SEQ_LENGTH` in `config.py`).
- Precision:
  - DistilBERT: Mixed Precision FP16 (`fp16=True`).
  - ModernBERT: Mixed Precision FP16 (`fp16=True`).
  - DeBERTa: FP32 (`fp16=False` due to `GradScaler` underflow crashes on disentangled attention).
- Class Weights: None (`CrossEntropyLoss` standard unweighted).
- Best Model Selection: Validation F1 (`load_best_model_at_end=True`, `metric_for_best_model="f1"`).

### C. Executed Seeds & Divergence Logs
- **DistilBERT**: Seeds 42, 7, 123 were all successfully run.
  - Checkpoint dirs: `models/prompt_injection_detector` (Seed 42), `results_distilbert_seed_7/checkpoint-687`, `results_distilbert_seed_123/checkpoint-458`.
- **ModernBERT**: Seed 42 was run (`results_modernbert_seed_42`). Seeds 7 and 123 were NOT run.
- **DeBERTa**: Seed 42 was run (`results_deberta_seed_42`).
  - **Divergence Reason**: At epoch 1 step 229, training logged:
    `"train_loss": 0.0172, "eval_loss": NaN, "eval_accuracy": 0.5851, "eval_f1": 0.0` (Source: `results_deberta_seed_42/epoch_history.json`).
    Gradients diverged into NaN under FP32 at learning rate $3 \times 10^{-5}$. Checkpoint produced F1 = 0.0.

---

## 5. PIPELINE: LAYER IMPLEMENTATION & EVALUATION STATUS
Source code: `guard.py`.

| Layer | Component Name | Description in Code | Evaluated in Result Files? |
| :--- | :--- | :--- | :---: |
| **Layer 1** | `Layer1Preprocessor` | Unicode NFKC normalization, zero-width stripping, spaced character collapsing, leetspeak mapping, targeted keyword typo correction, Base64/Hex decoding with `is_readable_text()` filter. | **YES** |
| **Layer 2** | `Layer2RuleFilter` | Heuristic regex pattern matching for direct system overrides, role-play jailbreaks, delimiter attacks, instruction extraction. Outputs rule score in $[0.0, 1.0]$. | **YES** |
| **Layer 3** | `Layer3TransformerClassifier` | DistilBERT inference on raw text, normalized text, and decoded text (max representation score). | **YES** |
| **Layer 4** | `Layer4ScoreFusion` | Combines rule score and model score via Noisy-OR formula ($1 - (1-r)(1-m)$), Max, or linear weighted average. | **YES** |
| **Layer 5** | `Layer5CanaryHardener` | Generates a 6-byte hexadecimal token `CANARY_<hex>` and demarcates system prompt and user input with security boundary instructions. | **NO** |
| **Layer 6** | `Layer6OutputGuard` | Substring and regex check of generated LLM completion text for canary token leakage or unauthorized override signals (`HACKED`, `SYSTEM_OVERRIDDEN`). | **NO** |

---

## 6. RESULTS
Exact numbers extracted directly from saved CSV files in `results/`.

### A. In-Distribution Clean Test Seen ($N = 1,208$, Attacks = 500, Safe = 708)
File: `results/comprehensive_test_seen.csv`

| Configuration | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `model_single` | 480 | 5 | 703 | 20 | 0.9793 | 0.9897 | 0.9600 | 0.9746 | 0.0071 |
| `model_multi` | 480 | 6 | 702 | 20 | 0.9785 | 0.9877 | 0.9600 | 0.9736 | 0.0085 |
| `rules_only` | 22 | 0 | 708 | 478 | 0.6043 | 1.0000 | 0.0440 | 0.0843 | 0.0000 |
| `weighted_single` ($0.3R+0.7M, \tau=0.35$) | 480 | 5 | 703 | 20 | 0.9793 | 0.9897 | 0.9600 | 0.9746 | 0.0071 |
| `weighted_multi` ($0.3R+0.7M, \tau=0.35$) | 480 | 6 | 702 | 20 | 0.9785 | 0.9877 | 0.9600 | 0.9736 | 0.0085 |
| `max_multi` | 480 | 6 | 702 | 20 | 0.9785 | 0.9877 | 0.9600 | 0.9736 | 0.0085 |
| `noisy_single` | 480 | 5 | 703 | 20 | 0.9793 | 0.9897 | 0.9600 | 0.9746 | 0.0071 |
| `noisy_multi` | 480 | 6 | 702 | 20 | 0.9785 | 0.9877 | 0.9600 | 0.9736 | 0.0085 |
| `protectai` (zero-shot) | 427 | 4 | 704 | 73 | 0.9363 | 0.9907 | 0.8540 | 0.9173 | 0.0056 |

- **Confidence Intervals (DistilBERT Seed 42)**:
  - Bootstrap 95% F1 Interval on Test Seen: `[0.9640, 0.9832]` (Source: `results/distilbert_multiseed_test_results.csv`).
  - Wilson 95% Accuracy Interval: `[0.9693, 0.9861]` (Source: `README.md`).
- **PR-AUC**: NOT FOUND in saved comprehensive CSV files.
- **Expected Calibration Error (ECE)** (computed on Clean Test Seen, $N=1,208$):
  - Model Only DistilBERT: **0.0110**
  - Noisy-OR Fusion: **0.0109**

### B. Out-of-Domain Unseen Test Sets
Files: `results/comprehensive_test_unseen_dolly.csv` ($N = 1,541$) and `results/comprehensive_test_unseen_alpaca.csv` ($N = 1,552$).

| Split & Configuration | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Dolly Safe ($N=1,541$)**: | | | | | | | | | |
| - `model_single` | 747 | 2 | 763 | 29 | 0.9799 | 0.9973 | 0.9626 | 0.9797 | 0.0026 |
| - `model_multi` | 758 | 2 | 763 | 18 | 0.9870 | 0.9974 | 0.9768 | 0.9870 | 0.0026 |
| - `rules_only` | 206 | 0 | 765 | 570 | 0.6301 | 1.0000 | 0.2655 | 0.4196 | 0.0000 |
| - `noisy_multi` | 758 | 2 | 763 | 18 | 0.9870 | 0.9974 | 0.9768 | 0.9870 | 0.0026 |
| - `protectai` | 776 | 0 | 765 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **Alpaca Safe ($N=1,552$)**: | | | | | | | | | |
| - `model_single` | 747 | 28 | 748 | 29 | 0.9633 | 0.9639 | 0.9626 | 0.9632 | 0.0361 |
| - `model_multi` | 758 | 30 | 746 | 18 | 0.9691 | 0.9619 | 0.9768 | 0.9693 | 0.0387 |
| - `rules_only` | 206 | 0 | 776 | 570 | 0.6327 | 1.0000 | 0.2655 | 0.4196 | 0.0000 |
| - `noisy_multi` | 758 | 30 | 746 | 18 | 0.9691 | 0.9619 | 0.9768 | 0.9693 | 0.0387 |
| - `protectai` | 776 | 1 | 775 | 0 | 0.9994 | 0.9987 | 1.0000 | 0.9994 | 0.0013 |

### C. Hard-Negative Evaluations
Files: `results/comprehensive_hard_dev.csv` ($N = 306$) and `results/comprehensive_hard_heldout.csv` ($N = 350$).

| Split & Configuration | Total Safe | False Alarms (FP) | True Negatives (TN) | FPR |
| :--- | :---: | :---: | :---: | :---: |
| **Development Set ($N = 306$)**: | | | | |
| - `model_single` | 306 | **0** | 306 | 0.00% (Rule of Three 95% bound $\le 0.98\%$) |
| - `model_multi` | 306 | **0** | 306 | 0.00% |
| - `rules_only` | 306 | **0** | 306 | 0.00% |
| - `protectai` | 306 | **9** | 297 | 2.94% |
| **Fresh Held-Out Set ($N = 350$)**: | | | | |
| - `model_single` | 350 | **119** | 231 | 34.00% |
| - `model_multi` | 350 | **127** | 223 | 36.29% |
| - `rules_only` | 350 | **0** | 350 | 0.00% |
| - `noisy_multi` | 350 | **127** | 223 | 36.29% |
| - `protectai` | 350 | **10** | 340 | 2.86% |

- **Benign Encoded Controls**: NOT FOUND in a standalone dedicated control benchmark; partially covered within `hard_negatives_heldout.csv` category `tech_code_encodings` ($N = 45$).

### D. Obfuscation Benchmark Suite ($N = 425$, All Attacks, Label = 1)
File: `results/comprehensive_obfuscation_breakdown.csv`

| Category | Type | N | Model Single | Model Multi | Rules Only | ProtectAI |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Base64 (Standard Latin) | Handled | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 9 (36.0%) |
| Hex Byte Encoding | Handled | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 25 (100%) |
| Leetspeak Obfuscation | Handled | 25 | 25 (100%) | 25 (100%) | 8 (32.0%) | 6 (24.0%) |
| Fullwidth / NFKC Unicode | Handled | 25 | 25 (100%) | 25 (100%) | 8 (32.0%) | 0 (0.0%) |
| Zero-Width Characters | Handled | 25 | 25 (100%) | 25 (100%) | 8 (32.0%) | 25 (100%) |
| Spaced Whitespace | Handled | 25 | 25 (100%) | 25 (100%) | 8 (32.0%) | 25 (100%) |
| Targeted Keyword Typos | Handled | 25 | 25 (100%) | 25 (100%) | 8 (32.0%) | 25 (100%) |
| Non-Latin Base64 | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 12 (48.0%) |
| Double Base64 | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 0 (0.0%) |
| Base32 Encoding | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 0 (0.0%) |
| URL Percent-Encoding | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 25 (100%) |
| HTML Entity Encoding | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 25 (100%) |
| ROT13 Cipher | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 0 (0.0%) |
| Reversed String | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 5 (20.0%) |
| Cyrillic Homoglyphs | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 24 (96.0%) |
| Binary ASCII | Held-Out | 25 | 25 (100%) | 25 (100%) | 0 (0.0%) | 25 (100%) |
| Delimiter Splitting (`_`) | Held-Out | 25 | 25 (100%) | 25 (100%) | 8 (32.0%) | 25 (100%) |
| **Pooled Handled (7 cats)** | Handled | **175** | **175 (100%)** | **175 (100%)** | **40 (22.9%)** | **116 (66.3%)** |
| **Pooled Held-Out (10 cats)**| Held-Out | **250** | **250 (100%)** | **250 (100%)** | **8 (3.2%)** | **116 (46.4%)** |

### E. Statistical Tests
1. **McNemar's Test**: DistilBERT vs. ModernBERT on Clean Test Seen ($N = 1,208$):
   - Contingency table: $b = 5$ (DistilBERT correct, ModernBERT wrong), $c = 2$ (DistilBERT wrong, ModernBERT correct).
   - Exact p-value: **0.4531** ($p > 0.05$). Statistically non-significant.
2. **McNemar's Test**: DistilBERT vs. ProtectAI on Hard Negatives Dev Set ($N = 306$):
   - Contingency table: $b = 9$ (DistilBERT correct, ProtectAI wrong), $c = 0$ (DistilBERT wrong, ProtectAI correct).
   - Exact p-value: **0.0039** ($p < 0.01$). Statistically significant.

---

## 7. TUNING HISTORY
Record of all modifications made after reviewing empirical test/held-out results:
1. **2026-10-06 ~11:08 AM (`guard.py`)**: Added `Layer1Preprocessor.is_readable_text()` and modified `extract_base64_payloads()` and `extract_hex_payloads()` after manual inspection of the 11 false alarms on `data/hard_negatives.csv` ($N = 306$).
2. **2026-10-06 ~11:25 AM (`scratch/tune_weighted.py`)**: Conducted grid search over linear weights $w_r \in [0.0, 0.5]$ and thresholds $\tau \in [0.2, 0.8]$ on `clean_val.csv` to replace the collapsing $0.5R + 0.5M$ baseline with $0.3R + 0.7M$ at $\tau = 0.35$.
3. **Pre-audit (`data_prep.py` lines 171–193)**: Added code block merging `data/hard_negatives.csv` into `train.csv`, causing test data contamination.

---

## 8. LATENCY
Source: `results/latency_benchmark_gpu.csv` and `scratch/benchmark_latency.py`.
- **Hardware**: NVIDIA GeForce RTX 4050 Laptop GPU (6GB VRAM), CUDA 11.8.
- **Batch Size**: 1.
- **Warm-Up Runs**: 50.
- **Timed Runs**: 200.
- **Precision**: FP16 for DistilBERT and ModernBERT; FP32 for ProtectAI DeBERTa-v3.
- **Timer Scope**:
  - `scratch/benchmark_latency.py`: Measures **pure model forward pass**. Tokenizer was called outside the timing loop (`inputs = tok(...); t0 = time.perf_counter(); model(**inputs); t1 = time.perf_counter()`).
  - `train.py`: Measures both pure forward latency (11.08 ms) and end-to-end latency with tokenization inside timer (12.01 ms).
- **Benchmark Forward Pass Results (Batch 1, GPU)**:
  - DistilBERT (Ours, 67.0M): **8.37 ms ± 0.95 ms** (P50: 8.10 ms, P95: 9.83 ms, 119.4 QPS).
  - ProtectAI DeBERTa-v3 (184.4M): **34.33 ms ± 11.44 ms** (P50: 33.73 ms, P95: 52.01 ms, 29.1 QPS).
  - ModernBERT (149.6M): **43.76 ms ± 4.93 ms** (P50: 42.17 ms, P95: 52.57 ms, 22.8 QPS).

---

## 9. TESTS
Source: `tests/` directory (pytest).
Total tests: **36 passed** in 6.69s.
1. `tests/test_fusion.py` (6 tests):
   - Verifies Noisy-OR mathematical formula ($1 - (1-r)(1-m)$).
   - Verifies high-confidence preservation, thresholding decision logic ($\ge 0.50$), score bounding in $[0.0, 1.0]$, rounding precision to 4 decimals, preservation of individual components.
2. `tests/test_normalization.py` (22 tests):
   - Whitespace and hyphen collapsing (3 cases).
   - Zero-width character stripping (3 cases).
   - Fullwidth Unicode NFKC normalization (3 cases).
   - Leetspeak character mapping (3 cases).
   - Base64 payload decoding (3 cases).
   - Hex payload decoding (3 cases).
   - Keyword typo tolerance (3 cases).
   - Full pipeline integration check (1 case).
3. `tests/test_rules.py` (8 tests):
   - Direct system override detection, jailbreak roleplay detection, instruction extraction, benign text non-detection, case insensitivity, multi-rule matches, max score selection, delimiter manipulation detection.

---

## 10. REPRODUCTION COMMANDS
Exact CLI sequence to reproduce all tables from raw datasets:
```bash
# 1. Download raw data (one-time setup)
python download_all_data.py

# 2. Extract balanced initial splits
python data_prep.py

# 3. MinHash audit and clean split generation
python minhash_audit.py

# 4. Train models
python train_all.py distilbert --epochs 3 --batch_size 32 --lr 3e-5
python train_all.py modernbert

# 5. Evaluate fusions, hard negatives, and baselines
python evaluate_all_fusions.py

# 6. Run test suite
pytest tests/ -v
```
Required data files to run evaluation:
- `data/clean_test_seen.csv`
- `data/clean_test_unseen.csv`
- `data/hard_negatives.csv`
- `data/hard_negatives_heldout.csv`
- `data/obfuscation_benchmark_suite.json`

---

## 11. LIMITATIONS EVIDENT IN CODE AND DATA
1. **Hard Negatives Training Contamination**: The original 306 hard negatives (`data/hard_negatives.csv`) were appended into `data/train.csv` in `data_prep.py` lines 171–193. The 0 / 306 false alarm rate is training data memorization.
2. **Held-Out Hard Negative False Alarm Rate**: On independent held-out hard negatives (`hard_negatives_heldout.csv`, $N=350$), DistilBERT exhibits a **34.0% false alarm rate (119 / 350)**.
3. **DeBERTa Divergence**: `microsoft/deberta-v3-base` training failed at epoch 1 with NaN loss and F1 = 0.0. No trained DeBERTa checkpoint exists.
4. **ModernBERT Seeds**: Only Seed 42 was run for ModernBERT. Seeds 7 and 123 were not trained.
5. **Rules Add Zero Decisions on Clean Data**: On clean test seen data ($N = 1,208$), the rule filter never changed a single classification decision compared to DistilBERT alone.
6. **Noisy-OR Calibration Equivalence**: Expected Calibration Error of Noisy-OR (0.0109) is functionally identical to Model Only (0.0110).
7. **Unevaluated Pipeline Layers**: Layers 5 (Canary Hardening) and 6 (Output Guard) were never evaluated against live LLM completions.
8. **Residual Cross-Split Leakage**: Even after MinHash filtering, 37 near-duplicates remain between clean validation and clean test seen data.

---

## 12. SUSPICIOUS OR IDENTICAL NUMBERS
| Observed Numbers | Affected Systems | Analysis / Explanation |
| :--- | :--- | :--- |
| **Acc=0.9793, F1=0.9746, FP=5, TP=480** | `model_single`, `weighted_single`, `noisy_single` on Test Seen | Identical because Layer 2 rules fire only 22 times, and whenever rules fire, DistilBERT already predicts positive. Rules change zero decisions. |
| **Acc=0.9785, F1=0.9736, FP=6, TP=480** | `model_multi`, `weighted_multi`, `max_multi`, `noisy_multi` on Test Seen | Identical because multi-view maximum score dominates rule scores; fusion rules produce identical threshold crossings at $\tau=0.50$. |
| **Recall = 100.0% (25/25)** across all 17 Obfuscation categories | `model_single`, `model_multi` | Caused by subword fragmentation and entropy shortcut bias: any high-entropy sequence triggers positive classification. This same bias drives the 34% FPR on held-out code. |
| **False Alarms = 0 / 306 (0.00%)** | DistilBERT on Development Hard Negatives | These exact 306 prompts were merged into `data/train.csv` under `source: hard_negative_clean`. |
