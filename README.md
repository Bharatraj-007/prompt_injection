# 🛡️ Empirical Evaluation and Defense Pipeline for Prompt Injection Attacks

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.25+-red.svg)](https://streamlit.io/)
[![Changelog](https://img.shields.io/badge/Changelog-v1--frozen-brightgreen.svg)](docs/CHANGELOG.md)

An empirical research and defense pipeline investigating small transformer classifiers, multi-view representation decoding, deterministic heuristics, and score fusion against direct and obfuscated prompt injection attacks.

---

## 📌 Project Overview
- **Author:** Bharatraj
- **Institution:** SRIHER, Department of BTech AI & Data Science
- **Repository:** `https://github.com/Bharatraj-007/prompt_injection.git`
- **Release Version:** `v1-frozen` (Code frozen before held-out hard-negative and novel obfuscation evaluations)
- **Detailed Audit & Changelog:** See [docs/CHANGELOG.md](docs/CHANGELOG.md)

---

## 🏗️ 6-Layer Architecture Overview

```
                       +---------------------------------------+
                       |           Raw Input Prompt            |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       | Layer 1: Preprocessing & Decoding     |
                       | (NFKC, Hidden Chars, Base64/Hex)      |
                       +---------------------------------------+
                                     /           \
                                    v             v
            +-------------------------------+    +-------------------------------+
            | Layer 2: Rule Filter Engine   |    | Layer 3: Transformer Model    |
            | (Deterministic Regex/Heur.)   |    | (DistilBERT Fine-tuned)       |
            +-------------------------------+    +-------------------------------+
                                    \             /
                                     v           v
                       +---------------------------------------+
                       | Layer 4: Probabilistic Score Fusion   |
                       | Noisy-OR / Validation-Tuned Weighted  |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       | Layer 5: Dynamic Canary Hardening     |
                       | (Demarcation & Cryptographic Token)   |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       | Target LLM Generation Step            |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       | Layer 6: Output Guard Verifier        |
                       | (Egress Check for Leaked Canaries)    |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       |         Final Guarded Output          |
                       |          (ALLOWED / BLOCKED)          |
                       +---------------------------------------+
```

> **Note on Layers 5 & 6**: Layers 1–4 constitute the **pre-LLM ingress firewall** evaluated below. Layers 5 and 6 are modular prompt engineering templates and egress substring verifiers; they do not classify input text and do not require an active LLM generation step for detector benchmarking.
>
> **Note on Extensions**: The `extensions_crossguard/` directory contains experimental future-work prototypes that are not part of the core evaluated pipeline.

---

## 🚀 Quickstart & Reproduction Commands

### Step 1: Environment Setup
```bash
# Clone and enter directory
git clone https://github.com/Bharatraj-007/prompt_injection.git
cd prompt_injection

# Install dependencies (pinned for reproducibility)
pip install -r requirements-frozen.txt
```

### Step 2: Data Preparation & Contamination Audit
```bash
# 1. Download raw benchmark corpora (one-time)
python download_all_data.py

# 2. Extract balanced 1:1 train/val/test splits
python data_prep.py

# 3. MinHash LSH contamination audit (removes Jaccard >= 0.80 near-duplicates)
python minhash_audit.py
```
*Audit finding*: MinHash deduplication removed **250 of 750 (33.3%)** candidate test attacks and 42 of 750 safe prompts that contaminated the training split.

### Step 3: Model Training
```bash
# Train DistilBERT across Seed 42 (reproducible deterministic training)
python train_all.py distilbert --epochs 3 --batch_size 32 --lr 3e-5

# Or train alternative backbones (ModernBERT)
python train_all.py modernbert
```

### Step 4: Run Tests & Evaluation
```bash
# 1. Run unit tests
pytest tests/ -v

# 2. Run full evaluation across seen, unseen, and hard-negatives
python evaluate.py

# 3. Run interactive web application
streamlit run app.py
```

---

## 📊 Empirical Findings & Benchmark Results

### 1. In-Distribution Clean Test Set ($N = 1,208$)
*Hardware: NVIDIA RTX 4050 Laptop GPU (6GB), CUDA 11.8*

| Defense Approach | Accuracy | Precision | Recall | F1-Score | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Rules Only (Layer 2)** | 0.6043 | 1.0000 | 0.0440 | 0.0843 | **0.00%** |
| **Model Only (Single-View)** | **0.9793** | 0.9897 | 0.9600 | **0.9746** | 0.71% |
| **Model Only (Multi-View)** | 0.9785 | 0.9877 | 0.9600 | 0.9736 | 0.85% |
| **Weighted Average ($0.3R + 0.7M$)** | **0.9793** | 0.9897 | 0.9600 | **0.9746** | 0.71% |
| **Noisy-OR Fusion (Multi-View)** | 0.9785 | 0.9877 | 0.9600 | 0.9736 | 0.85% |
| **Baseline: ProtectAI (Zero-Shot)** | 0.9363 | 0.9907 | 0.8540 | 0.9173 | 0.56% |

**Key Takeaways**:
- **Rules add zero decision changes on clean data**: DistilBERT alone caught 480 of 500 attacks and produced 5 false alarms out of 708 benign prompts.
- **Model Comparison**: DistilBERT ($F_1 = 0.9746$) and ModernBERT ($F_1 = 0.9717$) are statistically comparable (McNemar's test $p = 0.4531$, not significant).
- **Calibration**: Expected Calibration Error (ECE) is identical for Model Only ($0.0110$) and Noisy-OR ($0.0109$).

---

### 2. Out-of-Domain Unseen Test Sets

| Test Split | Defense Model | Accuracy | Recall | F1-Score | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Lakera Attacks + Dolly OOD** ($N=1,541$) | Model Single-View | 0.9799 | 0.9626 | 0.9797 | 0.26% |
| | Multi-View Pipeline | 0.9870 | **0.9768** | 0.9870 | 0.26% |
| | ProtectAI (Zero-Shot) | **1.0000** | **1.0000** | **1.0000** | **0.00%** |
| **Lakera Attacks + Alpaca OOD** ($N=1,552$) | Model Single-View | 0.9633 | 0.9626 | 0.9632 | 3.61% |
| | Multi-View Pipeline | 0.9691 | **0.9768** | 0.9693 | 3.87% |
| | ProtectAI (Zero-Shot) | **0.9994** | **1.0000** | **0.9994** | **0.13%** |

*Note*: Replacing Dolly benign prompts with Alpaca (never seen in training) reveals a higher out-of-domain false positive rate ($0.26\% \to 3.61\%$). ProtectAI evaluated zero-shot demonstrates strong generalization on plain semantic text.

---

### 3. Hard-Negative Evaluation: Development vs. Held-Out Sets

| Dataset | Sample Types | Single-View FPs | Multi-View FPs | ProtectAI FPs |
| :--- | :--- | :---: | :---: | :---: |
| **Development Set** ($N=306$) | Benign edge cases inspected during error analysis | **0 / 306 (0.0%)** | **0 / 306 (0.0%)** | 9 / 306 (2.94%) |
| **Held-Out Set** ($N=350$) | UUIDs, hashes, long compound words, serials, base64 code | 119 / 350 (34.0%) | 127 / 350 (36.3%) | **10 / 350 (2.86%)** |

**Error Analysis Insight**:
- On the **development set**, adding `is_readable_text()` eliminated naive Base64 decodes of ordinary words like *aerodynamicist*, reducing false alarms from 11 to 0.
- On the **fresh held-out set** ($N=350$, verified 0 near-duplicates with train data), DistilBERT's reliance on high-entropy token shortcuts triggered 119 false alarms when encountering technical code, cryptographic hashes, and UUIDs. ProtectAI's contextual pre-training avoided this trap (only 10 false alarms).

---

### 4. Obfuscation Benchmark Suite ($N = 425$ across 17 Categories)

| Category Group | Obfuscation Vector | Model Single-View | Multi-View / Noisy-OR | ProtectAI (DeBERTa) |
| :--- | :--- | :---: | :---: | :---: |
| **Handled Obfuscations** | Base64 (Standard Latin) | 25/25 (100%) | 25/25 (100%) | 9/25 (36.0%) |
| | Hex Byte Encoding | 25/25 (100%) | 25/25 (100%) | 25/25 (100%) |
| | Leetspeak Obfuscation | 25/25 (100%) | 25/25 (100%) | 6/25 (24.0%) |
| | Fullwidth / NFKC Unicode | 25/25 (100%) | 25/25 (100%) | **0/25 (0.0%)** |
| | Zero-Width Invisible Chars | 25/25 (100%) | 25/25 (100%) | 25/25 (100%) |
| | Spaced Whitespace | 25/25 (100%) | 25/25 (100%) | 25/25 (100%) |
| | Keyword Typosquatting | 25/25 (100%) | 25/25 (100%) | 25/25 (100%) |
| **Held-Out Novel Vectors** | Double Base64 | 25/25 (100%) | 25/25 (100%) | **0/25 (0.0%)** |
| | Base32 Encoding | 25/25 (100%) | 25/25 (100%) | **0/25 (0.0%)** |
| | ROT13 Cipher | 25/25 (100%) | 25/25 (100%) | **0/25 (0.0%)** |
| | Reversed String | 25/25 (100%) | 25/25 (100%) | 5/25 (20.0%) |
| | Cyrillic Homoglyphs | 25/25 (100%) | 25/25 (100%) | 24/25 (96.0%) |
| | URL Percent-Encoding | 25/25 (100%) | 25/25 (100%) | 25/25 (100%) |
| | HTML Entities | 25/25 (100%) | 25/25 (100%) | 25/25 (100%) |
| | Binary ASCII | 25/25 (100%) | 25/25 (100%) | 25/25 (100%) |

**Core Defense Trade-Off**:
- **ProtectAI** is highly resistant to false alarms on code, but **completely vulnerable (0% recall)** to fullwidth characters, ROT13, Base32, and double Base64 encodings.
- **DistilBERT** catches obfuscated text via subword fragmentation and entropy cues, but suffers high false alarm rates on legitimate technical text containing high-entropy tokens.

---

### 5. Latency & Throughput Benchmark (Single GPU, Batch Size 1)
*Measured over 50 warm-up runs and 200 timed iterations on RTX 4050 Mobile GPU:*

| Model Architecture | Parameters | Mean Latency | 95th Percentile | Throughput |
| :--- | :---: | :---: | :---: | :---: |
| **DistilBERT (Ours)** | **67.0M** | **8.37 ms ± 0.95 ms** | **9.83 ms** | **119.4 QPS** |
| **ProtectAI DeBERTa-v3** | 184.4M | 34.33 ms ± 11.44 ms | 52.01 ms | 29.1 QPS |
| **ModernBERT** | 149.6M | 43.76 ms ± 4.93 ms | 52.57 ms | 22.8 QPS |

DistilBERT delivers **4.1x higher throughput** than ProtectAI and **5.2x higher throughput** than ModernBERT under identical runtime conditions.

---

## 📂 Repository Layout

```
prompt_injection/
├── README.md                      # Primary research documentation and benchmarks
├── LICENSE                        # MIT License
├── requirements.txt               # Package dependencies
├── requirements-frozen.txt        # Exact pinned versions
├── environment.yml                # Conda environment specification
├── app.py                         # Interactive Streamlit defense UI
├── config.py                      # Centralized configuration & thresholds
├── guard.py                       # 6-Layer core pipeline implementation
├── train.py                       # Base training routine
├── train_all.py                   # Multi-architecture CLI trainer
├── evaluate.py                    # Evaluation and threshold sweep script
├── evaluate_all_fusions.py        # Fusion & multi-view ablation harness
├── data_prep.py                   # Dataset partitioning & balance verification
├── minhash_audit.py               # Contamination and near-duplicate audit
├── download_all_data.py           # Corpus download automation
├── architecture_diagram.py        # System diagram renderer
├── run_complete_pipeline.bat      # Windows automated execution script
├── docs/                          # Documentation & changelog
│   └── CHANGELOG.md               # Engineering fixes & audit history
├── tests/                         # Unit tests (pytest)
│   ├── test_normalization.py
│   ├── test_rules.py
│   └── test_fusion.py
├── results/                       # Consolidated evaluation CSV and JSON outputs
│   ├── comprehensive_test_seen.csv
│   ├── comprehensive_test_unseen_dolly.csv
│   ├── comprehensive_test_unseen_alpaca.csv
│   ├── comprehensive_hard_dev.csv
│   ├── comprehensive_hard_heldout.csv
│   ├── comprehensive_obfuscation_breakdown.csv
│   ├── latency_benchmark_gpu.csv
│   └── minhash_audit_report.json
├── plots/                         # Publication-quality charts & curves
└── extensions_crossguard/         # Prototype future-work extensions (not evaluated)
```

---

## 📝 Citation

```bibtex
@software{prompt_injection_empirical_2026,
  author = {Bharatraj},
  title = {Empirical Evaluation and Defense Architecture for Prompt Injection Attacks},
  year = {2026},
  institution = {SRIHER, BTech AI & Data Science},
  url = {https://github.com/Bharatraj-007/prompt_injection}
}
```
