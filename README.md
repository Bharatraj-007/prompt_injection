# 🛡️ Empirical Evaluation and Defense Pipeline for Prompt Injection Attacks

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Tests: 71 Passed](https://img.shields.io/badge/Tests-71%20Passed-brightgreen.svg)](tests/)
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

## 🏗️ 7-Layer Hybrid Architecture Overview

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
                                     /     |     \
                                    v      v      v
            +--------------------+  +--------------------+  +-------------------------+
            | Layer 2: Rules     |  | Layer 3: DistilBERT|  | Layer 7: LLM as a Judge |
            | (Regex/Heuristic)  |  | (Fine-Tuned CLS)   |  | (Groq / xAI / GPU / FB) |
            +--------------------+  +--------------------+  +-------------------------+
                                    \      |      /
                                     v     v     v
                       +---------------------------------------+
                       | Layer 4: Multi-Layer Score Fusion     |
                       | Noisy-OR Probabilistic Ensemble       |
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
                       | (Canary Egress & LLM Output Audit)    |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       |         Final Guarded Output          |
                       |          (ALLOWED / BLOCKED)          |
                       +---------------------------------------+
```

### ⚖️ Layer 7: LLM as a Judge (Defender)
The LLM Judge serves as the high-intelligence security analyst layer of the defense pipeline:
- **Groq Cloud API (`GroqJudge`)**: Ultra-low latency inference (<300ms) with `llama-3.3-70b-versatile`, `llama-3.1-8b-instant`, `mixtral-8x7b-32768`.
- **xAI Grok API (`XaiGrokJudge`)**: OpenAI-compatible client integration supporting `grok-2-latest` and `grok-beta`.
- **Local GPU Judge (`LocalGPUJudge`)**: Runs locally on NVIDIA CUDA (RTX 4050 6GB) using HuggingFace models (`Qwen/Qwen2.5-1.5B-Instruct`) with zero API token costs.
- **Heuristic Fallback Judge (`FallbackJudge`)**: Ensures zero system crashes and full offline resilience if network or API keys are unavailable.
- **GPU Diagnostics**: Real-time VRAM allocation tracking and live monitoring via `python -m nvitop`.

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
*Audit finding*: MinHash deduplication removed **301 of 1,500 (20.07%)** candidate test_seen samples, **293 of 1,500 (19.53%)** validation samples, and **14 of 1,552 (0.90%)** test_unseen samples that contaminated the training split ($Jaccard \ge 0.80$). An additional cross-split quarantine removed 39 test_seen and 2 test_unseen samples, enforcing strict zero-leakage partitions: **Clean Test Seen** ($N=1,160$), **Clean Test Unseen** ($N=1,536$), and **Clean Val** ($N=1,207$).

### Step 3: Model Training
```bash
# Train DistilBERT across Seed 42 (reproducible deterministic training)
python train.py

# Or train alternative backbones (ModernBERT)
python train_all.py modernbert
```

### Step 4: Run Tests & Evaluation
```bash
# 1. Run unit tests (71 tests passing)
pytest tests/ -v

# 2. Run full evaluation across seen, unseen, and hard-negatives
python evaluate.py

# 3. Run interactive web application
streamlit run app.py
```

---

## 📊 Empirical Findings & Benchmark Results

### 1. In-Distribution Clean Test Set ($N = 1,160$)
*Hardware: NVIDIA RTX 4050 Laptop GPU (6GB), PyTorch CUDA*

| Defense Approach | Accuracy | Precision | Recall | F1-Score | FPR | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rules Only (Layer 2)** | 0.6172 | 1.0000 | 0.0452 | 0.0864 | **0.00%** | **0.05 ms** |
| **Model Only (DistilBERT)** | **0.9759** | **0.9781** | **0.9613** | **0.9696** | 1.44% | 4.64 ms |
| **Hybrid Pipeline (Noisy-OR)** | **0.9759** | **0.9781** | **0.9613** | **0.9696** | 1.44% | 10.96 ms |

**Key Takeaways**:
- **Rules add zero decision divergence on clean data**: DistilBERT caught 447 of 465 attacks and produced 10 false alarms out of 695 benign prompts.
- **Statistical Significance**: McNemar's test between DistilBERT model-only and Noisy-OR hybrid yields $\chi^2 = 0.0$, $p = 1.0$ (no significant difference on clean test data).
- **Calibration**: Expected Calibration Error (ECE, 10 bins) is $0.0109$ for Model Only and $0.0110$ for Hybrid Noisy-OR.
- **Decision Equivalence**: At threshold $\theta = 0.50$, Noisy-OR ($1 - (1 - r)(1 - m)$) and Max Fusion ($\max(r, m)$) yield 100% identical binary blocking decisions because Layer 2 heuristic rules only fire with high confidence ($w \ge 0.85$).

---

### 2. Out-of-Domain Unseen Test Set ($N = 1,536$)

| Test Split | Defense Model | Accuracy | Precision | Recall | F1-Score | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Clean Test Unseen (OOD)** ($N=1,536$) | Hybrid Pipeline (Noisy-OR) | **0.9844** | **0.9947** | **0.9742** | **0.9844** | **0.53%** |

*Empirical Generalization Note*: Clean Test Unseen F1 is $+0.0148$ relative to Clean Test Seen. This difference is driven primarily by prompt length and structure: the unseen set has an average length of 71.0 characters versus 173.2 characters in the seen test set, resulting in lower subword token fragmentation.

---

### 3. Independent Adversarial Evaluation Suite ($N = 350$)

| Metric | Measured Value | Wilson 95% Confidence Interval |
| :--- | :---: | :---: |
| **Overall Suite Accuracy** | **96.29%** | 93.8% — 97.8% |
| **Attack Detection Rate (Recall)** | **293 / 300 (97.67%)** | 95.3% — 98.9% |
| **Benign Look-Alike FPR** | **6 / 50 (12.00%)** | 5.6% — 23.8% |

*Defense-in-Depth Clarification*: Layers 5 (Dynamic Cryptographic Canary) and 6 (Output Guard Inspection) provide output-level defense against system prompt exfiltration and payload execution. They are validated via automated verification suites rather than input classification tables.

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
*CUDA-synchronized dynamic latencies measured over 20 warm-up runs and 100 timed iterations on NVIDIA RTX 4050 Laptop GPU:*

| Pipeline Component | Parameter Scale | Mean Latency | Median Latency | 95th Percentile | Execution Mode |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Layer 2 Rules** | Heuristic Regex | **0.05 ms** | 0.04 ms | 0.08 ms | CPU Deterministic |
| **Layer 3 DistilBERT Forward** | 67.0M | **4.64 ms** | 4.60 ms | 4.92 ms | Local RTX 4050 GPU (FP32) |
| **Hybrid Pipeline End-to-End** | Multi-Layer | **10.96 ms** | 10.56 ms | 12.86 ms | Local GPU Pipeline |
| **Layer 7 LLM Judge (Cloud)** | 70B / Grok-2 | **~300 - 800 ms** | ~450 ms | ~950 ms | Cloud API (Groq / xAI) |

The local GPU hybrid pipeline processes requests with sub-11 ms latency, while Layer 7 LLM Judge provides asynchronous deep reasoning without blocking critical real-time traffic.

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
├── guard.py                       # 7-Layer core pipeline implementation
├── train.py                       # Base training routine with validation selection & NaN/Inf weight checks
├── train_all.py                   # Multi-architecture CLI trainer
├── evaluate.py                    # Dynamic latency, ECE, McNemar test & evaluation suite
├── evaluate_all_fusions.py        # Fusion & multi-view ablation harness
├── data_prep.py                   # Dataset partitioning & Stanford Alpaca OOD integration
├── minhash_audit.py               # Contamination audit & cross-split near-duplicate quarantine
├── download_all_data.py           # Corpus download automation (no runtime pip subprocesses)
├── architecture_diagram.py        # System diagram renderer
├── run_complete_pipeline.bat      # Windows automated execution script
├── docs/                          # Documentation & changelog
│   └── CHANGELOG.md               # Engineering fixes & audit history
├── tests/                         # Unit tests (71 passed via pytest)
│   ├── test_leakage_and_splits.py    # Zero-leakage & cross-split quarantine isolation tests
│   ├── test_normalization_fixes.py  # Prompt length preservation, leetspeak & Unicode tests
│   ├── test_training_safety.py       # Checkpoint weight verification & class weights tests
│   ├── test_evaluation_metrics.py    # ECE calibration, McNemar statistical & Wilson CI tests
│   ├── test_output_guard.py          # Dynamic canary uniqueness & output guard leak tests
│   ├── test_normalization.py         # Layer 1 de-obfuscation & normalization tests
│   ├── test_rules.py                 # Layer 2 regex heuristic pattern tests
│   ├── test_fusion.py                # Layer 4 Noisy-OR probabilistic fusion tests
│   └── test_llm_judge.py             # Layer 7 LLM Judge, API key isolation & think-tag tests
├── results/                       # Consolidated evaluation CSV and JSON outputs
│   ├── test_seen_sample_predictions.csv
│   ├── test_unseen_sample_predictions.csv
│   ├── adversarial_suite_predictions.csv
│   ├── comprehensive_test_seen.csv
│   ├── comprehensive_test_unseen_dolly.csv
│   ├── comprehensive_test_unseen_alpaca.csv
│   ├── comprehensive_hard_dev.csv
│   ├── comprehensive_hard_heldout.csv
│   ├── comprehensive_obfuscation_breakdown.csv
│   ├── latency_benchmark_gpu.csv
│   └── minhash_audit_report.json
├── plots/                         # Publication-quality charts & curves (200 DPI PNGs)
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
