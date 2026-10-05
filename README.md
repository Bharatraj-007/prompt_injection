# 🛡️ Prompt Injection Attack Detector and Defender

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.25+-red.svg)](https://streamlit.io/)

A multi-layered defense architecture for detecting and mitigating both **direct system prompt overrides** and **indirect prompt injection attacks** against Large Language Models (LLMs).

---

## 📌 Project Overview
- **Author:** Bharatraj
- **Institution:** SRIHER, Department of BTech AI & Data Science
- **Topic:** LLM Security (Direct & Indirect Prompt Injection Detection and Defense)
- **Repository:** `https://github.com/Bharatraj-007/prompt_injection.git`

---

## 🏗️ 6-Layer Defense Architecture

```
                       +---------------------------------------+
                       |           Raw Input Prompt            |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       | Layer 1: Preprocessing & Decoding     |
                       | (NFKC, Hidden Chars, Base64 Encodings) |
                       +---------------------------------------+
                                     /           \
                                    v             v
            +-------------------------------+    +-------------------------------+
            | Layer 2: Rule Filter Engine   |    | Layer 3: Transformer Model    |
            | (Multi-lingual Regex & Heur.) |    | (DeBERTa-v3 / DistilBERT)     |
            +-------------------------------+    +-------------------------------+
                                    \             /
                                     v           v
                       +---------------------------------------+
                       | Layer 4: Score Fusion & Thresholding  |
                       |  Fused Score = 0.3*L2 + 0.7*L3 >= 0.5 |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       | Layer 5: Dynamic Canary Token         |
                       | (Hardens Instructions & Seals Token)  |
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
                       | (Scans Output for Secret Leakage)     |
                       +---------------------------------------+
                                           |
                                           v
                       +---------------------------------------+
                       |         Final Guarded Output          |
                       |          (ALLOWED / BLOCKED)          |
                       +---------------------------------------+
```

---

## 🚀 Quickstart & Installation

```bash
# 1. Clone the repository
git clone https://github.com/Bharatraj-007/prompt_injection.git
cd prompt_injection

# 2. Install dependencies
pip install -r requirements.txt

# 3. Download raw Hugging Face datasets & clone BIPIA
python download_all_data.py

# 4. Run data preprocessing & stratification
python data_prep.py

# 5. Train transformer classifier across seeds (42, 7, 123)
python train.py

# 6. Evaluate pipeline, generate plots & obfuscation report
python evaluate.py

# 7. Launch Streamlit interactive demo
streamlit run app.py
```

---

## 📊 Benchmark Results

| Defense Approach | Accuracy | Precision | Recall | F1-Score | False Positive Rate | Inference Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rules Only (Layer 2)** | 0.9420 | 0.9510 | 0.9320 | 0.9414 | 0.0320 | 0.52 ms |
| **Model Only (Layer 3)** | 0.9620 | 0.9580 | 0.9650 | 0.9615 | 0.0210 | 14.20 ms |
| **Hybrid Pipeline (Layers 1-6)** | **0.9890** | **0.9850** | **0.9920** | **0.9885** | **0.0080** | **14.85 ms** |

---

## 📂 Project Structure

```
d:\prompt_injection\
├── download_all_data.py     # Script to fetch 7 HF datasets + GitHub repos
├── data_prep.py             # Preprocessing & 70/15/15 stratified splitting
├── guard.py                 # Core 6-layer defense pipeline module
├── train.py                 # Transformer fine-tuning script across seeds
├── evaluate.py              # Benchmark evaluation & graph generation script
├── app.py                   # Streamlit web user interface
├── architecture_diagram.py  # Matplotlib architecture image generator
├── requirements.txt         # Dependencies list
├── .gitignore               # Git exclusions
├── plots/                   # Saved evaluation graph artifacts (200 DPI PNG)
└── README.md                # Project documentation
```

---

## 🔗 Datasets Included
- `deepset/prompt-injections`
- `xTRam1/safe-guard-prompt-injection`
- `Lakera/gandalf_ignore_instructions` (Unseen benchmark test set)
- `Lakera/gandalf_summarization`
- `hackaprompt/hackaprompt-dataset`
- `databricks/databricks-dolly-15k` (Benign baseline)
- `neuralchemy/Prompt-injection-dataset`
- `microsoft/BIPIA` (Indirect injection benchmark)
