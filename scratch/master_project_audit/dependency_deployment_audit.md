# DEPENDENCY AND DEPLOYMENT READINESS AUDIT

**Project:** Hybrid AI Prompt Injection Detection and Defense Platform  
**Target Environment:** Local Python 3.11 Runtime / Offline Staging Mode  

---

## 1. Core Dependency Compatibility

| Package | Minimum / Declared | Installed Runtime | Status | Notes |
| :--- | :--- | :--- | :---: | :--- |
| **Python** | `>= 3.10` | `3.11.9` | **COMPATIBLE** | High performance standard CPython build |
| **PyTorch** | `>= 2.0.0` | `2.5.1+cu121` | **COMPATIBLE** | CUDA 12.1 acceleration enabled |
| **Transformers** | `>= 4.35.0` | `4.49.0` | **COMPATIBLE** | Safetensors and DistilBERT support |
| **Streamlit** | `>= 1.30.0` | `1.50.0` | **COMPATIBLE** | AppTest runner & web UI active |
| **Pandas** | `>= 2.0.0` | `2.3.3` | **COMPATIBLE** | Dataframes and benchmarking tables |
| **NumPy** | `>= 1.24.0` | `2.1.3` | **COMPATIBLE** | Array computations & metric aggregation |
| **Scikit-Learn** | `>= 1.3.0` | `1.6.1` | **COMPATIBLE** | ROC-AUC, confusion matrix, metrics |
| **Safetensors** | `>= 0.4.0` | `0.5.2` | **COMPATIBLE** | Secure weight loading |
| **ReportLab** | `>= 3.6.0` | `4.3.1` | **COMPATIBLE** | PDF executive audit report generation |
| **PyMuPDF (fitz)** | `>= 1.23.0` | `1.25.3` | **COMPATIBLE** | Document parsing & text extraction |
| **python-docx** | `>= 0.8.11` | `1.1.2` | **COMPATIBLE** | Word document text extraction |

---

## 2. Environment Configuration & Staging Isolation

* **Dual-Mode Operation:** Controlled via `APP_ENV` and `LOCAL_STAGING` environment variables in `config.py`.
* **Staging Mode:** `APP_ENV=staging`, `LOCAL_STAGING=True` enforces offline isolation:
  - External API calls are intercepted and directed to `MockAIProvider`.
  - Staging banner `🛠️ LOCAL STAGING ENVIRONMENT` renders at the top of the interface.
  - Telemetry is persisted in local SQLite with strict redaction.
* **Production Mode:** `APP_ENV=production`, `LOCAL_STAGING=False` activates live upstream provider connections (Gemini, Groq, OpenAI, Anthropic).
