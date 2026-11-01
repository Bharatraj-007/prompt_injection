# PRIORITIZED REMEDIATION ROADMAP

**Project:** Hybrid AI Prompt Injection Detection and Defense Platform  
**Audit Finding Classification:** P0 (Critical), P1 (High), P2 (Medium), P3 (Low / Polish)  

---

## 1. Prioritized Findings Table

| Priority | Issue ID | Area | File & Line Range | Finding Description | Recommended Action | Complexity | Dependencies |
| :---: | :---: | :---: | :--- | :--- | :--- | :---: | :--- |
| **P1** | **REM-001** | Model / Data | `guard.py` (L495-530) | Non-English prompt extraction and creative roleplay evasions | Expand multilingual hard-negatives & synthetic adversarial training suite | Medium | New data splits |
| **P2** | **REM-002** | Security | `guard.py` (L85-110) | Base64 decoder heuristic false triggers on random 16+ hex strings | Enforce valid Base64 padding and printable ASCII ratio validation | Low | `guard.py` |
| **P2** | **REM-003** | Architecture | `security_database.py` | SQLite single-file lock under distributed horizontal clustering | Provide PostgreSQL / SQLAlchemy connector option for multi-replica Kubernetes | High | DB driver |
| **P2** | **REM-004** | Calibration | `guard.py` (Layer 4) | Fused scores act as severity metric rather than strictly calibrated probabilities | Fit temperature scaling / isotonic regression on held-out validation set | Medium | Validation set |
| **P3** | **REM-005** | UI / Frontend | `app.py` | Streamlit deprecated `use_container_width` warning in future versions | Update `use_container_width=True` to `width='stretch'` across dataframe calls | Low | `app.py` |
| **P3** | **REM-006** | Testing | `tests/` | Playwright browser framework not pre-installed in offline environment | Add optional automated Playwright smoke tests for CI/CD container environments | Medium | CI pipeline |
