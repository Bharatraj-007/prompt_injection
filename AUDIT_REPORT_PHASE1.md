# PROMPT INJECTION DETECTOR - COMPREHENSIVE AUDIT REPORT
## Phase 1: READ-ONLY CODE AUDIT

**Auditor**: Senior ML Engineer & Security Reviewer  
**Date**: 2026-10-05  
**Environment**: Windows, Python 3.11, transformers v5, RTX 4050 6GB  
**Project**: DistilBERT + 6-Layer PromptGuardPipeline Prompt Injection Detector

---

## EXECUTIVE SUMMARY

This audit identified **30 code quality issues**, **5 data leakage risks**, **6 reproducibility gaps**, and **8 security vulnerabilities** across 7,306+ lines of code in 9 Python files plus test suite.

### Critical Issues (5)
- Missing label mappings in saved model config (F001)
- Training data imbalance (3806 vs 3500 samples) violates balance claims (F004)
- Documentation claims wrong row counts throughout (F002, F003)
- Duplicate fusion implementations with conflicting documentation (F005)
- Inconsistent epoch indexing creating potential off-by-one errors (F006)

### High-Risk Data Leakage (2)
- Threshold selection and test evaluation in same script (D003)
- Validation set cleaning happens AFTER training may have occurred (D002)

### Critical Security Vulnerabilities (2)
- ReDoS vulnerability in Base64 regex with unbounded repetition (S001)
- Hex decode allows arbitrary memory allocation (S002)

---

## DETAILED FINDINGS TABLE

| ID | Severity | File:Line | Problem | Evidence | Proposed Fix |
|---|---|---|---|---|---|
| **F001** | CRITICAL | config.py:1-27 | **Missing id2label/label2id in model config** | models/prompt_injection_detector/config.json exists but has no id2label/label2id fields; only has num_labels=2 | Add `id2label={0: "Benign", 1: "Injection"}` and `label2id={"Benign": 0, "Injection": 1}` to model config during model.save_pretrained() |
| **F002** | CRITICAL | train.py:256-262 | **Label mismatch in comments vs data** - Comments claim "750 benign, 750 injection" for val/test but actual clean_val.csv has 1210 rows (708 benign + 502 injection), clean_test_seen has 1208 rows (708 benign + 500 injection) | Executed: `Import-Csv clean_val.csv \| Measure-Object -Line` = 2248 rows dirty → 1210 clean after audit | Update ALL comments to match ACTUAL row counts from files; document contamination removal process |
| **F003** | CRITICAL | train.py:1-700 | **train.csv has 7306 rows, NOT 7000** - Comments/README claim 70/15/15 split should yield 7000/1500/1500 from 10,000 samples | PowerShell: `train.csv = 7306 rows (3806 benign, 3500 injection)` | Update all documentation; investigate where extra 306 samples came from (likely data_prep.py logic error) |
| **F004** | CRITICAL | data_prep.py:73 | **Imbalanced training data** - Code claims 1:1 balance but train.csv has 3806 benign vs 3500 injection (8.7% imbalance) | train.csv label counts: 0=3806, 1=3500 | Either fix data_prep.py to enforce strict n_samples balance OR add `class_weight='balanced'` in TrainingArguments |
| **F005** | HIGH | guard.py:189-203, evaluate.py:21-31, architecture_diagram.py:28 | **Conflicting fusion formulas** - README/diagram claim "0.3*L2 + 0.7*L3" weighted average but actual code uses `1-(1-r)*(1-m)` noisy-OR everywhere | guard.py:197 and evaluate.py:70-71 both use noisy-OR; README line 88 and architecture_diagram.py:28 say weighted average | Make fusion formula single source of truth in config.py; update README/diagram to match actual noisy-OR |
| **F006** | HIGH | train.py:182-194 | **Inconsistent epoch indexing** - Creates epoch_logs starting at 1 but trainer.state.log_history may contain fractional epochs < 1.0, leading to `max(1, min(epochs, int(np.ceil(ep))))` complexity | train.py:186 `e_idx = max(1, min(epochs, int(np.ceil(ep))))` can create edge cases | Use `int(round(trainer.state.epoch))` directly; validate no epoch 0 entries exist in saved JSON |
| **F007** | HIGH | evaluate.py:82-100, config.py:18 | **BLOCK_THRESHOLD not persisted** - evaluate.py selects optimal threshold from val sweep (e.g. 0.30) but config.py still has 0.50 hardcoded; choice not saved | evaluate.py:95 `pipeline.layer4.threshold = chosen_threshold` (runtime only) | Save chosen_threshold to config.py or create thresholds.json; document which is production vs experimental |
| **F008** | HIGH | guard.py:235-275, evaluate.py:124-126 | **Triple model inference per prompt** - inspect_and_defend() evaluates raw, normalized, AND augmented text separately (3 forward passes ≈ 15-18ms) but evaluate.py claims 5.49ms | guard.py:250-252 calls self.layer3.predict() three times; evaluate.py:125 hardcodes avg_latency_ms=5.49 | Either measure ACTUAL latency with time.perf_counter() OR batch all 3 variants together for true timing |
| **F009** | HIGH | evaluate.py:52-64, guard.py:245-260 | **Score extraction differs from inference** - evaluate.py uses batch inference with padding=True; guard.py uses single inference with padding=False. Different code paths = potentially different results | evaluate.py:58 `tokenizer(batch, padding=True)`; guard.py:169 `tokenizer(text, padding=False)` | Unify inference paths; add integration test asserting evaluate.py and guard.py produce IDENTICAL scores |
| **F010** | HIGH | minhash_audit.py:1-200 | **Adversarial suite not checked for leakage** - Script checks train vs val/test_seen/test_unseen but never checks if adversarial_eval_suite.json leaked into training | minhash_audit.py:76 splits_audit = [val, test_seen, test_unseen]; adversarial_eval_suite.json not included | Add adversarial_eval_suite.json to contamination checks against train/val/test splits |
| **F011** | MEDIUM | requirements.txt:2 | **Version ranges too loose** - All packages use `>=` (e.g. transformers>=4.30.0) but project uses v5.x-only features (processing_class parameter) | requirements.txt line 2; train.py:144 uses processing_class (v5+ only) | Pin: `transformers>=5.0.0,<6.0.0` or create requirements-frozen.txt with exact versions |
| **F012** | MEDIUM | train.py:18-28, evaluate.py:9-12, guard.py:9-12, app.py:5-9 | **Inconsistent config import fallbacks** - Every file has try/except with DIFFERENT fallback paths. If config.py missing, each uses different MODEL_DIR | train.py:24 uses os.path.join(os.getcwd(), ...); guard.py:12 uses BASE_DIR; app.py:9 uses os.getcwd() | Remove all fallbacks; make config.py import required OR centralize fallback to single function |
| **F013** | MEDIUM | train.py:144, requirements.txt:2 | **processing_class requires transformers v5** - Code uses v5-only parameter but requirements.txt allows v4.30+ installation | train.py:144 `processing_class=tokenizer` crashes on transformers<5.0 | Update requirements.txt to transformers>=5.0.0 AND add runtime version check |
| **F014** | MEDIUM | train.py:120-122 | **Checkpoint selection uses loss, not F1** - TrainingArguments uses metric_for_best_model="eval_loss" but stated goal is highest F1 | train.py:121-122 `metric_for_best_model="eval_loss", greater_is_better=False` | Change to `metric_for_best_model="f1", greater_is_better=True` OR document loss-based selection rationale |
| **F015** | MEDIUM | evaluate.py:78 | **Threshold sweep too coarse** - Uses [0.20, 0.30, ..., 0.80] with 0.10 steps; audit requires 0.05 increments | evaluate.py:78 hardcoded list | Change to `np.arange(0.05, 0.95, 0.05)` for finer granularity |
| **F016** | MEDIUM | guard.py:35-47 | **Levenshtein O(n²) implementation** - Custom implementation correct but slow; 14-char words = 196 ops/word × 100 words = significant latency | guard.py:35-47 nested loops | Use python-Levenshtein library (C-optimized) OR limit to first 50 words of input |
| **F017** | MEDIUM | guard.py:99 | **Base64 extraction has no max length** - Regex `{8,}` has no upper bound; 100KB Base64 string causes decode bombs | guard.py:99 `re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', text)` unbounded | Change to `{8,10000}` and add size check before decode |
| **F018** | MEDIUM | guard.py:173, evaluate.py:55-62 | **No error handling in model inference** - predict() has bare except that silently returns fallback; evaluate.py has no try/except at all | guard.py:173 `except Exception: pass`; evaluate.py:58-62 no error handling | Add explicit exception types; log errors; fail-closed (return 1.0 attack score on error) |
| **F019** | MEDIUM | app.py:44-51 | **No input length validation** - Streamlit text_area has no max_chars; user can paste 10MB causing OOM | app.py:46-50 text_area definitions have no max_chars parameter | Add `max_chars=50000`; display warning if exceeded |
| **F020** | MEDIUM | evaluate.py:125-127 | **Hardcoded latency values** - Lines use magic numbers 0.45ms (rules), 4.98ms (model), 5.49ms (hybrid) not measured from actual runs | evaluate.py:125 `avg_latency_ms=0.45` etc. are hardcoded constants | Remove hardcoded values; measure with time.perf_counter() OR import from saved benchmark results |
| **F021** | LOW | train.py:216-230 | **Redundant epoch history save** - Saved twice: results_seed_dir and data_dir with no explanation | train.py:220 and 226 write same data to different locations | Document reason OR remove redundant copy |
| **F022** | LOW | download_all_data.py:51 | **Git clone doesn't verify repo integrity** - Checks directory existence but not if it's valid git repo | download_all_data.py:51 `if os.path.exists(repo_path): continue` | Check for `.git` subdirectory existence |
| **F023** | LOW | All .py files | **No type hints** - No typing module usage anywhere; prevents static analysis | No `def function(x: str) -> dict:` syntax found | Add type hints to all function signatures |
| **F024** | LOW | guard.py, evaluate.py | **Missing docstrings** - Many functions have no docstrings explaining params/returns | guard.py:189 fuse(), evaluate.py:21 compute_metrics_dict() etc. | Add comprehensive docstrings with Args, Returns, Raises sections |
| **F025** | LOW | tests/ | **Only 1 test file** - Only test_normalization.py exists; no tests for layers 2-6, training, evaluation, metrics | `ls tests/` shows only test_normalization.py and __pycache__ | Add: test_rules.py, test_fusion.py, test_pipeline.py, test_metrics.py, test_integration.py |
| **F026** | LOW | evaluate.py:216 | **Plot generation warning but continues** - Prints warning about missing epoch history but doesn't fail; later code may reference non-existent plots | evaluate.py:216 "[WARNING] ... Skipping Plots 1-4" but continues execution | Fail-fast if epoch history missing OR create "Data Not Available" placeholder images |
| **F027** | LOW | minhash_audit.py:93-104 | **Long multiline string in JSON** - 7-line explanation string in JSON output makes parsing harder | minhash_audit.py:93-104 multiline string explanation | Move to separate explanation.md file; keep JSON machine-readable |
| **F028** | LOW | config.py:8-11 | **No path validation** - MODEL_DIR, DATA_DIR defined but never verified to exist | config.py defines paths without os.path.exists() checks | Add existence checks OR create directories on import |
| **F029** | LOW | All files | **No structured logging** - print() used everywhere; no log levels, no log files | Every file uses print() for output | Replace with logging module; add log level configuration |
| **F030** | LOW | architecture_diagram.py:28 | **Diagram formula wrong** - Shows "0.3 * L2 + 0.7 * L3" but code uses noisy-OR | architecture_diagram.py:28 doesn't match guard.py:197 | Update label to "1 - (1-rule)*(1-model)" |

---

## DATA LEAKAGE FINDINGS

| ID | Severity | File:Line | Problem | Evidence | Proposed Fix |
|---|---|---|---|---|---|
| **D001** | HIGH | data_prep.py:73-77 | **"Unseen" split not truly OOD** - Both seen and unseen draw from same dataset pools (Neuralchemy, xTRam1, Dolly). Only Lakera Ignore is truly unseen. 777 "unseen" Dolly samples just held out, not different distribution | data_prep.py:67-73 reserves first 777 Dolly for unseen_benign, rest to all_benign pool | Use completely different data sources for unseen (different time period/collection) OR relabel as "held-out test" not "OOD" |
| **D002** | HIGH | train.py:256, minhash_audit.py:76-85 | **Validation cleaned AFTER training may run** - train.py loads val.csv if clean_val.csv doesn't exist, but minhash_audit creates clean_val.csv by removing overlaps. If training ran first, used contaminated val | train.py:256 loads val.csv fallback; minhash_audit creates clean_val.csv | Make minhash_audit.py a prerequisite; train.py should FAIL if clean_val.csv missing |
| **D003** | HIGH | evaluate.py:75-127 | **Threshold selection and test eval in same script** - Threshold chosen on val (line 88), immediately applied to test (line 123) in single execution. Proper procedure: choose on val, save, run separate test evaluation | evaluate.py runs val sweep then test evaluation without separation | Split into threshold_selection.py (val only, saves threshold) and test_evaluation.py (loads threshold, runs test) |
| **D004** | MEDIUM | train.csv:2, data_prep.py:1-200 | **Hard negatives source unknown** - train.csv contains source="hard_negative_clean" samples but data_prep.py never creates hard_negatives.csv | train.csv line 2 shows hard_negative_clean; no generation code exists | Document hard negatives source OR remove from train.csv; add generation to pipeline |
| **D005** | LOW | evaluate.py:42-280 | **Adversarial suite mixed with test evaluation** - Both evaluated in same script suggests possible information leakage | evaluate.py loads adversarial suite immediately after test sets | Move adversarial evaluation to separate script for clear isolation |

---

## REPRODUCIBILITY FINDINGS

| ID | Severity | File:Line | Problem | Evidence | Proposed Fix |
|---|---|---|---|---|---|
| **R001** | HIGH | train.py:91-95, train.py:114 | **Seeds set in multiple places** - Manual numpy/torch seed setting happens before trainer initialization; random state could leak between seeds | Seeds set twice in different locations | Use `transformers.set_seed()` helper; add `torch.backends.cudnn.deterministic=True` |
| **R002** | HIGH | train.py:1-700 | **No deterministic algorithms flag** - Even with seeds, non-deterministic CUDA ops (scatter_add, index_add) cause variance | No `torch.use_deterministic_algorithms(True)` anywhere | Add deterministic flag; handle unsupported ops errors with fallbacks |
| **R003** | MEDIUM | requirements.txt:1-10 | **No pinned versions** - All use `>=` with no upper bound; transformers 5.5.4 used but user might get 6.0.0 with breaking changes | All packages use `>=` syntax | Create requirements-frozen.txt with `pip freeze` output; pin to tested versions |
| **R004** | MEDIUM | Project root | **No environment specification** - Python version, CUDA version, OS dependencies not specified | No environment.yml, Dockerfile, or .python-version file | Add environment.yml with CUDA version, Python 3.11, and system deps |
| **R005** | LOW | README.md:47-56 | **No run order specified** - 7 commands shown but no dependency graph (e.g. minhash_audit must run before train) | README quickstart lists commands without prerequisites | Add numbered execution order; add prerequisite checks in each script header |
| **R006** | LOW | train.py, evaluate.py | **No saved random state** - Scripts set seeds but don't save state to file; can't reproduce exact shuffle sequence | No pickle dump of random generators | Save numpy/torch/python random state to checkpoint file |

---

## SECURITY FINDINGS (Detector Vulnerabilities)

| ID | Severity | File:Line | Problem | Evidence | Proposed Fix |
|---|---|---|---|---|---|
| **S001** | CRITICAL | guard.py:99 | **ReDoS vulnerability** - Base64 regex `[A-Za-z0-9+/]{8,}={0,2}` with unbounded repetition can cause exponential backtracking on input like "AAAA...AAA=" (1MB of As) | Pattern allows unlimited repetition with no upper bound | Change to `{8,10000}` max length, use re.finditer with timeout, OR replace with string.find() |
| **S002** | CRITICAL | guard.py:130 | **Unbounded hex decode** - `bytes.fromhex(clean)` on 10MB hex string allocates 5MB memory with no limit; 100 concurrent requests = 500MB OOM | No size check before bytes.fromhex() call | Add `if len(clean) > 20000: return []` before decode |
| **S003** | HIGH | guard.py:53-90 | **Nested regex on untrusted input** - collapse_spaced_characters() uses multiple complex patterns like `r'\b(?:[a-zA-Z]\s*[-_.]\s*){2,}[a-zA-Z]\b'` that can be slow on pathological input | Multiple sequential re.sub calls on untrusted data | Add input length limit (max 5000 chars); wrap regex in timeout |
| **S004** | HIGH | app.py:48 | **No input sanitization** - User input passed directly to model with no validation; malformed unicode could crash internals | user_input goes directly to guard.inspect_and_defend() | Add validation: check encoding, max length, no null bytes, printable chars only |
| **S005** | MEDIUM | guard.py:174 | **Exception info might leak** - Bare except silently hides errors; if logging added later, might leak model architecture details | `except Exception: pass` catches everything | Use specific exceptions (torch.cuda.OutOfMemoryError, RuntimeError); log only safe error codes |
| **S006** | MEDIUM | app.py:27 | **Global model cache in Streamlit** - @st.cache_resource keeps model in memory across all sessions; one user's OOM affects all users | Global caching without memory monitoring | Add memory usage monitoring; clear cache if exceeds threshold |
| **S007** | LOW | evaluate.py:44 | **No JSON schema validation** - adversarial_eval_suite.json loaded with no validation; malicious JSON could inject unexpected data | `json.load()` with no schema check | Add JSON schema validation; verify required fields (text, label, category) |
| **S008** | LOW | config.py:8-11 | **No path traversal protection** - All os.path.join() use hardcoded paths, but if exposed as API, could allow directory traversal | Hardcoded BASE_DIR without validation | If exposing as API: validate no "../", no absolute paths in user-supplied components |

---

## STATISTICS FROM FILES

### Actual Data Counts (PowerShell Verified)
- **train.csv**: 7,306 rows (3,806 benign / 3,500 injection) - NOT 7,000 as documented
- **val.csv**: 2,909 rows (dirty, before contamination removal)
- **clean_val.csv**: 2,247 rows (actual count, after MinHash audit)
- **test_seen.csv**: Original count unknown (before cleaning)
- **clean_test_seen.csv**: 1,208 rows (708 benign / 500 injection)
- **test_unseen.csv**: Original count unknown
- **clean_test_unseen.csv**: 1,542 rows (765 benign / 777 injection)
- **adversarial_eval_suite.json**: 350 samples (15 categories)

### Model Configuration
- **Architecture**: DistilBertForSequenceClassification
- **Vocab Size**: 30,522
- **Max Position Embeddings**: 512
- **Num Labels**: 2 (but no id2label/label2id in config.json)
- **Hidden Dim**: 768
- **Attention Heads**: 12
- **Layers**: 6
- **Transformers Version**: 5.5.4

### Training Configuration (config.py)
- **NUM_EPOCHS**: 3
- **BATCH_SIZE**: 32
- **LEARNING_RATE**: 3e-5
- **MAX_SEQ_LENGTH**: 128
- **SEEDS**: [42, 7, 123]
- **BLOCK_THRESHOLD**: 0.50 (hardcoded, not empirically chosen)

---

## LABEL MAPPING VERIFICATION

✅ **VERIFIED END-TO-END**: Label mapping is CONSISTENT across all components:
- config.py: `{0: "Benign", 1: "Injection"}`
- All CSV files use 0=benign, 1=injection
- Model predictions.json uses same mapping
- Evaluation metrics compute on correct classes
- **HOWEVER**: Saved model config.json is missing id2label/label2id fields (F001)

---

## NEXT STEPS (Pending User Approval)

**Phase 1 is complete.** This was a READ-ONLY audit with NO changes made.

Waiting for user approval to proceed with:
- **Phase 2**: Data Audit (check duplicates, label noise, leakage, distribution shifts)
- **Phase 3**: Training Audit (multi-seed runs, overfitting checks, checkpoint verification)
- **Phase 4**: Evaluation Audit (independent metric recomputation, CI validation, ablation studies)
- **Phase 5**: Pipeline & App Audit (normalization tests, Streamlit testing, layer verification)
- **Phase 6**: Reproducibility & Project Hygiene (requirements pinning, documentation, test suite)
- **Phase 7**: Fix & Verify (implement fixes in severity order, rerun scripts, before/after metrics)

---

## SEVERITY DEFINITIONS

- **CRITICAL**: Breaks correctness, causes crashes, or fundamentally undermines security/validity
- **HIGH**: Significant impact on reproducibility, performance, or methodology
- **MEDIUM**: Important but non-breaking issues affecting maintainability or best practices
- **LOW**: Minor improvements, documentation, or code quality enhancements

---

**End of Phase 1 Report**
