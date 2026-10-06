# Engineering Changelog & Audit Log

## [v1.0.0-frozen] - 2026-10-06

### Core Defense Architecture & Error Analysis Fixes
- **Layer 1 (Sanitization & Representation Unpacking)**:
  - **F019 (Readability Verification)**: Discovered that naive Base64/Hex candidate regex matching (`[A-Za-z0-9+/]{8,}`) captured benign 8+ character English words (e.g., `aerodynamicist`, `interception`, `challenges`), decoding them into non-Latin byte fragments. Appending these fragments into `[DECODED_PAYLOADS]:` caused the transformer's multi-view pass to elevate risk, producing 11 false alarms (3.59% FPR) on the 306-sample development hard-negative set.
  - Implemented `Layer1Preprocessor.is_readable_text()` to require that decoded candidates contain at least 90% printable ASCII, at least 50% alphabetic characters, and natural word/vowel structure.
  - Development set false alarms eliminated (0 / 306). Clean test seen multi-view false alarms reduced from 28 (3.95%) to 6 (0.85%), matching single-view baseline.
- **Layer 2 (Deterministic Rule Filter)**:
  - Maintained ReDoS protection with bounded repetitions `{8,10000}` and max string length guards (`MAX_INPUT_LENGTH = 50,000`).
- **Layer 3 (Transformer Classifier)**:
  - Production DistilBERT checkpoint fine-tuned with seed 42, deterministic PyTorch RNG, and validation F1 checkpoint selection.
  - ModernBERT and DeBERTa-v3 multi-architecture training CLI implemented in `train_all.py`.
- **Layer 4 (Score Fusion)**:
  - Re-evaluated naive weighted average ($0.5/0.5$ at threshold $0.5$) which artificially collapsed recall to 3.4% when rules scored 0.0.
  - Benchmarked validation-tuned weighted baseline ($0.3 \cdot \text{rule} + 0.7 \cdot \text{model}$ at threshold $0.35$), restoring F1 to 97.46%.
- **Layers 5 & 6 (Canary Hardening & Egress Inspection)**:
  - Documented as prompt engineering templates and output verification heuristics rather than input classification models.

### Dataset Integrity & Contamination Audit
- **MinHash Deduplication**:
  - Filtered 14,000+ raw samples down to clean deduplicated splits (`clean_val.csv`, `clean_test_seen.csv`, `clean_test_unseen.csv`).
  - Identified and removed near-duplicate contamination (Jaccard similarity $\ge 0.80$) between training and test sets.
- **Hard-Negative Evaluation**:
  - Separated initial 306 samples into an explicit **development set** (`data/hard_negatives.csv`).
  - Generated an independent, strictly held-out **evaluation hard-negative set** (`data/hard_negatives_heldout.csv`, $N = 350$) targeting technical version numbers, UUIDs, git hashes, long German compound words, product serials, code snippets with base64 data URLs, and harmless prompts containing safety-adjacent words.
  - Verified 0 / 350 MinHash matches against training data.
- **Obfuscation Suite**:
  - Constructed a 425-sample benchmark suite (`data/obfuscation_benchmark_suite.json`) across 17 distinct attack categories, contrasting 7 handled obfuscations (Base64, Hex, Leetspeak, Fullwidth, Zero-width, Spaced, Typos) against 10 novel held-out evasion vectors (Double Base64, Non-Latin Base64, Base32, ROT13, Reversed strings, Cyrillic homoglyphs, Binary, URL percent-encoding, HTML entities, and Delimiter insertion).
