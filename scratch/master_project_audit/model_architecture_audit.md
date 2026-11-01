# MODEL ARCHITECTURE AND CHECKPOINT AUDIT REPORT

**Project:** Hybrid AI Prompt Injection Detection and Defense Platform  
**Production Checkpoint Path:** `D:\prompt_injection\models\prompt_injection_detector\model.safetensors`  
**Expected SHA-256:** `b5d574ff13f79a7d3b6bd76e387b216644c47bce1af761d15c58fd868519d1ba`  
**Observed SHA-256:** `b5d574ff13f79a7d3b6bd76e387b216644c47bce1af761d15c58fd868519d1ba` (**Verified 100% Match**)  

---

## 1. Checkpoint & Architecture Specifications

| Property | Value / Specification | Validation Status |
| :--- | :--- | :---: |
| **Model Architecture Class** | `DistilBertForSequenceClassification` | **CONFIRMED** |
| **Model Type** | `distilbert` | **CONFIRMED** |
| **Problem Type** | `single_label_classification` | **CONFIRMED** |
| **Number of Classes** | `2` (0: Benign, 1: Prompt Injection) | **CONFIRMED** |
| **Label Mapping** | `0 -> "Benign"`, `1 -> "Injection"` | **CONFIRMED** |
| **Total Parameters** | `66,955,010` (66,955,010) | **CONFIRMED** |
| **Trainable Parameters** | `66,955,010` | **CONFIRMED** |
| **Hidden Dimension ($d_{model}$)** | `768` | **CONFIRMED** |
| **Feedforward Dimension** | `3072` | **CONFIRMED** |
| **Attention Heads ($n_{heads}$)** | `12` | **CONFIRMED** |
| **Transformer Layers ($n_{layers}$)** | `6` | **CONFIRMED** |
| **Vocabulary Size** | `30522` | **CONFIRMED** |
| **Max Sequence Length** | `128` (Trained sequence length) / `512` (Positional limit) | **CONFIRMED** |
| **Activation Function** | `gelu` | **CONFIRMED** |
| **Classifier Dropout** | `0.2` | **CONFIRMED** |
| **Tensor Weight Format** | `safetensors` (Zero pickle deserialization risk) | **CONFIRMED** |
| **Weight Precision** | `float32` | **CONFIRMED** |

---

## 2. Tokenizer & Vocabulary Compatibility

* **Tokenizer Base:** `DistilBertTokenizerFast`
* **Special Tokens:**
  - `[PAD]` -> ID `0`
  - `[UNK]` -> ID `100`
  - `[CLS]` -> ID `101`
  - `[SEP]` -> ID `102`
  - `[MASK]` -> ID `103`
* **Padding Strategy:** Padded to maximum sequence length (`128`) during batch processing, with explicit attention mask propagation (`mask == 0` for padded tokens).
* **Truncation:** Right-side truncation at 128 tokens for single-view model inference, integrated with 128-token sliding window across longer texts.

---

## 3. Inference Logic & Probability Computation

* **Raw Logits:** `outputs = model(**inputs).logits` (Shape: `[batch_size, 2]`)
* **Softmax Probability:** `probs = torch.softmax(logits, dim=-1)`
* **Class Selection:** `attack_prob = probs[:, 1]` (Probability of prompt injection class)
* **Decision Boundary:** `attack_prob >= BLOCK_THRESHOLD (0.60)`
* **Fallback Behavior:** If model inference fails, fail-safe rule triggers with default safe decision.
