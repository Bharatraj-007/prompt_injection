"""
evaluate_all_fusions.py
Comprehensive evaluation of fusion variants, multi-view ablation,
hard negative false alarm analysis, and external baseline comparison.
"""
import sys
import os
import time
import json
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from guard import PromptGuardPipeline, Layer1Preprocessor, Layer2RuleFilter
from config import MODEL_DIR, BLOCK_THRESHOLD

def evaluate_metrics(y_true, scores, threshold=0.5):
    y_pred = (scores >= threshold).astype(int)
    acc = accuracy_score(y_true, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)
    }

def run_evaluation():
    print("=" * 80)
    print("  COMPREHENSIVE FUSION & MULTI-VIEW RE-EVALUATION BENCHMARK")
    print("=" * 80)

    guard = PromptGuardPipeline()
    rule_filter = guard.layer2
    model = guard.layer3.model
    tokenizer = guard.layer3.tokenizer
    device = guard.layer3.device

    # Load splits
    test_seen_df = pd.read_csv("data/clean_test_seen.csv")
    test_unseen_df = pd.read_csv("data/clean_test_unseen.csv")
    hard_neg_df = pd.read_csv("data/hard_negatives.csv")

    print(f"[+] Loaded Clean Test Seen:   {len(test_seen_df)} samples")
    print(f"[+] Loaded Clean Test Unseen: {len(test_unseen_df)} samples")
    print(f"[+] Loaded Hard Negatives:    {len(hard_neg_df)} samples")

    def extract_scores(texts, batch_size=64):
        raw_rules = []
        mv_rules = []
        raw_texts = []
        norm_texts = []
        aug_texts = []
        has_decoded_list = []

        for t in texts:
            l1 = Layer1Preprocessor.clean(str(t))
            # Rule evaluations
            r_raw = rule_filter.evaluate(str(t))["rule_score"]
            raw_rules.append(r_raw)

            r_norm = rule_filter.evaluate(l1["normalized_text"])["rule_score"]
            dec_scores = [rule_filter.evaluate(d)["rule_score"] for d in l1["decoded_payloads"]]
            r_mv = max([r_raw, r_norm] + dec_scores) if dec_scores else max(r_raw, r_norm)
            mv_rules.append(r_mv)

            raw_texts.append(str(t))
            norm_texts.append(l1["normalized_text"])
            aug_texts.append(l1["augmented_text"])
            has_decoded_list.append(bool(l1["decoded_payloads"]))

        def batch_predict(batch_texts):
            scores = []
            for i in range(0, len(batch_texts), batch_size):
                chunk = batch_texts[i:i + batch_size]
                inputs = tokenizer(chunk, return_tensors="pt", truncation=True, max_length=128, padding=True).to(device)
                with torch.no_grad():
                    logits = model(**inputs).logits
                    probs = torch.softmax(logits, dim=-1)[:, 1].cpu().tolist()
                    scores.extend(probs)
            return np.array(scores, dtype=float)

        m_raw = batch_predict(raw_texts)
        m_norm = batch_predict(norm_texts)
        m_aug = batch_predict(aug_texts)

        # Multi-view model score: max across views (if decoded payloads exist, include augmented)
        m_mv = np.maximum(m_raw, m_norm)
        for i, has_dec in enumerate(has_decoded_list):
            if has_dec:
                m_mv[i] = max(m_mv[i], m_aug[i])

        return {
            "r_raw": np.array(raw_rules, dtype=float),
            "r_mv": np.array(mv_rules, dtype=float),
            "m_raw": m_raw,
            "m_mv": m_mv
        }

    # Extract scores across datasets
    print("\n[+] Extracting pipeline feature representations for Test Seen...")
    seen_scores = extract_scores(test_seen_df['text'].tolist())

    print("[+] Extracting pipeline feature representations for Test Unseen...")
    unseen_scores = extract_scores(test_unseen_df['text'].tolist())

    print("[+] Extracting pipeline feature representations for Hard Negatives...")
    hn_scores = extract_scores(hard_neg_df['text'].tolist())

    # Define the 8 variants
    variants = [
        ("Model Only (Single-view)", lambda s: s["m_raw"]),
        ("Model Only (Multi-view)", lambda s: s["m_mv"]),
        ("Weighted Average (Single-view)", lambda s: 0.5 * s["r_raw"] + 0.5 * s["m_raw"]),
        ("Weighted Average (Multi-view)", lambda s: 0.5 * s["r_mv"] + 0.5 * s["m_mv"]),
        ("Max Fusion (Single-view)", lambda s: np.maximum(s["r_raw"], s["m_raw"])),
        ("Max Fusion (Multi-view)", lambda s: np.maximum(s["r_mv"], s["m_mv"])),
        ("Noisy-OR (Single-view)", lambda s: 1.0 - (1.0 - s["r_raw"]) * (1.0 - s["m_raw"])),
        ("Noisy-OR (Multi-view)", lambda s: 1.0 - (1.0 - s["r_mv"]) * (1.0 - s["m_mv"])),
    ]

    seen_results = []
    unseen_results = []
    hn_results = []

    for name, score_fn in variants:
        # Seen
        s_seen = score_fn(seen_scores)
        m_s = evaluate_metrics(test_seen_df['label'].values, s_seen, threshold=0.5)
        m_s["variant"] = name
        seen_results.append(m_s)

        # Unseen
        s_unseen = score_fn(unseen_scores)
        m_u = evaluate_metrics(test_unseen_df['label'].values, s_unseen, threshold=0.5)
        m_u["variant"] = name
        unseen_results.append(m_u)

        # Hard negatives (all label 0)
        s_hn = score_fn(hn_scores)
        y_hn = np.zeros(len(s_hn), dtype=int)
        fa_count = int((s_hn >= 0.5).sum())
        fa_rate = round(float(fa_count / len(s_hn)), 4)
        hn_results.append({
            "variant": name,
            "total_hard_negatives": len(s_hn),
            "false_alarms": fa_count,
            "false_alarm_rate": fa_rate
        })

    # Try external baseline (ProtectAI prompt injection model)
    ext_baseline_name = "protectai/deberta-v3-base-prompt-injection-v2"
    print(f"\n[+] Testing External Baseline: {ext_baseline_name}...")
    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        ext_tok = AutoTokenizer.from_pretrained(ext_baseline_name)
        ext_mod = AutoModelForSequenceClassification.from_pretrained(ext_baseline_name).to(device)
        ext_mod.eval()

        def ext_predict(texts, batch_size=64):
            preds = []
            for i in range(0, len(texts), batch_size):
                chunk = texts[i:i + batch_size]
                inp = ext_tok(chunk, return_tensors="pt", truncation=True, max_length=128, padding=True).to(device)
                with torch.no_grad():
                    logits = ext_mod(**inp).logits
                    probs = torch.softmax(logits, dim=-1)[:, 1].cpu().tolist()
                    preds.extend(probs)
            return np.array(preds, dtype=float)

        ext_s_seen = ext_predict(test_seen_df['text'].tolist())
        ext_m_seen = evaluate_metrics(test_seen_df['label'].values, ext_s_seen, threshold=0.5)
        ext_m_seen["variant"] = "Baseline: ProtectAI (External)"
        seen_results.append(ext_m_seen)

        ext_s_unseen = ext_predict(test_unseen_df['text'].tolist())
        ext_m_unseen = evaluate_metrics(test_unseen_df['label'].values, ext_s_unseen, threshold=0.5)
        ext_m_unseen["variant"] = "Baseline: ProtectAI (External)"
        unseen_results.append(ext_m_unseen)

        ext_s_hn = ext_predict(hard_neg_df['text'].tolist())
        ext_fa_count = int((ext_s_hn >= 0.5).sum())
        hn_results.append({
            "variant": "Baseline: ProtectAI (External)",
            "total_hard_negatives": len(ext_s_hn),
            "false_alarms": ext_fa_count,
            "false_alarm_rate": round(float(ext_fa_count / len(ext_s_hn)), 4)
        })
    except Exception as e:
        print(f"[-] External baseline could not be evaluated: {e}")

    # Build and print comparison tables
    df_seen = pd.DataFrame(seen_results)[["variant", "accuracy", "precision", "recall", "f1", "fpr"]]
    df_unseen = pd.DataFrame(unseen_results)[["variant", "accuracy", "precision", "recall", "f1", "fpr"]]
    df_hn = pd.DataFrame(hn_results)

    print("\n" + "=" * 90)
    print("  TABLE 1: CLEAN TEST SEEN PERFORMANCE (N = 1,208)")
    print("=" * 90)
    print(df_seen.to_string(index=False))

    print("\n" + "=" * 90)
    print("  TABLE 2: CLEAN TEST UNSEEN PERFORMANCE (N = 1,541)")
    print("=" * 90)
    print(df_unseen.to_string(index=False))

    print("\n" + "=" * 90)
    print("  TABLE 3: HARD NEGATIVES FALSE ALARM BENCHMARK (N = 306)")
    print("=" * 90)
    print(df_hn.to_string(index=False))

    # Save to JSON and CSV
    os.makedirs("data", exist_ok=True)
    df_seen.to_csv("data/fusion_ablation_test_seen.csv", index=False)
    df_unseen.to_csv("data/fusion_ablation_test_unseen.csv", index=False)
    df_hn.to_csv("data/fusion_ablation_hard_negatives.csv", index=False)
    print("\n[OK] Results saved to data/fusion_ablation_*.csv")

if __name__ == "__main__":
    run_evaluation()
