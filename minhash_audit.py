import os
import json
import hashlib
import pandas as pd
from datasketch import MinHash, MinHashLSH

def get_minhash(text, num_perm=128, seed=42):
    m = MinHash(num_perm=num_perm, seed=seed)
    for token in str(text).lower().split():
        m.update(token.encode('utf-8'))
    return m

def compute_hash(text):
    return hashlib.sha256(str(text).strip().encode('utf-8')).hexdigest()

def run_minhash_audit(threshold=0.80, num_perm=128, seed=42):
    print("=" * 75)
    print(f"  RIGOROUS MINHASH LSH DATA CONTAMINATION & LEAKAGE AUDIT (Jaccard >= {threshold})")
    print("=" * 75)

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(BASE_DIR, "data")
    train_path = os.path.join(data_dir, "train.csv")
    val_path = os.path.join(data_dir, "val.csv")
    test_seen_path = os.path.join(data_dir, "test_seen.csv")
    test_unseen_path = os.path.join(data_dir, "test_unseen.csv")

    assert os.path.exists(train_path), f"Missing {train_path}. Run data_prep.py first."

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_seen_df = pd.read_csv(test_seen_path)
    test_unseen_df = pd.read_csv(test_unseen_path)

    # -------------------------------------------------------------------------
    # 1. Exact Duplicate Audit Across Splits
    # -------------------------------------------------------------------------
    print("[+] 1. Checking Exact String Duplicates (SHA-256):")
    train_hashes = set(train_df['text'].apply(compute_hash))
    val_hashes = set(val_df['text'].apply(compute_hash))
    test_seen_hashes = set(test_seen_df['text'].apply(compute_hash))
    test_unseen_hashes = set(test_unseen_df['text'].apply(compute_hash))

    exact_dup_train_val = len(train_hashes.intersection(val_hashes))
    exact_dup_train_seen = len(train_hashes.intersection(test_seen_hashes))
    exact_dup_val_seen = len(val_hashes.intersection(test_seen_hashes))
    exact_dup_unseen_train = len(test_unseen_hashes.intersection(train_hashes))
    exact_dup_unseen_val = len(test_unseen_hashes.intersection(val_hashes))
    exact_dup_unseen_seen = len(test_unseen_hashes.intersection(test_seen_hashes))

    print(f"    - Exact Duplicates Train vs Val:         {exact_dup_train_val}")
    print(f"    - Exact Duplicates Train vs Test Seen:   {exact_dup_train_seen}")
    print(f"    - Exact Duplicates Val vs Test Seen:     {exact_dup_val_seen}")
    print(f"    - Exact Duplicates Test Unseen vs Train: {exact_dup_unseen_train}")
    print(f"    - Exact Duplicates Test Unseen vs Val:   {exact_dup_unseen_val}")
    print(f"    - Exact Duplicates Test Unseen vs Seen:  {exact_dup_unseen_seen}\n")

    # -------------------------------------------------------------------------
    # 2. Internal Near-Duplicates within Training Set
    # -------------------------------------------------------------------------
    print("[+] 2. Checking Internal Near-Duplicates within Training Set (Jaccard >= 0.80)...")
    train_lsh_internal = MinHashLSH(threshold=threshold, num_perm=num_perm)
    train_minhashes = []
    internal_train_dups = []
    
    for idx, row in train_df.iterrows():
        m = get_minhash(row['text'], num_perm=num_perm)
        train_minhashes.append(m)
        matches = train_lsh_internal.query(m)
        if len(matches) > 0:
            internal_train_dups.append(idx)
        train_lsh_internal.insert(f"train_{idx}", m)
    
    internal_dup_count = len(internal_train_dups)
    print(f"    - Internal Train Near-Duplicates: {internal_dup_count} / {len(train_df)} ({round(internal_dup_count/len(train_df)*100, 2)}%)")
    
    if internal_dup_count > 0:
        print(f"    [WARNING] {internal_dup_count} training samples ({internal_dup_count/len(train_df)*100:.1f}%) are near-duplicates of other training samples")
        print(f"              This can cause overfitting. Consider deduplicating train.csv.")
    print()

    # -------------------------------------------------------------------------
    # 3. MinHash LSH Indexing for Contamination Checks
    # -------------------------------------------------------------------------
    print(f"[+] 3. Indexing {len(train_df)} Training Samples into Master LSH Index...")
    lsh_train = MinHashLSH(threshold=threshold, num_perm=num_perm)
    for idx, m in enumerate(train_minhashes):
        lsh_train.insert(f"train_{idx}", m)
    print("[OK] Training set indexed successfully.\n")

    quarantined_log = []

    audit_results = {
        "methodology": {
            "similarity_metric": "MinHash LSH Jaccard",
            "threshold": threshold,
            "num_perm": num_perm,
            "seed": seed,
            "rationale": (
                f"A Jaccard similarity threshold of {threshold} is selected to reliably catch "
                "verbatim matches, whitespace permutations, character substitutions, and paraphrased "
                "safety directives while avoiding false clustering on shared grammatical stop words. "
                "Note: MinHash LSH verifies lexical and n-gram shingle non-overlap; it does not claim "
                "or prove total semantic independence."
            )
        },
        "exact_duplicates": {
            "train_vs_val": exact_dup_train_val,
            "train_vs_test_seen": exact_dup_train_seen,
            "val_vs_test_seen": exact_dup_val_seen,
            "test_unseen_vs_train": exact_dup_unseen_train,
            "test_unseen_vs_val": exact_dup_unseen_val,
            "test_unseen_vs_seen": exact_dup_unseen_seen
        },
        "internal_train_near_duplicates": {
            "count": internal_dup_count,
            "percentage": round(internal_dup_count / len(train_df) * 100, 2)
        },
        "splits_audit": {}
    }

    # Core splits to audit against train
    splits = [
        ("val", val_df, "clean_val.csv"),
        ("test_seen", test_seen_df, "clean_test_seen.csv"),
        ("test_unseen", test_unseen_df, "clean_test_unseen.csv")
    ]

    # Include hard_negatives.csv if it exists
    hard_neg_path = os.path.join(data_dir, "hard_negatives.csv")
    if os.path.exists(hard_neg_path):
        hard_neg_df = pd.read_csv(hard_neg_path)
        splits.append(("hard_negatives", hard_neg_df, "clean_hard_negatives.csv"))

    for split_name, df, clean_filename in splits:
        clean_rows = []
        near_duplicates = 0
        benign_dups = 0
        injection_dups = 0

        for idx, row in df.iterrows():
            m = get_minhash(row['text'], num_perm=num_perm, seed=seed)
            matches = lsh_train.query(m)
            if len(matches) > 0:
                near_duplicates += 1
                lbl = int(row.get('label', 0))
                if lbl == 0:
                    benign_dups += 1
                else:
                    injection_dups += 1
                quarantined_log.append({
                    "split": split_name,
                    "index": int(idx),
                    "reason": "Near-duplicate with train.csv",
                    "text_preview": str(row['text'])[:100],
                    "label": lbl,
                    "matched_train_ids": matches
                })
            else:
                clean_rows.append(row)

        clean_df = pd.DataFrame(clean_rows)
        clean_path = os.path.join(data_dir, clean_filename)
        clean_df.to_csv(clean_path, index=False)

        contamination_pct = round((near_duplicates / len(df)) * 100, 2) if len(df) > 0 else 0.0
        audit_results["splits_audit"][split_name] = {
            "total_samples": len(df),
            "near_duplicates_with_train": near_duplicates,
            "benign_near_duplicates": benign_dups,
            "injection_near_duplicates": injection_dups,
            "contamination_percentage": contamination_pct,
            "clean_samples_remaining": len(clean_df),
            "label_distribution": clean_df['label'].value_counts().to_dict() if 'label' in clean_df.columns else {},
            "clean_file_path": clean_path
        }

        print(f"[+] Split `{split_name}` Audit Against Train (Jaccard >= {threshold}):")
        print(f"    - Original Total:        {len(df)} samples")
        print(f"    - Near-duplicates found: {near_duplicates} ({contamination_pct}%) [Benign: {benign_dups}, Injection: {injection_dups}]")
        print(f"    - Clean Set Saved:       `{clean_filename}` (N = {len(clean_df)})\n")

    # Audit adversarial_eval_suite.json against train
    adv_suite_path = os.path.join(data_dir, "adversarial_eval_suite.json")
    if os.path.exists(adv_suite_path):
        with open(adv_suite_path, "r", encoding="utf-8") as f:
            adv_data = json.load(f)
        adv_df = pd.DataFrame(adv_data)
        adv_near_dups = 0
        for idx, row in adv_df.iterrows():
            m = get_minhash(row['text'], num_perm=num_perm, seed=seed)
            matches = lsh_train.query(m)
            if len(matches) > 0:
                adv_near_dups += 1
                quarantined_log.append({
                    "split": "adversarial_eval_suite",
                    "index": int(idx),
                    "reason": "Near-duplicate with train.csv",
                    "text_preview": str(row['text'])[:100],
                    "matched_train_ids": matches
                })
        print(f"[+] Adversarial Evaluation Suite Audit Against Train (N = {len(adv_df)}):")
        print(f"    - Near-duplicates with training: {adv_near_dups} / {len(adv_df)} ({round(adv_near_dups/len(adv_df)*100, 2)}%)\n")
        audit_results["splits_audit"]["adversarial_eval_suite"] = {
            "total_samples": len(adv_df),
            "near_duplicates_with_train": adv_near_dups
        }

    # -------------------------------------------------------------------------
    # 4. Cross-Split Overlap Remediation: Enforce Zero Cross-Split Overlap
    # -------------------------------------------------------------------------
    print("[+] 4. Enforcing Cross-Split Near-Duplicate Elimination...")
    val_clean_df = pd.read_csv(os.path.join(data_dir, "clean_val.csv"))
    test_seen_clean_df = pd.read_csv(os.path.join(data_dir, "clean_test_seen.csv"))
    test_unseen_clean_df = pd.read_csv(os.path.join(data_dir, "clean_test_unseen.csv"))

    val_lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    for idx, row in val_clean_df.iterrows():
        val_lsh.insert(f"val_{idx}", get_minhash(row['text'], num_perm=num_perm, seed=seed))

    # Remove any test_seen samples that overlap with val
    deduped_seen_rows = []
    val_seen_removals = 0
    for idx, row in test_seen_clean_df.iterrows():
        m = get_minhash(row['text'], num_perm=num_perm, seed=seed)
        matches = val_lsh.query(m)
        if len(matches) > 0:
            val_seen_removals += 1
            quarantined_log.append({
                "split": "clean_test_seen",
                "index": int(idx),
                "reason": "Cross-split overlap with clean_val",
                "text_preview": str(row['text'])[:100]
            })
        else:
            deduped_seen_rows.append(row)

    if val_seen_removals > 0:
        test_seen_clean_df = pd.DataFrame(deduped_seen_rows)
        test_seen_clean_df.to_csv(os.path.join(data_dir, "clean_test_seen.csv"), index=False)
        print(f"    - Quarantined {val_seen_removals} test_seen samples overlapping with val.csv")

    # Index clean_test_seen for unseen comparison
    seen_lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    for idx, row in test_seen_clean_df.iterrows():
        seen_lsh.insert(f"seen_{idx}", get_minhash(row['text'], num_perm=num_perm, seed=seed))

    # Remove any test_unseen samples that overlap with val or test_seen
    deduped_unseen_rows = []
    unseen_cross_removals = 0
    for idx, row in test_unseen_clean_df.iterrows():
        m = get_minhash(row['text'], num_perm=num_perm, seed=seed)
        if len(val_lsh.query(m)) > 0 or len(seen_lsh.query(m)) > 0:
            unseen_cross_removals += 1
            quarantined_log.append({
                "split": "clean_test_unseen",
                "index": int(idx),
                "reason": "Cross-split overlap with clean_val or clean_test_seen",
                "text_preview": str(row['text'])[:100]
            })
        else:
            deduped_unseen_rows.append(row)

    if unseen_cross_removals > 0:
        test_unseen_clean_df = pd.DataFrame(deduped_unseen_rows)
        test_unseen_clean_df.to_csv(os.path.join(data_dir, "clean_test_unseen.csv"), index=False)
        print(f"    - Quarantined {unseen_cross_removals} test_unseen samples overlapping with seen/val")

    print(f"    - Final Clean Val Samples:         {len(val_clean_df)}")
    print(f"    - Final Clean Test Seen Samples:    {len(test_seen_clean_df)}")
    print(f"    - Final Clean Test Unseen Samples:  {len(test_unseen_clean_df)}\n")

    # Save detailed quarantined samples log
    quarantine_path = os.path.join(data_dir, "quarantined_contaminated_samples.json")
    with open(quarantine_path, "w", encoding="utf-8") as f:
        json.dump(quarantined_log, f, indent=2)
    print(f"[OK] Logged {len(quarantined_log)} quarantined contaminated samples to `{quarantine_path}`")

    report_path = os.path.join(data_dir, "minhash_audit_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(audit_results, f, indent=2)

    print(f"[OK] Comprehensive MinHash Audit Report successfully saved to `{report_path}`")
    print("=" * 75)
    return audit_results

if __name__ == "__main__":
    run_minhash_audit()
