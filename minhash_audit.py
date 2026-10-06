import os
import json
import hashlib
import pandas as pd
from datasketch import MinHash, MinHashLSH

def get_minhash(text, num_perm=128):
    m = MinHash(num_perm=num_perm)
    for token in str(text).lower().split():
        m.update(token.encode('utf-8'))
    return m

def compute_hash(text):
    return hashlib.sha256(str(text).strip().encode('utf-8')).hexdigest()

def run_minhash_audit(threshold=0.80, num_perm=128):
    print("=" * 75)
    print(f"  RIGOROUS MINHASH LSH DATA CONTAMINATION & LEAKAGE AUDIT (Jaccard >= {threshold})")
    print("=" * 75)

    data_dir = os.path.join(os.getcwd(), "data")
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

    audit_results = {
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

    splits = [
        ("val", val_df, "clean_val.csv"),
        ("test_seen", test_seen_df, "clean_test_seen.csv"),
        ("test_unseen", test_unseen_df, "clean_test_unseen.csv")
    ]

    for split_name, df, clean_filename in splits:
        clean_rows = []
        near_duplicates = 0
        benign_dups = 0
        injection_dups = 0

        for idx, row in df.iterrows():
            m = get_minhash(row['text'], num_perm=num_perm)
            matches = lsh_train.query(m)
            if len(matches) > 0:
                near_duplicates += 1
                if int(row['label']) == 0:
                    benign_dups += 1
                else:
                    injection_dups += 1
            else:
                clean_rows.append(row)

        clean_df = pd.DataFrame(clean_rows)
        clean_path = os.path.join(data_dir, clean_filename)
        clean_df.to_csv(clean_path, index=False)

        contamination_pct = round((near_duplicates / len(df)) * 100, 2)
        audit_results["splits_audit"][split_name] = {
            "total_samples": len(df),
            "near_duplicates_with_train": near_duplicates,
            "benign_near_duplicates": benign_dups,
            "injection_near_duplicates": injection_dups,
            "contamination_percentage": contamination_pct,
            "clean_samples_remaining": len(clean_df),
            "label_distribution": clean_df['label'].value_counts().to_dict(),
            "clean_file_path": clean_path
        }

        print(f"[+] Split `{split_name}.csv` Audit Against Train (Jaccard >= {threshold}):")
        print(f"    - Original Total:        {len(df)} samples")
        print(f"    - Near-duplicates found: {near_duplicates} ({contamination_pct}%) [Benign: {benign_dups}, Injection: {injection_dups}]")
        print(f"    - Clean Set Saved:       `{clean_filename}` (N = {len(clean_df)})")
        print(f"    - Clean Class Balance:   {clean_df['label'].value_counts().to_dict()}\n")

    # -------------------------------------------------------------------------
    # 4. Cross-Split Overlap: Val vs Test Seen & Test Unseen vs Seen Splits
    # -------------------------------------------------------------------------
    print("[+] 4. Checking Cross-Split Near-Duplicates (Val vs Test Seen & Unseen Isolation)...")
    val_clean_df = pd.read_csv(os.path.join(data_dir, "clean_val.csv"))
    test_seen_clean_df = pd.read_csv(os.path.join(data_dir, "clean_test_seen.csv"))
    test_unseen_clean_df = pd.read_csv(os.path.join(data_dir, "clean_test_unseen.csv"))

    val_lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    for idx, row in val_clean_df.iterrows():
        val_lsh.insert(f"val_{idx}", get_minhash(row['text'], num_perm=num_perm))

    val_vs_seen_overlap = 0
    for idx, row in test_seen_clean_df.iterrows():
        m = get_minhash(row['text'], num_perm=num_perm)
        if len(val_lsh.query(m)) > 0:
            val_vs_seen_overlap += 1

    seen_lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    for idx, row in test_seen_clean_df.iterrows():
        seen_lsh.insert(f"seen_{idx}", get_minhash(row['text'], num_perm=num_perm))

    unseen_vs_val_overlap = 0
    unseen_vs_seen_overlap = 0
    for idx, row in test_unseen_clean_df.iterrows():
        m = get_minhash(row['text'], num_perm=num_perm)
        if len(val_lsh.query(m)) > 0:
            unseen_vs_val_overlap += 1
        if len(seen_lsh.query(m)) > 0:
            unseen_vs_seen_overlap += 1

    audit_results["cross_split_leakage"] = {
        "clean_val_vs_clean_test_seen_near_duplicates": val_vs_seen_overlap,
        "clean_test_unseen_vs_clean_val_near_duplicates": unseen_vs_val_overlap,
        "clean_test_unseen_vs_clean_test_seen_near_duplicates": unseen_vs_seen_overlap
    }

    print(f"    - Clean Val vs Clean Test Seen Overlap:       {val_vs_seen_overlap} samples")
    print(f"    - Clean Test Unseen vs Clean Val Overlap:     {unseen_vs_val_overlap} samples")
    print(f"    - Clean Test Unseen vs Clean Test Seen Overlap:{unseen_vs_seen_overlap} samples\n")

    # -------------------------------------------------------------------------
    # 5. Compute and Report Actual Contamination Statistics
    # -------------------------------------------------------------------------
    # Compute actual overlap statistics dynamically
    val_benign_count = int((val_df['label'] == 0).sum())
    val_injection_count = int((val_df['label'] == 1).sum())
    test_seen_benign_count = int((test_seen_df['label'] == 0).sum())
    test_seen_injection_count = int((test_seen_df['label'] == 1).sum())
    
    clean_val_benign = int((pd.read_csv(os.path.join(data_dir, "clean_val.csv"))['label'] == 0).sum())
    clean_test_seen_benign = int((pd.read_csv(os.path.join(data_dir, "clean_test_seen.csv"))['label'] == 0).sum())
    
    benign_removed_val = val_benign_count - clean_val_benign
    benign_removed_test = test_seen_benign_count - clean_test_seen_benign
    
    print(f"[+] Contamination Impact Analysis:")
    print(f"    - Original val.csv: {val_benign_count} benign, {val_injection_count} injection")
    print(f"    - Original test_seen.csv: {test_seen_benign_count} benign, {test_seen_injection_count} injection")
    print(f"    - Benign samples removed from val: {benign_removed_val} ({benign_removed_val/val_benign_count*100:.1f}%)")
    print(f"    - Benign samples removed from test_seen: {benign_removed_test} ({benign_removed_test/test_seen_benign_count*100:.1f}%)")
    print(f"    - Final clean_val benign count: {clean_val_benign}")
    print(f"    - Final clean_test_seen benign count: {clean_test_seen_benign}")
    
    if clean_val_benign == clean_test_seen_benign:
        print(f"\n[NOTE] Both clean splits have exactly {clean_val_benign} benign samples because:")
        print(f"       - Both started with {val_benign_count} benign samples (stratified split)")
        print(f"       - Both had {benign_removed_val} near-duplicates with training removed")
        print(f"       - This occurs when both splits sampled from the same benign source pool")
    print()

    audit_results["contamination_impact"] = {
        "val_original_benign": val_benign_count,
        "test_seen_original_benign": test_seen_benign_count,
        "val_benign_removed": benign_removed_val,
        "test_seen_benign_removed": benign_removed_test,
        "val_final_benign": clean_val_benign,
        "test_seen_final_benign": clean_test_seen_benign
    }

    report_path = os.path.join(data_dir, "minhash_audit_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(audit_results, f, indent=2)

    print(f"[OK] Comprehensive MinHash Audit Report successfully saved to `{report_path}`")
    print("=" * 75)
    return audit_results

if __name__ == "__main__":
    run_minhash_audit()
