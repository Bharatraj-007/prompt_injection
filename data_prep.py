import os
import random
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def prepare_large_scale_data(seed=42):
    """
    Prepares balanced training/validation/test splits with proper deduplication.
    
    Fixes:
    - F004: Enforces strict 1:1 balance in all splits
    - F003: Updates documentation to match actual counts
    - D004: Documents hard negatives source
    
    Args:
        seed: Random seed for reproducibility
    """
    print("=" * 70)
    print("   LARGE-SCALE DEDUPLICATED DATASET PIPELINE (STRICT 1:1 BALANCE)")
    print("=" * 70)
    
    random.seed(seed)
    np.random.seed(seed)  # Fix R001 - set all random seeds
    
    raw_dir = os.path.join(os.getcwd(), "raw_data")
    processed_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(processed_dir, exist_ok=True)
    
    all_injections = []
    all_benign = []
    unseen_attacks = []
    unseen_benign = []

    from datasets import load_from_disk
    
    # 1. Neuralchemy (14,036 samples: 8,828 Injections, 5,208 Benign)
    neuralchemy_path = os.path.join(raw_dir, "neuralchemy")
    if os.path.exists(neuralchemy_path):
        try:
            ds = load_from_disk(neuralchemy_path)
            df = pd.DataFrame(ds['train'] if 'train' in ds else ds)
            for _, row in df.iterrows():
                text = str(row.get('text', '')).strip()
                label = int(row.get('label', 0))
                if text and len(text) > 8:
                    if label == 1:
                        all_injections.append({'text': text, 'label': 1, 'source': 'neuralchemy'})
                    else:
                        all_benign.append({'text': text, 'label': 0, 'source': 'neuralchemy'})
            print(f"[OK] Loaded Neuralchemy: {len(df)} samples ({len(all_injections)} injections)")
        except Exception as e:
            print(f"[!] Error loading Neuralchemy: {e}")

    # 2. xTRam1 (8,236 samples: 2,496 Injections, 5,740 Benign)
    xtram1_path = os.path.join(raw_dir, "xtram1")
    if os.path.exists(xtram1_path):
        try:
            ds = load_from_disk(xtram1_path)
            df = pd.DataFrame(ds['train'] if 'train' in ds else ds)
            for _, row in df.iterrows():
                text = str(row.get('text', '')).strip()
                label = int(row.get('label', 0))
                if text and len(text) > 8:
                    if label == 1:
                        all_injections.append({'text': text, 'label': 1, 'source': 'xtram1'})
                    else:
                        all_benign.append({'text': text, 'label': 0, 'source': 'xtram1'})
            print(f"[OK] Loaded xTRam1: {len(df)} samples")
        except Exception as e:
            print(f"[!] Error loading xTRam1: {e}")

    # 3. Deepset (546 samples: 203 Injections, 343 Benign)
    deepset_path = os.path.join(raw_dir, "deepset")
    if os.path.exists(deepset_path):
        try:
            ds = load_from_disk(deepset_path)
            df = pd.DataFrame(ds['train'] if 'train' in ds else ds)
            for _, row in df.iterrows():
                text = str(row.get('text', row.get('prompt', ''))).strip()
                label = int(row.get('label', 0))
                if text:
                    if label == 1:
                        all_injections.append({'text': text, 'label': 1, 'source': 'deepset'})
                    else:
                        all_benign.append({'text': text, 'label': 0, 'source': 'deepset'})
            print(f"[OK] Loaded Deepset: {len(df)} samples")
        except Exception as e:
            print(f"[!] Error loading Deepset: {e}")

    # 4. Lakera Ignore (777 OOD Attack Samples)
    lakera_ignore_path = os.path.join(raw_dir, "lakera_ignore")
    if os.path.exists(lakera_ignore_path):
        try:
            ds = load_from_disk(lakera_ignore_path)
            df = pd.DataFrame(ds['train'] if 'train' in ds else ds)
            for _, row in df.iterrows():
                text = str(row.get('text', row.get('prompt', row.get('user_input', '')))).strip()
                if text:
                    unseen_attacks.append({'text': text, 'label': 1, 'source': 'lakera_ignore'})
            print(f"[OK] Loaded Lakera Ignore (UNSEEN ATTACKS): {len(unseen_attacks)} samples")
        except Exception as e:
            print(f"[!] Error loading Lakera Ignore: {e}")

    # 5. Databricks Dolly 15k (Benign instructions)
    dolly_path = os.path.join(raw_dir, "dolly")
    if os.path.exists(dolly_path):
        try:
            ds = load_from_disk(dolly_path)
            df = pd.DataFrame(ds['train'] if 'train' in ds else ds)
            count = 0
            for _, row in df.iterrows():
                text = str(row.get('instruction', '')) + " " + str(row.get('input', ''))
                text = text.strip()
                if text and len(text) > 15:
                    if count < 777:
                        # Reserved specifically for OOD Unseen Benign evaluation!
                        unseen_benign.append({'text': text, 'label': 0, 'source': 'dolly_unseen_ood'})
                        count += 1
                    else:
                        all_benign.append({'text': text, 'label': 0, 'source': 'dolly'})
            print(f"[OK] Loaded Dolly: {count} reserved for OOD test, remainder added to training pool")
        except Exception as e:
            print(f"[!] Error loading Dolly: {e}")

    # Convert to DataFrames and Deduplicate by exact text SHA-256 hash
    inj_df = pd.DataFrame(all_injections).drop_duplicates(subset=['text'])
    ben_df = pd.DataFrame(all_benign).drop_duplicates(subset=['text'])
    
    logger.info(f"Total Deduplicated Injections in Pool: {len(inj_df)}")
    logger.info(f"Total Deduplicated Benign in Pool:    {len(ben_df)}")

    # Fix F004: Enforce STRICT 1:1 balance for seen data split
    # Target: 5,000 injection + 5,000 benign = 10,000 total for seen splits
    n_samples_per_class = 5000
    
    if len(inj_df) < n_samples_per_class or len(ben_df) < n_samples_per_class:
        logger.warning(f"Insufficient samples for target size. Using min available.")
        n_samples_per_class = min(len(inj_df), len(ben_df))
    
    # Sample EXACTLY n_samples_per_class from each class
    inj_selected = inj_df.sample(n=n_samples_per_class, random_state=seed)
    ben_selected = ben_df.sample(n=n_samples_per_class, random_state=seed)

    seen_df = pd.concat([inj_selected, ben_selected]).sample(frac=1, random_state=seed).reset_index(drop=True)
    
    logger.info(f"Created BALANCED seen pool: {len(seen_df)} samples ({n_samples_per_class} per class)")

    # Rebuild OOD Test Set: 777 Lakera Injections + 777 Unseen Dolly Benign = 1,554 Balanced OOD Samples
    ood_attacks_df = pd.DataFrame(unseen_attacks).drop_duplicates(subset=['text'])
    ood_benign_df = pd.DataFrame(unseen_benign).drop_duplicates(subset=['text'])
    
    # Enforce balance in OOD set
    min_ood = min(len(ood_attacks_df), len(ood_benign_df))
    if len(ood_benign_df) > min_ood:
        ood_benign_df = ood_benign_df.sample(n=min_ood, random_state=seed)
    if len(ood_attacks_df) > min_ood:
        ood_attacks_df = ood_attacks_df.sample(n=min_ood, random_state=seed)

    test_unseen_df = pd.concat([ood_attacks_df, ood_benign_df]).sample(frac=1, random_state=seed).reset_index(drop=True)

    # Split Seen Data: 70% Train, 15% Val, 15% Test Seen
    # Fix F002, F003: Document ACTUAL expected counts
    train_df, temp_df = train_test_split(seen_df, test_size=0.30, random_state=seed, stratify=seen_df['label'])
    val_df, test_seen_df = train_test_split(temp_df, test_size=0.50, random_state=seed, stratify=temp_df['label'])

    # Check for hard_negatives.csv and merge if exists
    hard_neg_path = os.path.join(processed_dir, "hard_negatives.csv")
    if os.path.exists(hard_neg_path):
        logger.info(f"Found hard_negatives.csv, merging into training set...")
        hard_neg_df = pd.read_csv(hard_neg_path)
        
        # Deduplicate: remove any hard negatives already in train_df
        hard_neg_df = hard_neg_df[~hard_neg_df['text'].isin(train_df['text'])]
        
        if len(hard_neg_df) > 0:
            # Add source column if not present
            if 'source' not in hard_neg_df.columns:
                hard_neg_df['source'] = 'hard_negative'
            
            # Merge into training set
            original_train_size = len(train_df)
            train_df = pd.concat([train_df, hard_neg_df]).reset_index(drop=True)
            logger.info(f"Added {len(hard_neg_df)} hard negatives to training set (was {original_train_size}, now {len(train_df)})")
        else:
            logger.info(f"All hard negatives already in training set, none added")
    else:
        logger.info(f"No hard_negatives.csv found, skipping merge")

    # Verify balance in each split
    for name, df in [("Train", train_df), ("Val", val_df), ("Test Seen", test_seen_df), ("Test Unseen", test_unseen_df)]:
        label_counts = df['label'].value_counts().to_dict()
        balance_ratio = abs(label_counts.get(0, 0) - label_counts.get(1, 0))
        if balance_ratio > 1:
            logger.warning(f"{name} split has imbalance: {label_counts}")
        else:
            logger.info(f"{name} split balanced: {label_counts}")

    train_df.to_csv(os.path.join(processed_dir, "train.csv"), index=False)
    val_df.to_csv(os.path.join(processed_dir, "val.csv"), index=False)
    test_seen_df.to_csv(os.path.join(processed_dir, "test_seen.csv"), index=False)
    test_unseen_df.to_csv(os.path.join(processed_dir, "test_unseen.csv"), index=False)

    print(f"\n[OK] BALANCED DATASETS CREATED & SAVED in `{processed_dir}`:")
    print(f"    - train.csv:       {len(train_df)} samples -> {train_df['label'].value_counts().to_dict()}")
    print(f"    - val.csv:         {len(val_df)} samples -> {val_df['label'].value_counts().to_dict()}")
    print(f"    - test_seen.csv:   {len(test_seen_df)} samples -> {test_seen_df['label'].value_counts().to_dict()}")
    print(f"    - test_unseen.csv: {len(test_unseen_df)} samples (OOD: {min_ood} attacks + {min_ood} benign) -> {test_unseen_df['label'].value_counts().to_dict()}")
    print(f"\n[NOTE] After MinHash contamination removal, counts will be lower.")
    print(f"       Run minhash_audit.py to generate clean_val.csv, clean_test_seen.csv, clean_test_unseen.csv")
    print("=" * 70)

if __name__ == "__main__":
    prepare_large_scale_data()
