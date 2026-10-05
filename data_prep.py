import os
import random
import pandas as pd
from sklearn.model_selection import train_test_split

def prepare_large_scale_data(seed=42):
    print("=" * 70)
    print("   LARGE-SCALE DEDUPLICATED DATASET PIPELINE (FULL DATASET USE)")
    print("=" * 70)
    
    random.seed(seed)
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
    
    print(f"\n[+] Total Deduplicated Injections in Pool: {len(inj_df)}")
    print(f"[+] Total Deduplicated Benign in Pool:    {len(ben_df)}")

    # Balance 1:1 ratio for seen data split
    n_samples = min(len(inj_df), len(ben_df), 5000) # 5,000 Injections + 5,000 Benign = 10,000 Total Seen pool
    inj_selected = inj_df.sample(n=min(n_samples, len(inj_df)), random_state=seed)
    ben_selected = ben_df.sample(n=min(n_samples, len(ben_df)), random_state=seed)

    seen_df = pd.concat([inj_selected, ben_selected]).sample(frac=1, random_state=seed).reset_index(drop=True)

    # Rebuild OOD Test Set: 777 Lakera Injections + 777 Unseen Dolly Benign = 1,554 Balanced OOD Samples
    ood_attacks_df = pd.DataFrame(unseen_attacks).drop_duplicates(subset=['text'])
    ood_benign_df = pd.DataFrame(unseen_benign).drop_duplicates(subset=['text'])
    if len(ood_benign_df) > len(ood_attacks_df):
        ood_benign_df = ood_benign_df.sample(n=len(ood_attacks_df), random_state=seed)

    test_unseen_df = pd.concat([ood_attacks_df, ood_benign_df]).sample(frac=1, random_state=seed).reset_index(drop=True)

    # Split Seen Data: 70% Train (7,000), 15% Val (1,500), 15% Test Seen (1,500)
    train_df, temp_df = train_test_split(seen_df, test_size=0.30, random_state=seed, stratify=seen_df['label'])
    val_df, test_seen_df = train_test_split(temp_df, test_size=0.50, random_state=seed, stratify=temp_df['label'])

    train_df.to_csv(os.path.join(processed_dir, "train.csv"), index=False)
    val_df.to_csv(os.path.join(processed_dir, "val.csv"), index=False)
    test_seen_df.to_csv(os.path.join(processed_dir, "test_seen.csv"), index=False)
    test_unseen_df.to_csv(os.path.join(processed_dir, "test_unseen.csv"), index=False)

    print(f"\n[OK] LARGE-SCALE BALANCED DATASETS CREATED & SAVED in `{processed_dir}`:")
    print(f"    - train.csv:       {len(train_df)} samples (70%) -> {train_df['label'].value_counts().to_dict()}")
    print(f"    - val.csv:         {len(val_df)} samples (15%) -> {val_df['label'].value_counts().to_dict()}")
    print(f"    - test_seen.csv:   {len(test_seen_df)} samples (15%) -> {test_seen_df['label'].value_counts().to_dict()}")
    print(f"    - test_unseen.csv: {len(test_unseen_df)} samples (BALANCED OOD: 777 Lakera Attacks + 777 Dolly Benign) -> {test_unseen_df['label'].value_counts().to_dict()}")
    print("=" * 70)

if __name__ == "__main__":
    prepare_large_scale_data()
