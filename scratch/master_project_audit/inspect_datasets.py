import pandas as pd
import json

datasets = [
    'clean_test_seen.csv', 
    'clean_test_unseen.csv', 
    'clean_val.csv', 
    'hard_negatives.csv', 
    'hard_negatives_heldout.csv', 
    'train.csv', 
    'val.csv', 
    'test_seen.csv', 
    'test_unseen.csv'
]

for d in datasets:
    path = f'data/{d}'
    try:
        df = pd.read_csv(path)
        dist = df['label'].value_counts().to_dict() if 'label' in df.columns else 'no label'
        print(f"{d:30s} | Shape: {str(df.shape):15s} | Label Dist: {dist}")
    except Exception as e:
        print(f"{d:30s} | Error: {e}")

# Also inspect suites
for s in ['adversarial_eval_suite.json', 'obfuscation_benchmark_suite.json']:
    try:
        with open(f'data/{s}', 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                print(f"{s:30s} | Items: {len(data):15d} | Type: list")
            elif isinstance(data, dict):
                print(f"{s:30s} | Keys: {list(data.keys())} | Type: dict")
    except Exception as e:
        print(f"{s:30s} | Error: {e}")
