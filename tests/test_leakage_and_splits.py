import os
import pandas as pd
import pytest

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

@pytest.fixture(scope="module")
def datasets():
    train_path = os.path.join(DATA_DIR, "train.csv")
    val_path = os.path.join(DATA_DIR, "clean_val.csv")
    seen_path = os.path.join(DATA_DIR, "clean_test_seen.csv")
    unseen_path = os.path.join(DATA_DIR, "clean_test_unseen.csv")

    data = {}
    if os.path.exists(train_path):
        data["train"] = pd.read_csv(train_path)
    if os.path.exists(val_path):
        data["val"] = pd.read_csv(val_path)
    if os.path.exists(seen_path):
        data["seen"] = pd.read_csv(seen_path)
    if os.path.exists(unseen_path):
        data["unseen"] = pd.read_csv(unseen_path)
    return data

def test_labels_are_binary(datasets):
    for split_name, df in datasets.items():
        assert "label" in df.columns, f"{split_name} missing 'label' column"
        unique_labels = set(df["label"].unique())
        assert unique_labels.issubset({0, 1}), f"{split_name} contains non-binary labels: {unique_labels}"

def test_no_empty_texts(datasets):
    for split_name, df in datasets.items():
        assert "text" in df.columns, f"{split_name} missing 'text' column"
        assert df["text"].isna().sum() == 0, f"{split_name} contains NaN texts"
        empty_count = (df["text"].str.strip() == "").sum()
        assert empty_count == 0, f"{split_name} contains empty strings"

def test_no_exact_duplicate_leakage(datasets):
    if "train" not in datasets:
        pytest.skip("train.csv not available")
    
    train_texts = set(datasets["train"]["text"].str.strip().str.lower())

    for eval_split in ["val", "seen", "unseen"]:
        if eval_split in datasets:
            eval_texts = set(datasets[eval_split]["text"].str.strip().str.lower())
            intersection = train_texts.intersection(eval_texts)
            assert len(intersection) == 0, (
                f"Contamination detected! {len(intersection)} exact duplicates found between "
                f"train.csv and clean_{eval_split}.csv. Example: {list(intersection)[:3]}"
            )

def test_cross_eval_split_isolation(datasets):
    if "val" in datasets and "seen" in datasets:
        val_texts = set(datasets["val"]["text"].str.strip().str.lower())
        seen_texts = set(datasets["seen"]["text"].str.strip().str.lower())
        assert len(val_texts.intersection(seen_texts)) == 0, "Overlap found between val and test_seen"

    if "val" in datasets and "unseen" in datasets:
        val_texts = set(datasets["val"]["text"].str.strip().str.lower())
        unseen_texts = set(datasets["unseen"]["text"].str.strip().str.lower())
        assert len(val_texts.intersection(unseen_texts)) == 0, "Overlap found between val and test_unseen"
