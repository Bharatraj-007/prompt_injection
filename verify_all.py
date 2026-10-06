"""
Full system verification script - checks all components
"""
import os
import json
import pandas as pd

SEP = "=" * 60

# ── 1. Model files ────────────────────────────────────────────
print(SEP)
print("1. MODEL FILES")
print(SEP)
model_dirs = [
    "models/prompt_injection_detector",
    "models/distilbert_seed_42",
    "models/distilbert_seed_7",
    "models/distilbert_seed_123",
]
for folder in model_dirs:
    if os.path.exists(folder):
        files = os.listdir(folder)
        if files:
            sizes = {f: f"{round(os.path.getsize(os.path.join(folder, f))/1024/1024, 1)}MB"
                     for f in files}
            print(f"  OK   {folder}")
            for name, sz in sizes.items():
                print(f"         {name}: {sz}")
        else:
            print(f"  WARN {folder}: empty")
    else:
        print(f"  MISS {folder}")

# ── 2. Data files ─────────────────────────────────────────────
print()
print(SEP)
print("2. DATA FILES")
print(SEP)
data_files = [
    "data/train.csv",
    "data/val.csv",
    "data/clean_val.csv",
    "data/clean_test_seen.csv",
    "data/clean_test_unseen.csv",
    "data/hard_negatives.csv",
    "data/minhash_audit_report.json",
    "data/distilbert_multiseed_test_results.csv",
    "data/adversarial_benchmark_results.json",
]
for f in data_files:
    if os.path.exists(f):
        sz = round(os.path.getsize(f) / 1024, 1)
        print(f"  OK   {f}  ({sz} KB)")
    else:
        print(f"  MISS {f}")

# ── 3. Row counts and class balance ───────────────────────────
print()
print(SEP)
print("3. DATASET ROW COUNTS & CLASS BALANCE")
print(SEP)
csv_splits = [
    "data/train.csv",
    "data/val.csv",
    "data/clean_val.csv",
    "data/clean_test_seen.csv",
    "data/clean_test_unseen.csv",
]
for f in csv_splits:
    df = pd.read_csv(f)
    vc = df["label"].value_counts().sort_index().to_dict()
    benign = vc.get(0, 0)
    attack = vc.get(1, 0)
    ratio = round(benign / attack, 2) if attack else "N/A"
    print(f"  {f}: {len(df)} rows  benign={benign}  attack={attack}  ratio={ratio}")

# Check hard negatives merged
train_df = pd.read_csv("data/train.csv")
hn_df = pd.read_csv("data/hard_negatives.csv")
overlap = train_df["text"].isin(hn_df["text"]).sum()
print(f"\n  Hard negatives in train.csv: {overlap} / {len(hn_df)} merged")

# ── 4. Model config ───────────────────────────────────────────
print()
print(SEP)
print("4. MODEL CONFIG (models/prompt_injection_detector/config.json)")
print(SEP)
with open("models/prompt_injection_detector/config.json") as fh:
    cfg = json.load(fh)
for key in ["model_type", "num_labels", "id2label", "label2id"]:
    val = cfg.get(key, "MISSING")
    status = "OK" if val != "MISSING" else "MISS"
    print(f"  {status}  {key}: {val}")

# ── 5. Multi-seed results ─────────────────────────────────────
print()
print(SEP)
print("5. MULTI-SEED TRAINING RESULTS")
print(SEP)
results_path = "data/distilbert_multiseed_test_results.csv"
if os.path.exists(results_path):
    df = pd.read_csv(results_path)
    cols = ["seed", "test_seen_f1", "test_unseen_f1", "test_seen_fpr",
            "forward_latency_ms"]
    print(df[cols].to_string(index=False))
    print(f"\n  Mean test_seen_f1  : {df['test_seen_f1'].mean():.4f}")
    print(f"  Mean test_unseen_f1: {df['test_unseen_f1'].mean():.4f}")
    print(f"  Mean FPR           : {df['test_seen_fpr'].mean():.4f}")
else:
    print("  MISS distilbert_multiseed_test_results.csv")

# ── 6. Adversarial benchmark ──────────────────────────────────
print()
print(SEP)
print("6. ADVERSARIAL BENCHMARK SUMMARY")
print(SEP)
adv_path = "data/adversarial_benchmark_results.json"
if os.path.exists(adv_path):
    with open(adv_path) as fh:
        adv = json.load(fh)
    # adversarial_benchmark_results.json is a list of per-sample dicts
    if isinstance(adv, list):
        total = len(adv)
        attacks = [x for x in adv if x.get("true_label") == 1]
        benigns = [x for x in adv if x.get("true_label") == 0]
        detected = sum(1 for x in attacks if x.get("actual_decision") == "BLOCKED")
        fp = sum(1 for x in benigns if x.get("actual_decision") == "BLOCKED")
        acc = round((detected + (len(benigns) - fp)) / total * 100, 2)
        print(f"  Total samples    : {total}")
        print(f"  Attacks detected : {detected} / {len(attacks)}  ({round(detected/len(attacks)*100,1)}%)")
        print(f"  Benign FP        : {fp} / {len(benigns)}  ({round(fp/len(benigns)*100,1)}%)")
        print(f"  Overall accuracy : {acc}%")
    else:
        summary = adv.get("summary", {})
        for k, v in summary.items():
            print(f"  {k}: {v}")
else:
    print("  MISS adversarial_benchmark_results.json")

# ── 7. Plots ──────────────────────────────────────────────────
print()
print(SEP)
print("7. PLOTS")
print(SEP)
if os.path.exists("plots"):
    for f in sorted(os.listdir("plots")):
        sz = round(os.path.getsize(f"plots/{f}") / 1024, 1)
        print(f"  OK   plots/{f}  ({sz} KB)")
else:
    print("  MISS plots/ directory")

# ── 8. Core source files ──────────────────────────────────────
print()
print(SEP)
print("8. CORE SOURCE FILES")
print(SEP)
src_files = [
    "train.py", "evaluate.py", "data_prep.py", "minhash_audit.py",
    "guard.py", "app.py", "config.py",
    "crossguard/models/crossguard.py",
    "crossguard/preprocessing/sanitizer.py",
]
for f in src_files:
    if os.path.exists(f):
        lines = sum(1 for _ in open(f, encoding="utf-8", errors="ignore"))
        print(f"  OK   {f}  ({lines} lines)")
    else:
        print(f"  MISS {f}")

# ── 9. CUBLAS fix in train.py ─────────────────────────────────
print()
print(SEP)
print("9. KEY FIX VERIFICATION IN SOURCE FILES")
print(SEP)
checks = [
    ("train.py",         "CUBLAS_WORKSPACE_CONFIG",    "CUBLAS env var set before torch import"),
    ("train.py",         "warn_only=True",              "Deterministic algorithms warn_only"),
    ("data_prep.py",     "hard_negatives.csv",          "Hard negatives merge logic"),
    ("minhash_audit.py", "internal_dup_count",          "Internal dup count variable (not list)"),
    ("minhash_audit.py", "Contamination Impact Analysis","Computed contamination stats"),
    ("guard.py",         "id2label",                    "id2label loaded in guard"),
    ("crossguard/preprocessing/sanitizer.py", "12,1000",  "ReDoS fix (bounded quantifier {12,1000})"),
]
for filepath, pattern, desc in checks:
    if os.path.exists(filepath):
        content = open(filepath, encoding="utf-8", errors="ignore").read()
        found = pattern in content
        status = "OK" if found else "MISS"
        print(f"  {status}  {desc}  [{filepath}]")
    else:
        print(f"  MISS  {filepath} not found")

print()
print(SEP)
print("VERIFICATION COMPLETE")
print(SEP)
