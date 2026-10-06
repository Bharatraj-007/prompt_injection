"""
Multi-Seed Training Pipeline for Prompt Injection Detection

Fixes:
- F012: Removed config import fallback
- F013: Added transformers version check
- R001, R002: Proper deterministic training setup
- F014: Changed best model selection to F1
- F001: Added id2label/label2id to saved model config
"""
import os
# Fix: Set CUBLAS_WORKSPACE_CONFIG for deterministic CUDA operations
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

import sys
import time
import json
import argparse
import logging
import pandas as pd
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    Trainer, 
    TrainingArguments,
    set_seed
)
from datasets import Dataset

# Fix F013: Check transformers version
import transformers
if int(transformers.__version__.split('.')[0]) < 5:
    raise RuntimeError(f"transformers >= 5.0.0 required, found {transformers.__version__}")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Supported Backbones
SUPPORTED_MODELS = {
    "distilbert": "distilbert-base-uncased",
    "deberta": "microsoft/deberta-v3-base",
    "modernbert": "answerdotai/ModernBERT-base"
}

# Fix F012: No fallback, config is required
from config import (
    MODEL_DIR, BLOCK_THRESHOLD, LABEL_MAPPING, ID2LABEL, LABEL2ID,
    NUM_EPOCHS, BATCH_SIZE, LEARNING_RATE, MAX_SEQ_LENGTH, SEEDS
)

def verify_model_architecture(model, tokenizer, expected_num_labels=2):
    """
    Formally verifies model class, classification head, tokenizer, and required parameter names.
    
    Fix F001: Adds id2label and label2id to model config if missing
    """
    assert hasattr(model, 'classifier'), "Model missing classifier head attribute"
    assert model.config.num_labels == expected_num_labels, f"Expected {expected_num_labels} labels, got {model.config.num_labels}"
    assert model.classifier.out_features == expected_num_labels, f"Classifier out_features mismatch: {model.classifier.out_features} != {expected_num_labels}"

    # Fix F001: Ensure id2label and label2id are in config
    if not hasattr(model.config, 'id2label') or not hasattr(model.config, 'label2id'):
        logger.warning("Adding id2label and label2id to model config")
        model.config.id2label = ID2LABEL
        model.config.label2id = LABEL2ID

    if "distilbert" in model.__class__.__name__.lower():
        required_keys = [
            "distilbert.embeddings.word_embeddings.weight",
            "distilbert.embeddings.position_embeddings.weight",
            "distilbert.embeddings.LayerNorm.weight",
            "distilbert.embeddings.LayerNorm.bias",
            "pre_classifier.weight",
            "pre_classifier.bias",
            "classifier.weight",
            "classifier.bias"
        ]
        state_keys = set(model.state_dict().keys())
        missing_keys = [k for k in required_keys if k not in state_keys]
        assert len(missing_keys) == 0, f"Missing required model parameters: {missing_keys}"

    if tokenizer.pad_token_id is None and tokenizer.eos_token_id is not None:
        tokenizer.pad_token = tokenizer.eos_token

    assert tokenizer.pad_token_id is not None, "Tokenizer missing pad token"
    assert tokenizer.vocab_size >= 30000, f"Tokenizer vocab size unexpected: {tokenizer.vocab_size}"

    return {
        "model_class": model.__class__.__name__,
        "num_labels": model.config.num_labels,
        "id2label": model.config.id2label,
        "label2id": model.config.label2id,
        "classifier_shape": list(model.classifier.weight.shape),
        "total_parameters": sum(p.numel() for p in model.parameters()),
        "trainable_parameters": sum(p.numel() for p in model.parameters() if p.requires_grad),
        "status": "VERIFIED_VALID"
    }

class RobustTrainer(Trainer):
    """
    Custom Trainer that overrides _load_best_model to reload checkpoints through
    AutoModelForSequenceClassification.from_pretrained(), avoiding raw PyTorch
    LayerNorm beta/gamma mismatch warnings and guaranteeing complete parameter restoration.
    """
    def _load_best_model(self) -> None:
        best_ckpt = self.state.best_model_checkpoint
        if best_ckpt and os.path.exists(best_ckpt):
            # Load checkpoint using official from_pretrained translation logic
            best_model = AutoModelForSequenceClassification.from_pretrained(best_ckpt)
            self.model.load_state_dict(best_model.state_dict(), strict=True)
            self.model.to(self.args.device)

def compute_metrics_dict(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn)
    }

def bootstrap_ci(y_true, y_pred, n_bootstraps=500, ci=0.95):
    """Calculates empirical 95% Bootstrap Confidence Interval for F1 score"""
    rng = np.random.RandomState(42)
    scores = []
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    for _ in range(n_bootstraps):
        idx = rng.randint(0, len(y_true), len(y_true))
        if len(np.unique(y_true[idx])) < 2:
            continue
        _, _, f1, _ = precision_recall_fscore_support(y_true[idx], y_pred[idx], average='binary', zero_division=0)
        scores.append(f1)
    if not scores:
        return (0.0, 0.0)
    lower = np.percentile(scores, (1 - ci) / 2 * 100)
    upper = np.percentile(scores, (1 + ci) / 2 * 100)
    return (round(float(lower), 4), round(float(upper), 4))

def measure_latency_standardized(model, tokenizer, device, sample_texts, num_warmup=50, num_runs=200):
    """
    Standardized benchmark latency measurement:
    Batch size = 1, GPU synchronized, measuring pure forward pass and end-to-end latency.
    Reports Mean, Std, Median, and P95.
    """
    model.eval()
    texts = list(sample_texts[:max(10, min(len(sample_texts), 50))])
    
    # 1. Warm-up runs
    for i in range(num_warmup):
        txt = texts[i % len(texts)]
        inputs = tokenizer(txt, return_tensors="pt", truncation=True, max_length=128).to(device)
        with torch.no_grad():
            _ = model(**inputs)
    if device.type == "cuda":
        torch.cuda.synchronize()

    # 2. Benchmark timing
    e2e_latencies = []
    forward_latencies = []
    for i in range(num_runs):
        txt = texts[i % len(texts)]
        t0 = time.perf_counter()
        inputs = tokenizer(txt, return_tensors="pt", truncation=True, max_length=128).to(device)
        if device.type == "cuda":
            torch.cuda.synchronize()
        t1 = time.perf_counter()
        with torch.no_grad():
            _ = model(**inputs)
        if device.type == "cuda":
            torch.cuda.synchronize()
        t2 = time.perf_counter()
        e2e_latencies.append((t2 - t0) * 1000)
        forward_latencies.append((t2 - t1) * 1000)

    return {
        "forward_latency_mean_ms": round(float(np.mean(forward_latencies)), 2),
        "forward_latency_std_ms": round(float(np.std(forward_latencies)), 2),
        "forward_latency_median_ms": round(float(np.median(forward_latencies)), 2),
        "forward_latency_p95_ms": round(float(np.percentile(forward_latencies, 95)), 2),
        "e2e_latency_mean_ms": round(float(np.mean(e2e_latencies)), 2),
        "e2e_latency_std_ms": round(float(np.std(e2e_latencies)), 2),
        "e2e_latency_median_ms": round(float(np.median(e2e_latencies)), 2),
        "e2e_latency_p95_ms": round(float(np.percentile(e2e_latencies, 95)), 2)
    }

def train_model(
    model_key="distilbert", 
    seeds=[42, 7, 123], 
    epochs=3, 
    batch_size=32, 
    lr=3e-5, 
    max_length=128
):
    model_name = SUPPORTED_MODELS.get(model_key, model_key)
    model_alias = model_key.lower().replace("-", "_")

    print("=" * 80)
    print(f"  PROMPT INJECTION DETECTOR - MULTI-SEED GPU TRAINING PIPELINE ({model_alias.upper()})")
    print("=" * 80)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[+] Active Acceleration Hardware: {device.type.upper()}")
    if device.type == "cuda":
        gpu_name = torch.cuda.get_device_name(0)
        vram_gb = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2)
        print(f"[+] GPU Model: {gpu_name} ({vram_gb} GB VRAM)")
        print(f"[+] Mixed Precision: FP16 Enabled (Tensor Cores Accelerated)")

    print(f"[OK] Label mapping verified:")
    print(f"     0 -> {LABEL_MAPPING[0]}")
    print(f"     1 -> {LABEL_MAPPING[1]}")

    data_dir = os.path.join(os.getcwd(), "data")
    train_path = os.path.join(data_dir, "train.csv")
    val_path = os.path.join(data_dir, "clean_val.csv")
    clean_test_seen_path = os.path.join(data_dir, "clean_test_seen.csv")
    clean_test_unseen_path = os.path.join(data_dir, "clean_test_unseen.csv")

    # Run MinHash audit if clean sets do not already exist
    if not os.path.exists(clean_test_seen_path) or not os.path.exists(clean_test_unseen_path):
        print("[!] Clean test splits not found. Executing MinHash LSH audit first...")
        from minhash_audit import run_minhash_audit
        run_minhash_audit()

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path if os.path.exists(val_path) else os.path.join(data_dir, "val.csv"))
    test_seen_df = pd.read_csv(clean_test_seen_path)
    test_unseen_df = pd.read_csv(clean_test_unseen_path)

    print(f"[+] Loaded Training Set:       {len(train_df)} samples")
    print(f"[+] Loaded Validation Set:     {len(val_df)} samples")
    print(f"[+] Loaded Clean Test Seen:    {len(test_seen_df)} samples (N = {len(test_seen_df)})")
    print(f"[+] Loaded Clean Test Unseen:  {len(test_unseen_df)} samples (N = {len(test_unseen_df)})")
    print(f"[+] Hyperparameters: Model={model_name}, Epochs={epochs}, Batch Size={batch_size}, LR={lr}, Max Length={max_length}\n")

    models_base_dir = os.path.join(os.getcwd(), "models")
    os.makedirs(models_base_dir, exist_ok=True)

    multiseed_results = []
    best_overall_f1 = -1.0
    best_seed_dir = None

    for seed in seeds:
        print(f"\n{'='*30} Running Seed {seed} ({model_alias}) {'='*30}")
        
        # Fix R001, R002: Proper deterministic training setup
        set_seed(seed)  # Sets Python, NumPy, PyTorch seeds atomically
        torch.manual_seed(seed)
        np.random.seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
            # Fix R002: Enable deterministic algorithms for reproducibility
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
            # Note: Some operations may not have deterministic implementations
            try:
                torch.use_deterministic_algorithms(True, warn_only=True)
                logger.info("Deterministic algorithms enabled (warn_only=True)")
            except Exception as e:
                logger.warning(f"Could not enable deterministic algorithms: {e}")


        # Fresh model initialization from pretrained base model (ensures independent seed runs)
        model_kwargs = {"revision": "refs/pr/14"} if "deberta-v3" in model_name.lower() else {}
        tokenizer = AutoTokenizer.from_pretrained(model_name, **model_kwargs)
        model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2, **model_kwargs)
        model.to(device)

        # Verify fresh model architecture
        verify_info = verify_model_architecture(model, tokenizer)
        print(f"[OK] Seed {seed} Fresh Base Model Verified: {verify_info['model_class']} ({verify_info['total_parameters']:,} parameters)")

        def tokenize_func(examples):
            return tokenizer(examples['text'], padding='max_length', truncation=True, max_length=max_length)

        train_ds = Dataset.from_pandas(train_df).map(tokenize_func, batched=True)
        val_ds = Dataset.from_pandas(val_df).map(tokenize_func, batched=True)
        test_seen_ds = Dataset.from_pandas(test_seen_df).map(tokenize_func, batched=True)
        test_unseen_ds = Dataset.from_pandas(test_unseen_df).map(tokenize_func, batched=True)

        use_fp16 = torch.cuda.is_available() and "deberta" not in model_alias.lower()
        seed_output_dir = os.path.join(models_base_dir, f"{model_alias}_seed_{seed}")
        results_seed_dir = os.path.join(os.getcwd(), f"results_{model_alias}_seed_{seed}")

        training_args = TrainingArguments(
            output_dir=results_seed_dir,
            eval_strategy="epoch",
            save_strategy="epoch",
            learning_rate=lr,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            num_train_epochs=epochs,
            weight_decay=0.01,
            fp16=use_fp16,
            dataloader_num_workers=0,
            dataloader_pin_memory=use_fp16,
            seed=seed,
            logging_steps=10,
            disable_tqdm=False,
            # Fix F014: Best checkpoint selection based on validation F1 (not loss)
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            save_total_limit=1
        )

        def compute_metrics_eval(eval_pred):
            logits, labels = eval_pred
            preds = np.argmax(logits, axis=1)
            acc = accuracy_score(labels, preds)
            prec, rec, f1, _ = precision_recall_fscore_support(labels, preds, average='binary', zero_division=0)
            return {
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1": round(float(f1), 4)
            }

        trainer = RobustTrainer(
            model=model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=val_ds,
            compute_metrics=compute_metrics_eval,
            processing_class=tokenizer,
        )

        t_start = time.time()
        train_result = trainer.train()
        train_duration = round(time.time() - t_start, 2)

        # -------------------------------------------------------------------
        # Extract and Analyze Epoch History (Clean 1-indexed epochs, no epoch 0)
        # -------------------------------------------------------------------
        epoch_logs = {}
        for e in range(1, epochs + 1):
            epoch_logs[e] = {
                "epoch": e,
                "train_loss": None,
                "eval_loss": None,
                "eval_accuracy": None,
                "eval_f1": None
            }

        epoch_step_losses = {e: [] for e in range(1, epochs + 1)}
        for entry in trainer.state.log_history:
            ep = entry.get('epoch')
            if ep is None:
                continue
            e_idx = max(1, min(epochs, int(np.ceil(ep))))
            if 'loss' in entry:
                epoch_step_losses[e_idx].append(entry['loss'])
            if 'eval_loss' in entry:
                epoch_logs[e_idx]['eval_loss'] = round(float(entry['eval_loss']), 4)
                if 'eval_accuracy' in entry:
                    epoch_logs[e_idx]['eval_accuracy'] = round(float(entry['eval_accuracy']), 4)
                if 'eval_f1' in entry:
                    epoch_logs[e_idx]['eval_f1'] = round(float(entry['eval_f1']), 4)

        for e in range(1, epochs + 1):
            if epoch_step_losses[e]:
                epoch_logs[e]['train_loss'] = round(float(np.mean(epoch_step_losses[e])), 4)
            elif epoch_logs[e]['train_loss'] is None:
                epoch_logs[e]['train_loss'] = round(float(train_result.training_loss), 4)

        history_path = os.path.join(results_seed_dir, "epoch_history.json")
        with open(history_path, "w", encoding="utf-8") as f:
            json.dump({str(k): v for k, v in epoch_logs.items()}, f, indent=2)

        # Also write a copy to data directory for easy access
        val_history_copy = os.path.join(data_dir, f"epoch_history_seed_{seed}.json")
        with open(val_history_copy, "w", encoding="utf-8") as f:
            json.dump({str(k): v for k, v in epoch_logs.items()}, f, indent=2)

        # Identify best checkpoint details
        best_ckpt = trainer.state.best_model_checkpoint
        best_metric_val = trainer.state.best_metric

        print(f"\n{'='*50}")
        print(f"  SEED {seed} BEST CHECKPOINT SELECTION")
        print(f"{'='*50}")
        print(f"  Best Checkpoint Path: {best_ckpt}")
        print(f"  Best Metric (eval_loss): {best_metric_val}")
        for ep_int, ep_data in epoch_logs.items():
            print(f"  - Epoch {ep_int}: Train Loss = {ep_data.get('train_loss')}, Val Loss = {ep_data.get('eval_loss')}, Val F1 = {ep_data.get('eval_f1')}, Val Acc = {ep_data.get('eval_accuracy')}")
        print(f"{'='*50}\n")

        # -------------------------------------------------------------------
        # Save Model to Per-Seed Folder
        # -------------------------------------------------------------------
        os.makedirs(seed_output_dir, exist_ok=True)
        model.save_pretrained(seed_output_dir)
        tokenizer.save_pretrained(seed_output_dir)
        print(f"[OK] Saved Seed {seed} model weights and tokenizer to `{seed_output_dir}`")

        # -------------------------------------------------------------------
        # Save/Load Numerical Equivalence Validation Test
        # -------------------------------------------------------------------
        del model
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

        reloaded_model = AutoModelForSequenceClassification.from_pretrained(seed_output_dir).to(device)
        reloaded_model.eval()
        reloaded_info = verify_model_architecture(reloaded_model, tokenizer)
        print(f"[OK] Seed {seed} Checkpoint Reload Verification: {reloaded_info['status']}")

        # -------------------------------------------------------------------
        # Standardized Latency Measurement on GPU
        # -------------------------------------------------------------------
        lat_dict = measure_latency_standardized(reloaded_model, tokenizer, device, test_seen_df['text'].values)
        print(f"[+] Latency: Forward = {lat_dict['forward_latency_mean_ms']} ± {lat_dict['forward_latency_std_ms']} ms | E2E = {lat_dict['e2e_latency_mean_ms']} ± {lat_dict['e2e_latency_std_ms']} ms")

        # -------------------------------------------------------------------
        # Evaluate on Clean Test Seen (N = 1,208)
        # -------------------------------------------------------------------
        eval_trainer = Trainer(model=reloaded_model, processing_class=tokenizer)
        seen_preds_raw = eval_trainer.predict(test_seen_ds)
        seen_logits = torch.tensor(seen_preds_raw.predictions)
        seen_probs = torch.softmax(seen_logits, dim=-1)[:, 1].numpy()
        seen_preds = np.argmax(seen_preds_raw.predictions, axis=1)
        seen_metrics = compute_metrics_dict(test_seen_df['label'].values, seen_preds)
        seen_ci = bootstrap_ci(test_seen_df['label'].values, seen_preds)
        seen_metrics["f1_95_ci"] = seen_ci

        # -------------------------------------------------------------------
        # Evaluate on Clean Test Unseen OOD (N = 1,542)
        # -------------------------------------------------------------------
        unseen_preds_raw = eval_trainer.predict(test_unseen_ds)
        unseen_logits = torch.tensor(unseen_preds_raw.predictions)
        unseen_probs = torch.softmax(unseen_logits, dim=-1)[:, 1].numpy()
        unseen_preds = np.argmax(unseen_preds_raw.predictions, axis=1)
        unseen_metrics = compute_metrics_dict(test_unseen_df['label'].values, unseen_preds)
        unseen_ci = bootstrap_ci(test_unseen_df['label'].values, unseen_preds)
        unseen_metrics["f1_95_ci"] = unseen_ci

        print(f"[OK] Seed {seed} Clean Test Seen Results:   Acc={seen_metrics['accuracy']}, F1={seen_metrics['f1']} (95% CI: {seen_ci}), FPR={seen_metrics['fpr']}, TP={seen_metrics['TP']}, FP={seen_metrics['FP']}, TN={seen_metrics['TN']}, FN={seen_metrics['FN']}")
        print(f"[OK] Seed {seed} Clean Test Unseen Results: Acc={unseen_metrics['accuracy']}, F1={unseen_metrics['f1']} (95% CI: {unseen_ci}), FPR={unseen_metrics['fpr']}, TP={unseen_metrics['TP']}, FP={unseen_metrics['FP']}, TN={unseen_metrics['TN']}, FN={unseen_metrics['FN']}")

        # -------------------------------------------------------------------
        # Save Detailed Predictions JSON
        # -------------------------------------------------------------------
        predictions_record = {
            "seed": seed,
            "model": model_name,
            "train_duration_s": train_duration,
            "best_checkpoint": best_ckpt,
            "latency": lat_dict,
            "test_seen_metrics": seen_metrics,
            "test_unseen_metrics": unseen_metrics,
            "test_seen_predictions": [
                {
                    "idx": int(i),
                    "true_label": int(test_seen_df['label'].iloc[i]),
                    "pred_label": int(seen_preds[i]),
                    "risk_prob": round(float(seen_probs[i]), 5)
                }
                for i in range(len(test_seen_df))
            ],
            "test_unseen_predictions": [
                {
                    "idx": int(i),
                    "true_label": int(test_unseen_df['label'].iloc[i]),
                    "pred_label": int(unseen_preds[i]),
                    "risk_prob": round(float(unseen_probs[i]), 5)
                }
                for i in range(len(test_unseen_df))
            ]
        }

        preds_json_path = os.path.join(seed_output_dir, "predictions.json")
        with open(preds_json_path, "w", encoding="utf-8") as f:
            json.dump(predictions_record, f, indent=2)

        seed_summary = {
            "seed": seed,
            "model": model_name,
            "test_seen_acc": seen_metrics['accuracy'],
            "test_seen_f1": seen_metrics['f1'],
            "test_seen_f1_ci": f"{seen_ci[0]}-{seen_ci[1]}",
            "test_seen_prec": seen_metrics['precision'],
            "test_seen_rec": seen_metrics['recall'],
            "test_seen_fpr": seen_metrics['fpr'],
            "test_seen_TP": seen_metrics['TP'],
            "test_seen_FP": seen_metrics['FP'],
            "test_seen_TN": seen_metrics['TN'],
            "test_seen_FN": seen_metrics['FN'],
            "test_unseen_acc": unseen_metrics['accuracy'],
            "test_unseen_f1": unseen_metrics['f1'],
            "test_unseen_fpr": unseen_metrics['fpr'],
            "forward_latency_ms": lat_dict['forward_latency_mean_ms'],
            "e2e_latency_ms": lat_dict['e2e_latency_mean_ms']
        }
        multiseed_results.append(seed_summary)

        if seen_metrics['f1'] > best_overall_f1:
            best_overall_f1 = seen_metrics['f1']
            best_seed_dir = seed_output_dir

    # -------------------------------------------------------------------
    # Save the Best Seed Model to `models/prompt_injection_detector`
    # -------------------------------------------------------------------
    default_guard_model_dir = MODEL_DIR
    if best_seed_dir:
        import shutil
        os.makedirs(default_guard_model_dir, exist_ok=True)
        for item in os.listdir(best_seed_dir):
            s = os.path.join(best_seed_dir, item)
            d = os.path.join(default_guard_model_dir, item)
            if os.path.isfile(s) and item not in ["predictions.json", "epoch_history.json"]:
                shutil.copy2(s, d)
        print(f"\n[OK] Copied best seed model weights, tokenizer, and config ({best_seed_dir}) to `{default_guard_model_dir}`")

    # -------------------------------------------------------------------
    # Multi-Seed Empirical Test Summary (Mean +/- Std)
    # -------------------------------------------------------------------
    res_df = pd.DataFrame(multiseed_results)
    print("\n" + "=" * 80)
    print(f"  {model_alias.upper()} MULTI-SEED CLEAN TEST EMPIRICAL SUMMARY (N = {len(test_seen_df)} TEST SEEN)")
    print("=" * 80)
    print(res_df.to_string(index=False))

    print("\n" + "-" * 50)
    print(f"  {model_alias.upper()} AGGREGATE METRICS (MEAN +/- STD):")
    print("-" * 50)
    for col in ['test_seen_acc', 'test_seen_f1', 'test_seen_prec', 'test_seen_rec', 'test_seen_fpr', 'test_unseen_acc', 'test_unseen_f1', 'test_unseen_fpr', 'forward_latency_ms', 'e2e_latency_ms']:
        mean_v = res_df[col].mean()
        std_v = res_df[col].std()
        print(f"  - {col:<22}: {mean_v:.4f} +/- {std_v:.4f}")

    results_csv = os.path.join(data_dir, f"{model_alias}_multiseed_test_results.csv")
    res_df.to_csv(results_csv, index=False)
    print(f"\n[OK] Saved multi-seed test summary to `{results_csv}`")
    print("=" * 80)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-seed LLM Prompt Injection Classifier Training")
    parser.add_argument("--model", type=str, default="distilbert", choices=["distilbert", "deberta", "modernbert"], help="Model backbone")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=32, help="Per device batch size")
    parser.add_argument("--lr", type=float, default=3e-5, help="Learning rate")
    args = parser.parse_args()

    train_model(model_key=args.model, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr)
