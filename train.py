import os
import time
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

def compute_metrics_dict(y_true, y_pred, latency_ms=0.0):
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
        "latency_ms": round(float(latency_ms), 2)
    }

def train_model(seeds=[42, 7, 123], model_name="distilbert-base-uncased", epochs=4, batch_size=32, lr=3e-5, max_length=128):
    print("=" * 60)
    print("  PROMPT INJECTION DETECTOR - RTX 4050 GPU TRAINING PIPELINE")
    print("=" * 60)
    
    import torch
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[+] Active Acceleration Hardware: {device.type.upper()}")
    if device.type == "cuda":
        gpu_name = torch.cuda.get_device_name(0)
        vram_gb = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2)
        print(f"[+] GPU Model: {gpu_name} ({vram_gb} GB VRAM)")
        print(f"[+] Mixed Precision: FP16 Enabled (Tensor Cores Accelerated)")

    data_dir = os.path.join(os.getcwd(), "data")
    train_path = os.path.join(data_dir, "train.csv")
    val_path = os.path.join(data_dir, "val.csv")
    
    if not os.path.exists(train_path) or not os.path.exists(val_path):
        print("[!] Dataset files not found. Running data_prep.py first...")
        from data_prep import prepare_data
        prepare_data()

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)

    print(f"[+] Loaded Training Data: {len(train_df)} rows")
    print(f"[+] Loaded Validation Data: {len(val_df)} rows")
    print(f"[+] Hyperparameters: Epochs={epochs}, Batch Size={batch_size}, LR={lr}, Max Length={max_length}\n")

    seed_results = []
    output_model_dir = os.path.join(os.getcwd(), "models", "prompt_injection_detector")
    os.makedirs(output_model_dir, exist_ok=True)

    from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
    from datasets import Dataset

    for seed in seeds:
        print(f"--- Running RTX 4050 Training with Seed: {seed} ---")
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        np.random.seed(seed)

        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
        model.to(device)

        def tokenize_func(examples):
            return tokenizer(examples['text'], padding='max_length', truncation=True, max_length=max_length)

        train_ds = Dataset.from_pandas(train_df).map(tokenize_func, batched=True)
        val_ds = Dataset.from_pandas(val_df).map(tokenize_func, batched=True)

        use_fp16 = torch.cuda.is_available()

        training_args = TrainingArguments(
            output_dir=os.path.join(os.getcwd(), f"results_seed_{seed}"),
            eval_strategy="epoch",
            save_strategy="epoch",
            learning_rate=lr,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            num_train_epochs=epochs,
            weight_decay=0.01,
            fp16=use_fp16, # Hardware FP16 acceleration for RTX 4050
            dataloader_num_workers=0, # Optimized for Windows PyTorch
            dataloader_pin_memory=use_fp16,
            seed=seed,
            logging_steps=10,
            disable_tqdm=False
        )

        def compute_metrics_eval(eval_pred):
            logits, labels = eval_pred
            preds = np.argmax(logits, axis=1)
            return compute_metrics_dict(labels, preds)

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=val_ds,
            compute_metrics=compute_metrics_eval,
        )

        t_start = time.time()
        trainer.train()
        train_time = round(time.time() - t_start, 2)
        print(f"[OK] Completed Training Seed {seed} on GPU in {train_time}s")

        # Record validation latency on GPU
        start_t = time.time()
        preds_raw = trainer.predict(val_ds)
        inference_time = (time.time() - start_t) * 1000 / max(1, len(val_ds))

        preds = np.argmax(preds_raw.predictions, axis=1)
        metrics = compute_metrics_dict(val_df['label'].values, preds, latency_ms=inference_time)
        metrics['seed'] = seed
        seed_results.append(metrics)
        print(f"[OK] Seed {seed} GPU Results: Acc={metrics['accuracy']}, F1={metrics['f1']}, FPR={metrics['fpr']}, Latency={metrics['latency_ms']}ms")

        # Save the best seed model artifacts
        if seed == seeds[0]:
            model.save_pretrained(output_model_dir)
            tokenizer.save_pretrained(output_model_dir)
            print(f"[OK] RTX 4050 GPU Fine-Tuned Model Checkpoint saved to `{output_model_dir}`")

    # Calculate Mean and Standard Deviation across seeds
    res_df = pd.DataFrame(seed_results)
    print("\n" + "=" * 60)
    print("   RTX 4050 MULTI-SEED GPU EVALUATION SUMMARY (MEAN +/- STD)")
    print("=" * 60)
    for col in ['accuracy', 'precision', 'recall', 'f1', 'fpr', 'latency_ms']:
        mean_val = res_df[col].mean()
        std_val = res_df[col].std()
        print(f"  - {col.upper():<12}: {mean_val:.4f} +/- {std_val:.4f}")
    
    summary_path = os.path.join(data_dir, "training_metrics.csv")
    res_df.to_csv(summary_path, index=False)
    print(f"\n[OK] Saved GPU training metrics summary to `{summary_path}`")

if __name__ == "__main__":
    train_model()
