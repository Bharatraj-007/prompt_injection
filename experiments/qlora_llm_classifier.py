import os
import sys
import time
import json
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    Trainer, 
    TrainingArguments,
    BitsAndBytesConfig
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import Dataset

def train_qlora_llm():
    print("=" * 80)
    print("   QLoRA 1.5B LLM CLASSIFIER (Qwen2.5-1.5B) - RTX 4050 6GB GPU PIPELINE")
    print("=" * 80)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type != "cuda":
        print("[!] QLoRA requires NVIDIA CUDA acceleration. Skipping...")
        return

    data_dir = os.path.join(os.getcwd(), "data")
    logs_dir = os.path.join(os.getcwd(), "experiments", "logs")
    models_dir = os.path.join(os.getcwd(), "models")
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    train_df = pd.read_csv(os.path.join(data_dir, "train.csv"))
    val_df = pd.read_csv(os.path.join(data_dir, "val.csv"))
    test_seen_df = pd.read_csv(os.path.join(data_dir, "test_seen.csv"))

    model_id = "Qwen/Qwen2.5-1.5B-Instruct"
    print(f"[+] Base Model: {model_id}")
    print("[+] Quantization: 4-Bit NormalFloat4 (NF4) with Double Quantization")

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16
    )

    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        model = AutoModelForSequenceClassification.from_pretrained(
            model_id,
            num_labels=2,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True
        )
        model.config.pad_token_id = tokenizer.pad_token_id

        # Prepare model for kbit training and attach LoRA adapter
        model = prepare_model_for_kbit_training(model)

        peft_config = LoraConfig(
            r=16,
            lora_alpha=32,
            target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
            lora_dropout=0.05,
            bias="none",
            task_type="SEQ_CLS"
        )
        model = get_peft_model(model, peft_config)
        model.print_trainable_parameters()

        def tok_fn(batch):
            return tokenizer(batch['text'], padding='max_length', truncation=True, max_length=128)

        train_ds = Dataset.from_pandas(train_df).map(tok_fn, batched=True)
        val_ds = Dataset.from_pandas(val_df).map(tok_fn, batched=True)
        test_ds = Dataset.from_pandas(test_seen_df).map(tok_fn, batched=True)

        output_dir = os.path.join(models_dir, "qwen_1.5b_qlora")

        training_args = TrainingArguments(
            output_dir=output_dir,
            eval_strategy="epoch",
            save_strategy="no",
            learning_rate=2e-4,
            per_device_train_batch_size=4,
            gradient_accumulation_steps=4,
            num_train_epochs=2,
            weight_decay=0.01,
            fp16=True,
            logging_steps=10,
            disable_tqdm=True
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_ds,
            eval_dataset=val_ds
        )

        print("[+] Starting QLoRA Fine-Tuning on RTX 4050 GPU...")
        start_time = time.time()
        trainer.train()
        train_time = round(time.time() - start_time, 2)
        print(f"[OK] Completed QLoRA Training in {train_time}s")

        # Evaluate on Test Seen
        t0 = time.time()
        preds_raw = trainer.predict(test_ds)
        latency = (time.time() - t0) * 1000 / len(test_ds)

        preds = np.argmax(preds_raw.predictions, axis=1)
        labels = test_seen_df['label'].values

        acc = accuracy_score(labels, preds)
        prec, rec, f1, _ = precision_recall_fscore_support(labels, preds, average='binary', zero_division=0)
        cm = confusion_matrix(labels, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        res_dict = {
            "model_name": "QLoRA-Qwen2.5-1.5B",
            "parameters_m": 1540,
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "fpr": round(float(fpr), 4),
            "latency_ms": round(float(latency), 2),
            "train_time_sec": train_time
        }

        print(f"[OK] QLoRA Results: Acc={res_dict['accuracy']}, F1={res_dict['f1']}, FPR={res_dict['fpr']}, Latency={res_dict['latency_ms']}ms")

        with open(os.path.join(logs_dir, "qlora_qwen_1.5b_results.json"), "w") as f:
            json.dump(res_dict, f, indent=2)

        model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)
        print(f"[OK] Saved QLoRA Adapter Checkpoint to `{output_dir}`")

    except Exception as e:
        print(f"[!] QLoRA Execution Error: {e}")

if __name__ == "__main__":
    train_qlora_llm()
