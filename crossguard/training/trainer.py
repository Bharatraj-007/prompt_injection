import os
import time
import torch
import torch.nn as nn
import torch.nn.functional as F
import pandas as pd
import numpy as np
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, get_cosine_schedule_with_warmup
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
from crossguard.models.crossguard import CrossGuardModel
from crossguard.preprocessing.sanitizer import LosslessSanitizerEngine
from guard import Layer2RuleFilter

class CrossGuardDataset(Dataset):
    def __init__(self, df, tokenizer, sanitizer, max_seq_len=128):
        self.df = df
        self.tokenizer = tokenizer
        self.sanitizer = sanitizer
        self.max_seq_len = max_seq_len
        self.rule_filter = Layer2RuleFilter()

    def __len__(self):
        return len(self.df)

    def __getitem__(self, idx):
        row = self.df.iloc[idx]
        user_text = str(row['text'])
        label = int(row['label'])
        sys_prompt = "You are a helpful AI assistant."

        # Sanitization
        san_res = self.sanitizer.sanitize(user_text)
        cleaned_user = san_res["augmented_text"]
        char_ids = torch.tensor(san_res["char_ids"], dtype=torch.long)

        # Tokenization
        sys_tokens = self.tokenizer(sys_prompt, padding='max_length', truncation=True, max_length=64, return_tensors="pt")
        user_tokens = self.tokenizer(cleaned_user, padding='max_length', truncation=True, max_length=self.max_seq_len, return_tensors="pt")

        # Layer 2 Rule evaluation
        rule_res = self.rule_filter.evaluate(cleaned_user)
        rule_score = torch.tensor([rule_res["rule_score"]], dtype=torch.float32)

        return {
            "sys_input_ids": sys_tokens['input_ids'].squeeze(0),
            "sys_attention_mask": sys_tokens['attention_mask'].squeeze(0),
            "user_input_ids": user_tokens['input_ids'].squeeze(0),
            "user_attention_mask": user_tokens['attention_mask'].squeeze(0),
            "user_char_ids": char_ids,
            "rule_score": rule_score.squeeze(0),
            "label": torch.tensor(label, dtype=torch.long)
        }

def supervised_contrastive_loss(features, labels, temperature=0.07):
    # features: [B, D], labels: [B]
    norm_feats = F.normalize(features, dim=-1)
    sim_matrix = torch.matmul(norm_feats, norm_feats.T) / temperature
    
    labels = labels.unsqueeze(1)
    mask = torch.eq(labels, labels.T).float().to(features.device)
    
    logits_mask = torch.ones_like(mask) - torch.eye(mask.size(0)).to(features.device)
    mask = mask * logits_mask

    exp_sim = torch.exp(sim_matrix) * logits_mask
    log_prob = sim_matrix - torch.log(exp_sim.sum(dim=1, keepdim=True) + 1e-8)
    
    mean_log_prob_pos = (mask * log_prob).sum(dim=1) / (mask.sum(dim=1) + 1e-8)
    loss = -mean_log_prob_pos.mean()
    return loss

def train_crossguard(seeds=[42, 7, 123], epochs=4, batch_size=16, lr=3e-5):
    print("=" * 65)
    print("  CROSSGUARD RESEARCH TRAINING PIPELINE (RTX 4050 ACCELERATED)")
    print("=" * 65)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[+] Hardware Device: {device.type.upper()} ({torch.cuda.get_device_name(0) if device.type=='cuda' else 'CPU'})")

    data_dir = os.path.join(os.getcwd(), "data")
    train_df = pd.read_csv(os.path.join(data_dir, "train.csv"))
    val_df = pd.read_csv(os.path.join(data_dir, "val.csv"))

    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    sanitizer = LosslessSanitizerEngine()

    train_loader = DataLoader(CrossGuardDataset(train_df, tokenizer, sanitizer), batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(CrossGuardDataset(val_df, tokenizer, sanitizer), batch_size=batch_size, shuffle=False)

    seed_metrics = []

    for seed in seeds:
        print(f"\n--- Training Seed: {seed} ---")
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        np.random.seed(seed)

        model = CrossGuardModel().to(device)
        optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
        total_steps = len(train_loader) * epochs
        scheduler = get_cosine_schedule_with_warmup(optimizer, num_warmup_steps=int(total_steps*0.1), num_training_steps=total_steps)
        scaler = torch.amp.GradScaler('cuda', enabled=device.type=='cuda')

        bce_loss_fn = nn.CrossEntropyLoss()

        for epoch in range(epochs):
            model.train()
            total_loss = 0.0
            for batch in train_loader:
                optimizer.zero_grad()
                
                b_sys_ids = batch['sys_input_ids'].to(device)
                b_sys_mask = batch['sys_attention_mask'].to(device)
                b_user_ids = batch['user_input_ids'].to(device)
                b_user_mask = batch['user_attention_mask'].to(device)
                b_char_ids = batch['user_char_ids'].to(device)
                b_rule_score = batch['rule_score'].to(device)
                b_labels = batch['label'].to(device)

                with torch.amp.autocast('cuda', enabled=device.type=='cuda'):
                    outputs = model(b_sys_ids, b_sys_mask, b_user_ids, b_user_mask, b_char_ids, b_rule_score)
                    logits = outputs['logits']
                    context_vec = outputs['context_vector']

                    loss_bce = bce_loss_fn(logits, b_labels)
                    loss_saca = supervised_contrastive_loss(context_vec, b_labels)
                    loss = loss_bce + 0.1 * loss_saca

                scaler.scale(loss).backward()
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                scaler.step(optimizer)
                scaler.update()
                scheduler.step()

                total_loss += loss.item()

            print(f"  Epoch {epoch+1}/{epochs} | Training Loss: {total_loss/len(train_loader):.4f}")

        # Evaluation
        model.eval()
        y_true, y_pred, y_scores = [], [], []
        t_start = time.time()
        with torch.no_grad():
            for batch in val_loader:
                b_sys_ids = batch['sys_input_ids'].to(device)
                b_sys_mask = batch['sys_attention_mask'].to(device)
                b_user_ids = batch['user_input_ids'].to(device)
                b_user_mask = batch['user_attention_mask'].to(device)
                b_char_ids = batch['user_char_ids'].to(device)
                b_rule_score = batch['rule_score'].to(device)
                b_labels = batch['label'].to(device)

                outputs = model(b_sys_ids, b_sys_mask, b_user_ids, b_user_mask, b_char_ids, b_rule_score)
                scores = outputs['fused_score'].squeeze(-1).cpu().numpy()
                preds = (scores >= 0.5).astype(int)

                y_true.extend(b_labels.cpu().numpy())
                y_pred.extend(preds)
                y_scores.extend(scores)

        val_latency = (time.time() - t_start) * 1000 / len(val_df)
        acc = accuracy_score(y_true, y_pred)
        prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
        
        metrics = {"seed": seed, "accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "latency_ms": val_latency}
        seed_metrics.append(metrics)
        print(f"[OK] Seed {seed} Final Val Metrics: Acc={acc:.4f}, F1={f1:.4f}, Latency={val_latency:.2f}ms")

        # Save checkpoint
        if seed == seeds[0]:
            ckpt_dir = os.path.join(os.getcwd(), "checkpoints")
            os.makedirs(ckpt_dir, exist_ok=True)
            torch.save(model.state_dict(), os.path.join(ckpt_dir, "crossguard_best.pt"))
            print(f"[OK] CrossGuard Model Checkpoint saved to `{ckpt_dir}/crossguard_best.pt`")

    res_df = pd.DataFrame(seed_metrics)
    print("\n" + "=" * 65)
    print("   CROSSGUARD MULTI-SEED SUMMARY (MEAN +/- STD)")
    print("=" * 65)
    for col in ['accuracy', 'precision', 'recall', 'f1', 'latency_ms']:
        print(f"  - {col.upper():<12}: {res_df[col].mean():.4f} +/- {res_df[col].std():.4f}")

if __name__ == "__main__":
    train_crossguard()
