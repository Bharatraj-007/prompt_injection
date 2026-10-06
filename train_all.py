"""
train_all.py - Unified multi-model training runner

Supports:
  python train_all.py distilbert
  python train_all.py deberta
  python train_all.py modernbert
  python train_all.py all
"""
import sys
import os
import argparse

# Set UTF-8 encoding for standard output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

from train import train_model, SUPPORTED_MODELS

def main():
    parser = argparse.ArgumentParser(description="Multi-model Prompt Injection Detector Training")
    parser.add_argument("model", nargs="?", default="distilbert", choices=["distilbert", "deberta", "modernbert", "all"],
                        help="Model architecture to train (distilbert, deberta, modernbert, or all)")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--batch_size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=3e-5, help="Learning rate")
    parser.add_argument("--seeds", nargs="+", type=int, default=[42, 7, 123], help="Seeds to run")
    args = parser.parse_args()

    models_to_run = ["distilbert", "deberta", "modernbert"] if args.model == "all" else [args.model]

    for m in models_to_run:
        print("\n" + "=" * 80)
        print(f"  STARTING TRAINING FOR BACKBONE: {m.upper()}")
        print("=" * 80)
        train_model(model_key=m, seeds=args.seeds, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr)

if __name__ == "__main__":
    main()
