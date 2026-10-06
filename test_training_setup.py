"""
Quick test to verify training setup before full run
"""
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

import torch
import transformers

print("=" * 70)
print("TRAINING SETUP VERIFICATION")
print("=" * 70)

# Check environment
print(f"✅ CUBLAS_WORKSPACE_CONFIG: {os.environ.get('CUBLAS_WORKSPACE_CONFIG', 'NOT SET')}")
print(f"✅ PyTorch version: {torch.__version__}")
print(f"✅ Transformers version: {transformers.__version__}")
print(f"✅ CUDA available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"✅ CUDA device: {torch.cuda.get_device_name(0)}")

# Test deterministic algorithms
print("\nTesting deterministic algorithms...")
try:
    torch.use_deterministic_algorithms(True, warn_only=True)
    print("✅ Deterministic algorithms enabled (warn_only=True)")
except Exception as e:
    print(f"❌ Could not enable deterministic algorithms: {e}")

# Check data files
print("\nChecking data files...")
data_files = [
    "data/train.csv",
    "data/val.csv",
    "data/clean_val.csv",
    "data/clean_test_seen.csv",
    "data/clean_test_unseen.csv",
    "data/hard_negatives.csv"
]

for f in data_files:
    exists = os.path.exists(f)
    status = "✅" if exists else "⚠️"
    print(f"{status} {f}: {'exists' if exists else 'missing'}")

# Check model directory
print("\nChecking model directory...")
model_dir = "models/prompt_injection_detector"
if os.path.exists(model_dir):
    files = os.listdir(model_dir)
    print(f"✅ {model_dir} exists ({len(files)} files)")
else:
    print(f"⚠️ {model_dir} does not exist yet (will be created during training)")

print("\n" + "=" * 70)
print("READY TO TRAIN!")
print("=" * 70)
print("\nRun:")
print("  python train.py --model distilbert --epochs 3")
