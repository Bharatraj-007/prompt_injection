"""
Centralized Configuration for Prompt Injection Detection System

This module provides all configuration constants, paths, and hyperparameters
with validation to ensure paths exist and values are sensible.

Fixes: F028 (path validation), F012 (single source of truth)
"""
import os
import logging
from typing import Dict

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Centralized system configurations and paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_DIR = os.path.join(MODELS_DIR, "prompt_injection_detector")
DATA_DIR = os.path.join(BASE_DIR, "data")
PLOTS_DIR = os.path.join(BASE_DIR, "plots")

# Ensure critical directories exist
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR, exist_ok=True)

# Label mapping with explicit id2label and label2id for model config (Fix F001)
LABEL_MAPPING: Dict[int, str] = {
    0: "Benign (Safe Prompt)",
    1: "Prompt Injection (Attack)"
}

ID2LABEL: Dict[int, str] = {
    0: "Benign",
    1: "Injection"
}

LABEL2ID: Dict[str, int] = {
    "Benign": 0,
    "Injection": 1
}

# Decision threshold for the hybrid security pipeline
# This will be empirically optimized on clean_val.csv during evaluation
# Default: 0.50 (will be updated by evaluate.py threshold sweep)
BLOCK_THRESHOLD = 0.50

# Training Hyperparameters (as specified in requirements - do not modify without justification)
NUM_EPOCHS = 3
BATCH_SIZE = 32
LEARNING_RATE = 3e-5
MAX_SEQ_LENGTH = 128
SEEDS = [42, 7, 123]

# Score Fusion Method - Noisy-OR probabilistic combination (Fix F005)
# Formula: fused_score = 1 - (1 - rule_score) * (1 - model_score)
# This ensures high confidence in either detector is preserved
FUSION_METHOD = "noisy_or"  # Options: "noisy_or", "weighted_average"

# Security limits (Fix S001, S002, S003, S017)
MAX_INPUT_LENGTH = 50000  # Maximum characters in user input
MAX_DECODE_SIZE = 10000   # Maximum hex/base64 string length to decode
REGEX_TIMEOUT_SECONDS = 2  # Timeout for regex operations

# Validate paths on import
if not os.path.exists(DATA_DIR):
    logger.warning(f"DATA_DIR does not exist: {DATA_DIR}. Creating it.")
    os.makedirs(DATA_DIR, exist_ok=True)

if not os.path.exists(MODEL_DIR):
    logger.warning(f"MODEL_DIR does not exist: {MODEL_DIR}. This is expected before first training.")

logger.info(f"Configuration loaded: BASE_DIR={BASE_DIR}")
