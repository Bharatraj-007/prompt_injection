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
# Calibrated to 0.60 for Arm C Candidate (Step 4D.15 deployment)
BLOCK_THRESHOLD = 0.60

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
MAX_INPUT_LENGTH = 50000  # Maximum characters in user input (hard cap)
MAX_DECODE_SIZE = 10000   # Maximum hex/base64 string length to decode
REGEX_TIMEOUT_SECONDS = 2  # Timeout for regex operations

# Stage 2: Sliding-Window & Boundary Protection Limits (Fix 128-token blindspot)
SLIDING_WINDOW_SIZE = 128       # Window size for transformer inference (matches training distribution)
SLIDING_WINDOW_STRIDE = 64      # 50% overlap between adjacent windows to prevent boundary splits
MAX_INSPECT_TOKENS = 2048       # Maximum total tokens inspected via sliding window (~1500 words)
MAX_SLIDING_WINDOWS = 32        # Upper bound on number of windows to prevent unbounded computation
MAX_SAFE_INPUT_LENGTH = 12000   # Character threshold beyond which oversized input is explicitly rejected

# Load environment variables from .env
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"), override=False)
except ImportError:
    # Manual .env loader fallback
    env_file = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("'\""))

def get_config_var(key: str, default: str = "") -> str:
    """
    Safely get configuration variable from:
    1. streamlit.secrets (if running inside Streamlit Cloud / web environment)
    2. os.environ
    3. default value
    """
    try:
        import streamlit as st
        if hasattr(st, "secrets") and key in st.secrets:
            return str(st.secrets[key])
    except Exception:
        pass
    return os.environ.get(key, default)


# Model and Fallback Settings for Online/Cloud Hosting
HF_MODEL_REPO = get_config_var("HF_MODEL_REPO", "")
MODEL_PATH = get_config_var("MODEL_PATH", MODEL_DIR)
MODEL_FALLBACK_POLICY = get_config_var("MODEL_FALLBACK_POLICY", "fail_closed").lower()

# LLM as a Judge configurations for Defender
GROQ_API_KEY = get_config_var("GROQ_API_KEY", "")
GROK_API_KEY = get_config_var("GROK_API_KEY", "")
GEMINI_API_KEY = get_config_var("GEMINI_API_KEY", "")
OPENAI_API_KEY = get_config_var("OPENAI_API_KEY", "")
GROQ_BASE_URL = get_config_var("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
XAI_BASE_URL = get_config_var("XAI_BASE_URL", "https://api.x.ai/v1")

DEFAULT_GROQ_MODEL = get_config_var("DEFAULT_GROQ_MODEL", "qwen/qwen3.8-27b")
FAST_GROQ_MODEL = get_config_var("FAST_GROQ_MODEL", "meta-llama/llama-prompt-guard-2-86m")
DEFAULT_GROK_MODEL = get_config_var("DEFAULT_GROK_MODEL", "grok-2-latest")
DEFAULT_GEMINI_MODEL = get_config_var("DEFAULT_GEMINI_MODEL", "gemini-flash-latest")
DEFAULT_LOCAL_MODEL = get_config_var("DEFAULT_LOCAL_MODEL", "Qwen/Qwen2.5-1.5B-Instruct")

LLM_JUDGE_TEMPERATURE = 0.0
LLM_JUDGE_TIMEOUT = 15  # seconds
LLM_JUDGE_THRESHOLD = 0.50

# Staging Environment & Local Isolation Configuration (Step 5.8)
APP_ENV = get_config_var("APP_ENV", "production").lower()
LOCAL_STAGING = (
    get_config_var("LOCAL_STAGING", "").lower() in ("1", "true", "yes")
    or APP_ENV in ("staging", "local_staging")
)

# Validate paths on import
if not os.path.exists(DATA_DIR):
    logger.warning(f"DATA_DIR does not exist: {DATA_DIR}. Creating it.")
    os.makedirs(DATA_DIR, exist_ok=True)

if not os.path.exists(MODEL_DIR):
    logger.warning(f"MODEL_DIR does not exist: {MODEL_DIR}. This is expected before first training.")

logger.info(f"Configuration loaded: BASE_DIR={BASE_DIR}")
