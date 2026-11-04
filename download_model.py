"""
Model Downloader & Hugging Face Hub Sync Utility

Downloads fine-tuned or pre-trained prompt injection detection models from
Hugging Face Hub into the local models directory for offline or containerized serving.
"""

import os
import sys
import argparse
import logging
from config import BASE_DIR, MODELS_DIR, MODEL_DIR

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_HF_MODEL = "protectai/deberta-v3-base-prompt-injection"


def download_model(repo_id: str, target_dir: str = MODEL_DIR):
    """Downloads model and tokenizer from Hugging Face Hub to target directory."""
    logger.info(f"Connecting to Hugging Face Hub to download '{repo_id}'...")
    os.makedirs(target_dir, exist_ok=True)

    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        logger.info("Downloading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(repo_id)
        tokenizer.save_pretrained(target_dir)

        logger.info("Downloading model weights...")
        model = AutoModelForSequenceClassification.from_pretrained(repo_id)
        model.save_pretrained(target_dir)

        logger.info(f"Model successfully saved to '{target_dir}'.")
        return True
    except Exception as e:
        logger.error(f"Failed to download model '{repo_id}': {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Download model weights for online deployment.")
    parser.add_argument(
        "--repo-id",
        type=str,
        default=os.environ.get("HF_MODEL_REPO", DEFAULT_HF_MODEL),
        help=f"Hugging Face repository ID (default: {DEFAULT_HF_MODEL})"
    )
    parser.add_argument(
        "--target-dir",
        type=str,
        default=MODEL_DIR,
        help=f"Target local directory (default: {MODEL_DIR})"
    )
    args = parser.parse_args()

    success = download_model(args.repo_id, args.target_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
