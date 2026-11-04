"""
Hugging Face Model Upload Utility (Option 3: Hybrid Architecture)

Uploads your locally trained prompt injection classifier from 'models/prompt_injection_detector'
directly to your personal Hugging Face Model Hub repository.
"""

import os
import sys
import argparse
import logging
from typing import Tuple, List
from config import MODEL_DIR

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


REQUIRED_FILES = [
    "config.json",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json"
]


def verify_local_model_files(model_dir: str = MODEL_DIR) -> Tuple[bool, List[str]]:
    """Checks whether the local model directory contains all required artifacts."""
    missing = []
    for fname in REQUIRED_FILES:
        fpath = os.path.join(model_dir, fname)
        if not os.path.exists(fpath):
            missing.append(fname)
    return (len(missing) == 0, missing)


def upload_to_hub(repo_id: str, local_model_dir: str = MODEL_DIR, hf_token: str = None):
    """Pushes tokenizer and model weights to Hugging Face Hub."""
    if not os.path.exists(local_model_dir):
        logger.error(f"Local model directory '{local_model_dir}' does not exist.")
        return False

    is_complete, missing_files = verify_local_model_files(local_model_dir)
    if not is_complete:
        logger.error(f"Local model directory is missing required files: {missing_files}")
        return False
    logger.info(f"Verified all required model artifacts in '{local_model_dir}': {REQUIRED_FILES}")

    token = hf_token or os.environ.get("HF_TOKEN")
    if not token:
        logger.warning(
            "No Hugging Face token provided. Ensure you are already logged in via 'huggingface-cli login' "
            "or provide --token or set the HF_TOKEN environment variable."
        )

    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        logger.info(f"Loading local model and tokenizer from '{local_model_dir}'...")
        tokenizer = AutoTokenizer.from_pretrained(local_model_dir)
        model = AutoModelForSequenceClassification.from_pretrained(local_model_dir)

        # Ensure label mapping is explicitly configured
        from config import ID2LABEL, LABEL2ID
        model.config.id2label = ID2LABEL
        model.config.label2id = LABEL2ID

        logger.info(f"Uploading tokenizer to Hugging Face Hub repository '{repo_id}'...")
        tokenizer.push_to_hub(repo_id, token=token)

        logger.info(f"Uploading model weights to Hugging Face Hub repository '{repo_id}'...")
        model.push_to_hub(repo_id, token=token)

        logger.info("=" * 60)
        logger.info(f"🎉 Model successfully published to: https://huggingface.co/{repo_id}")
        logger.info("=" * 60)
        return True
    except Exception as e:
        logger.error(f"Failed to upload model to Hugging Face Hub: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Upload trained model to Hugging Face Hub.")
    parser.add_argument(
        "--repo-id",
        type=str,
        required=True,
        help="Hugging Face repo name (e.g., your-username/prompt-injection-distilbert)"
    )
    parser.add_argument(
        "--model-dir",
        type=str,
        default=MODEL_DIR,
        help=f"Local model folder to upload (default: {MODEL_DIR})"
    )
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="Hugging Face Write Token (get it from https://huggingface.co/settings/tokens)"
    )
    args = parser.parse_args()

    success = upload_to_hub(args.repo_id, args.model_dir, args.token)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
