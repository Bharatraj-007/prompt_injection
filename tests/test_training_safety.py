import os
import sys
import torch
import tempfile
import pytest
import numpy as np
from transformers import DistilBertConfig, DistilBertForSequenceClassification
from sklearn.utils.class_weight import compute_class_weight

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from train import check_model_weights_valid, MODEL_DIR

def test_check_model_weights_valid_detects_corrupted_weights():
    # If the real model exists, check that it passes verification
    if os.path.exists(MODEL_DIR):
        assert check_model_weights_valid(MODEL_DIR) is True

    # Test detection of NaN and Inf weights on a tiny dummy model
    with tempfile.TemporaryDirectory() as tmpdir:
        config = DistilBertConfig(
            vocab_size=100,
            dim=32,
            n_layers=1,
            n_heads=2,
            hidden_dim=64,
            num_labels=2
        )
        model = DistilBertForSequenceClassification(config)
        model.save_pretrained(tmpdir)
        
        # Valid weights should pass
        assert check_model_weights_valid(tmpdir) is True

        # Corrupt weights with NaN
        with torch.no_grad():
            for param in model.parameters():
                param[0] = float('nan')
                break
        model.save_pretrained(tmpdir)
        assert check_model_weights_valid(tmpdir) is False

        # Corrupt weights with Inf
        with torch.no_grad():
            for param in model.parameters():
                param[0] = float('inf')
                break
        model.save_pretrained(tmpdir)
        assert check_model_weights_valid(tmpdir) is False

def test_class_weight_computation_balanced():
    # 80 benign, 20 injection (imbalanced)
    labels = np.array([0] * 80 + [1] * 20)
    weights = compute_class_weight("balanced", classes=np.array([0, 1]), y=labels)
    
    assert len(weights) == 2
    # Class 1 should have higher weight than Class 0 to counter imbalance
    assert weights[1] > weights[0]
    assert np.isclose(weights[0], 100 / (2 * 80))
    assert np.isclose(weights[1], 100 / (2 * 20))
