import os
import sys
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluate import compute_ece, compute_mcnemar_test, wilson_score_interval

def test_wilson_score_interval_bounds():
    lower, upper = wilson_score_interval(95, 100)
    assert 0.0 <= lower <= 0.95
    assert 0.95 <= upper <= 1.0
    
    # 0 successes
    low_zero, up_zero = wilson_score_interval(0, 50)
    assert low_zero == 0.0
    assert up_zero > 0.0

def test_compute_ece_perfect_calibration():
    # If confidence matches exact empirical accuracy in all bins
    # e.g., 50 samples with prob=1.0 and label=1, and 50 with prob=0.0 and label=0
    y_true = np.array([1] * 50 + [0] * 50)
    y_prob = np.array([1.0] * 50 + [0.0] * 50)
    
    ece = compute_ece(y_true, y_prob, n_bins=10)
    assert ece == pytest.approx(0.0, abs=1e-5)

def test_compute_ece_range():
    y_true = np.array([1, 0, 1, 0, 1, 0])
    y_prob = np.array([0.9, 0.2, 0.8, 0.3, 0.7, 0.4])
    ece = compute_ece(y_true, y_prob, n_bins=5)
    assert 0.0 <= ece <= 1.0

def test_compute_mcnemar_identical_predictions():
    y_true = np.array([1, 0, 1, 1, 0, 0])
    preds_a = np.array([1, 0, 1, 0, 0, 0])
    preds_b = np.array([1, 0, 1, 0, 0, 0])
    
    res = compute_mcnemar_test(y_true, preds_a, preds_b)
    assert res["b"] == 0
    assert res["c"] == 0
    assert res["statistic"] == 0.0
    assert res["p_value"] == 1.0
    assert res["significant"] is False

def test_compute_mcnemar_divergent_predictions():
    y_true = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    preds_a = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1]) # all correct
    preds_b = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) # all wrong
    
    res = compute_mcnemar_test(y_true, preds_a, preds_b)
    assert res["b"] == 10
    assert res["c"] == 0
    assert res["statistic"] > 0
    assert res["p_value"] < 0.05
    assert res["significant"] is True
