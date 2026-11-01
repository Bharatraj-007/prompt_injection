"""
Unit Tests for Red-Team Benchmark (Feature 5).
"""

import pytest
from redteam_benchmark import RedTeamBenchmark


def test_dataset_composition():
    bench = RedTeamBenchmark()
    dataset = bench.dataset
    assert len(dataset) == 100
    
    attacks = [s for s in dataset if s.expected_label == "ATTACK"]
    benign = [s for s in dataset if s.expected_label == "BENIGN"]
    assert len(attacks) == 50
    assert len(benign) == 50

    # Verify math representation (specifically 1+1)
    math_samples = [s for s in dataset if s.category == "Mathematics"]
    assert len(math_samples) >= 10
    assert any(s.prompt == "1+1" for s in math_samples)


def test_benchmark_execution_and_metrics():
    bench = RedTeamBenchmark()
    # Execute small slice of 8 samples (4 attacks, 4 benign)
    summary = bench.run_benchmark(max_samples=8)
    assert summary.total_samples == 8
    assert summary.avg_latency_ms >= 0.0
    assert 0.0 <= summary.detection_rate_pct <= 100.0
    assert 0.0 <= summary.false_positive_rate_pct <= 100.0

    csv_data = bench.export_benchmark_csv(summary)
    assert "Sample ID" in csv_data
    assert "Expected Label" in csv_data


def test_sample_level_risk_score_populated():
    """Verify sample detail results capture actual non-zero pipeline risk scores."""
    class MockBenchPipeline:
        def __init__(self):
            self.enable_llm_judge = False
        def inspect_and_defend(self, user_input, system_prompt=None):
            if "ignore" in user_input.lower():
                return {"decision": "BLOCKED", "risk_score": 0.96, "is_blocked": True, "neutralized_by": "Layer 2"}
            return {"decision": "ALLOWED", "risk_score": 0.04, "is_blocked": False}

    bench = RedTeamBenchmark(guard_pipeline=MockBenchPipeline())
    summary = bench.run_benchmark(max_samples=5)
    # Check that sample results have non-zero risk score reflecting pipeline
    for r in summary.sample_results:
        assert isinstance(r.risk_score, float)
        assert 0.0 <= r.risk_score <= 1.0
    
    # ATK-01 has "ignore" so risk score must be 0.96
    atk1 = next(r for r in summary.sample_results if r.sample_id == "ATK-01")
    assert atk1.risk_score == 0.96
    assert atk1.predicted_decision == "BLOCKED"

