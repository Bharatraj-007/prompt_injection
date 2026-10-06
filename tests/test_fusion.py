"""
Test Suite for Layer 4 Score Fusion

Fix F025: Expanded test coverage for fusion layer
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guard import Layer4ScoreFusion

class TestScoreFusion:
    """Test Noisy-OR fusion logic"""
    
    def setup_method(self):
        """Setup test fusion layer"""
        self.fusion = Layer4ScoreFusion(threshold=0.50)
    
    def test_noisy_or_formula(self):
        """Verify noisy-OR formula: 1 - (1-r)*(1-m)"""
        # Perfect agreement: both detect attack
        result = self.fusion.fuse(1.0, 1.0)
        assert result["fused_score"] == 1.0
        
        # Both indicate benign
        result = self.fusion.fuse(0.0, 0.0)
        assert result["fused_score"] == 0.0
        
        # One detector fires: fused should preserve high score
        result = self.fusion.fuse(0.9, 0.1)
        expected = 1.0 - (1.0 - 0.9) * (1.0 - 0.1)  # = 1 - 0.1*0.9 = 0.91
        assert abs(result["fused_score"] - expected) < 0.01
    
    def test_high_confidence_preservation(self):
        """Verify that high confidence in either detector is preserved"""
        # Rule detector very confident
        result = self.fusion.fuse(0.95, 0.1)
        assert result["fused_score"] >= 0.95, "High rule score should be preserved"
        
        # Model very confident
        result = self.fusion.fuse(0.1, 0.95)
        assert result["fused_score"] >= 0.95, "High model score should be preserved"
    
    def test_threshold_decision(self):
        """Test blocking decision based on threshold"""
        # Above threshold
        result = self.fusion.fuse(0.6, 0.5)
        assert result["is_blocked"] == True
        assert result["decision"] == "BLOCKED"
        
        # Below threshold
        result = self.fusion.fuse(0.3, 0.2)
        assert result["is_blocked"] == False
        assert result["decision"] == "ALLOWED"
        
        # Exactly at threshold
        self.fusion.threshold = 0.50
        result = self.fusion.fuse(0.3, 0.3)  # fused = 1-(0.7*0.7) = 0.51
        assert result["is_blocked"] == True
    
    def test_score_bounding(self):
        """Test that scores are properly bounded to [0, 1]"""
        # Test with out-of-range inputs
        result = self.fusion.fuse(1.5, 0.5)  # Should clip to 1.0
        assert 0.0 <= result["fused_score"] <= 1.0
        
        result = self.fusion.fuse(-0.1, 0.5)  # Should clip to 0.0
        assert 0.0 <= result["fused_score"] <= 1.0
    
    def test_rounding_precision(self):
        """Verify scores are rounded to 4 decimal places"""
        result = self.fusion.fuse(0.123456789, 0.987654321)
        assert len(str(result["fused_score"]).split('.')[-1]) <= 4
    
    def test_component_scores_preserved(self):
        """Verify original component scores are returned"""
        result = self.fusion.fuse(0.7, 0.8)
        assert result["rule_score"] == 0.7
        assert result["model_score"] == 0.8
        assert "fused_score" in result
        assert "threshold" in result
