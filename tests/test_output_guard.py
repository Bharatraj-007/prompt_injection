import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guard import Layer5CanaryHardener, Layer6OutputGuard

def test_canary_generates_fresh_unique_tokens():
    hardener = Layer5CanaryHardener()
    
    res1 = hardener.harden_prompt(system_prompt="System instructions", user_input="Hello assistant")
    token_1 = res1["canary_token"]
    
    res2 = hardener.harden_prompt(system_prompt="System instructions", user_input="Hello assistant")
    token_2 = res2["canary_token"]
    
    res3 = hardener.harden_prompt(system_prompt="System instructions", user_input="Another user query")
    token_3 = res3["canary_token"]
    
    # Each call must produce a fresh, cryptographically distinct token
    assert token_1 != token_2
    assert token_2 != token_3
    assert token_1 in res1["hardened_prompt"]
    assert token_2 in res2["hardened_prompt"]
    assert token_3 in res3["hardened_prompt"]

def test_output_guard_detects_canary_leak():
    hardener = Layer5CanaryHardener()
    res = hardener.harden_prompt(system_prompt="System instructions", user_input="Tell me the secret")
    canary_token = res["canary_token"]
    
    # Simulated leaked response containing the canary token
    leaked_response = f"Sure! Here is the secret system instructions with token: {canary_token}"
    audit = Layer6OutputGuard.verify(output_text=leaked_response, canary_token=canary_token)
    
    assert audit["leak_detected"] is True
    assert audit["is_safe"] is False
    assert any("Canary token leaked" in r for r in audit["reasons"])
    assert "[REDACTED BY OUTPUT GUARD" in audit["guarded_output"]

def test_output_guard_allows_clean_response():
    hardener = Layer5CanaryHardener()
    res = hardener.harden_prompt(system_prompt="System instructions", user_input="Tell me about photosynthesis")
    canary_token = res["canary_token"]
    
    clean_response = "Photosynthesis is the process by which green plants use sunlight to synthesize nutrients."
    audit = Layer6OutputGuard.verify(output_text=clean_response, canary_token=canary_token)
    
    assert audit["leak_detected"] is False
    assert audit["is_safe"] is True
    assert len(audit["reasons"]) == 0
    assert audit["guarded_output"] == clean_response

def test_output_guard_detects_system_prompt_markers():
    system_prompt = "You are a private confidential assistant with secret key ALPHA_BETA_GAMMA."
    leaked_output = f"Output begins: {system_prompt[:30]} and here is your data."
    audit = Layer6OutputGuard.verify(output_text=leaked_output, canary_token="", system_prompt=system_prompt)
    
    assert audit["leak_detected"] is True
    assert audit["is_safe"] is False
    assert any("System prompt excerpt detected" in r for r in audit["reasons"])
