"""
Guarded AI Chat Engine.

Implements the exact 6-step guarded prompt processing sequence:
1. User input ingestion & validation
2. Input security inspection through the 7-layer defense pipeline
3. Security decision gating (BLOCKED -> AI provider is NEVER called)
4. AI response generation (only for ALLOWED prompts)
5. Layer 6 Output security inspection (detects canary or system prompt leaks)
6. Final safe response delivery with comprehensive telemetry
"""

import time
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any

from guard import PromptGuardPipeline
from ai_provider import BaseAIProvider, AIResponse, AIProviderFactory, MockAIProvider
from privacy_guard import PrivacyGuard
from conversation_guard import ConversationGuard
from security_database import SecurityDatabase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class SecurityAnalysis:
    """Security telemetry captured during input inspection."""
    decision: str              # "ALLOWED" or "BLOCKED"
    is_blocked: bool
    risk_score: float          # 0.0 to 1.0
    responsible_layer: str     # e.g., "Layer 2: Rule Filter", "Layer 3: Classifier", "Layer 4: Fusion"
    explanation: str           # User-safe explanation
    matched_rules: List[str] = field(default_factory=list)
    model_score: float = 0.0
    rule_score: float = 0.0
    latency_ms: float = 0.0
    threshold: float = 0.60

@dataclass
class OutputSecurityAnalysis:
    """Security telemetry captured during output inspection."""
    decision: str              # "PASS" or "BLOCKED"
    is_safe: bool
    reasons: List[str] = field(default_factory=list)
    canary_leak: bool = False
    system_prompt_leak: bool = False
    guarded_content: str = ""

@dataclass
class GuardedChatTurn:
    """Encapsulates a single round of user prompt, security decision, and AI answer."""
    turn_id: int
    user_prompt: str
    timestamp: str
    security_analysis: SecurityAnalysis
    ai_response: Optional[AIResponse] = None
    output_security: Optional[OutputSecurityAnalysis] = None
    final_display_text: str = ""
    is_successful: bool = True
    error_message: Optional[str] = None
    pii_detected: bool = False
    pii_redaction_count: int = 0
    redacted_prompt: Optional[str] = None
    multi_turn_analysis: Optional[Any] = None
    event_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "turn_id": self.turn_id,
            "user_prompt": self.user_prompt,
            "timestamp": self.timestamp,
            "security_analysis": asdict(self.security_analysis),
            "ai_response": self.ai_response.to_dict() if self.ai_response else None,
            "output_security": asdict(self.output_security) if self.output_security else None,
            "final_display_text": self.final_display_text,
            "is_successful": self.is_successful,
            "error_message": self.error_message,
            "pii_detected": self.pii_detected,
            "pii_redaction_count": self.pii_redaction_count,
            "redacted_prompt": self.redacted_prompt,
            "event_id": self.event_id
        }

# ---------------------------------------------------------------------------
# Guarded Chat Controller
# ---------------------------------------------------------------------------

class GuardedChatEngine:
    """
    Coordinates prompt defense, upstream AI generation, and output security.
    Guarantees that malicious prompts NEVER reach upstream AI providers.
    """

    def __init__(
        self,
        guard_pipeline: Optional[PromptGuardPipeline] = None,
        pipeline: Optional[PromptGuardPipeline] = None,
        default_ai_provider: Optional[BaseAIProvider] = None,
        default_system_prompt: str = "You are a helpful and secure AI assistant.",
        privacy_guard: Optional[PrivacyGuard] = None,
        conversation_guard: Optional[ConversationGuard] = None,
        security_db: Optional[SecurityDatabase] = None
    ):
        target_pipe = guard_pipeline or pipeline
        if target_pipe is not None:
            self.guard = target_pipe
        else:
            self.guard = PromptGuardPipeline()
        self.default_ai_provider = default_ai_provider
        self.default_system_prompt = default_system_prompt
        self.privacy_guard = privacy_guard or PrivacyGuard()
        self.conversation_guard = conversation_guard or ConversationGuard()
        self.security_db = security_db or SecurityDatabase()

    def determine_responsible_layer(self, inspect_res: Dict[str, Any]) -> str:
        """Determines which security layer was primarily responsible for blocking."""
        l2 = inspect_res.get("layer2", {})
        l3 = inspect_res.get("layer3", {})
        l7 = inspect_res.get("layer7")

        if l7 and l7.get("verdict") == "INJECTION":
            return f"Layer 7: LLM as a Judge ({l7.get('model_name', 'Judge')})"
        if l2.get("matched_rules"):
            rules_str = ", ".join(l2["matched_rules"])
            return f"Layer 2: Rule Filter ({rules_str})"
        if l3.get("model_score", 0.0) >= self.guard.layer4.threshold:
            return f"Layer 3: DistilBERT Transformer (score={l3.get('model_score'):.4f})"
        if inspect_res.get("layer4", {}).get("is_blocked"):
            return "Layer 4: Multi-Layer Noisy-OR Score Fusion"
        return "Multi-Layer Defense Pipeline"

    def process_turn(
        self,
        user_prompt: str,
        turn_id: int = 1,
        system_prompt: str = "You are a helpful and secure AI assistant.",
        ai_provider: Optional[BaseAIProvider] = None,
        model_name: Optional[str] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        use_llm_judge: Optional[bool] = None,
        session_id: str = "default_session",
        enable_privacy_redaction: bool = True
    ) -> GuardedChatTurn:
        """
        Executes the exact 6-step guarded prompt processing sequence with
        PII redaction and multi-turn crescendo attack detection.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Step 1: Input Validation
        if not user_prompt or not user_prompt.strip():
            sec = SecurityAnalysis(
                decision="BLOCKED",
                is_blocked=True,
                risk_score=0.0,
                responsible_layer="Input Validator",
                explanation="Input cannot be empty. Please enter a valid prompt.",
                latency_ms=0.0
            )
            return GuardedChatTurn(
                turn_id=turn_id,
                user_prompt="",
                timestamp=timestamp,
                security_analysis=sec,
                final_display_text="⚠️ Please enter a non-empty prompt.",
                is_successful=False,
                error_message="Empty prompt rejected."
            )

        clean_user_prompt = user_prompt.strip()
        effective_ai_provider = ai_provider or self.default_ai_provider or MockAIProvider()

        # Step 2: Input Security Inspection
        t0 = time.perf_counter()
        if use_llm_judge is None:
            if isinstance(effective_ai_provider, MockAIProvider):
                use_llm_judge = False
            else:
                use_llm_judge = getattr(self.guard, 'enable_llm_judge', False)

        try:
            inspect_res = self.guard.inspect_and_defend(
                user_input=clean_user_prompt,
                system_prompt=system_prompt,
                use_llm_judge=use_llm_judge
            )
        except Exception as e:
            # Fail-closed behavior on security inspection error with secret scrubbing
            from privacy_guard import scrub_secrets_from_text
            scrubbed_err = scrub_secrets_from_text(str(e))
            logger.error(f"Security pipeline exception during inspection: {scrubbed_err}")
            sec = SecurityAnalysis(
                decision="BLOCKED",
                is_blocked=True,
                risk_score=1.0,
                responsible_layer="Security Pipeline Fail-Safe",
                explanation="Security inspection encountered an unexpected error. Enforcing fail-closed block.",
                latency_ms=round((time.perf_counter() - t0) * 1000, 2)
            )
            event_id = None
            if self.security_db is not None:
                try:
                    event_id = self.security_db.log_event(
                        event_type="chat_exception",
                        decision="BLOCKED",
                        risk_score=1.0,
                        threshold=self.guard.layer4.threshold,
                        detection_layer="Security Pipeline Fail-Safe",
                        processing_latency=round((time.perf_counter() - t0) * 1000, 2),
                        session_id=session_id,
                        error_category="SecurityInspectionException",
                        user_prompt_sanitized=clean_user_prompt
                    )
                except Exception:
                    pass
            return GuardedChatTurn(
                turn_id=turn_id,
                user_prompt=clean_user_prompt,
                timestamp=timestamp,
                security_analysis=sec,
                final_display_text="🛑 **Request Blocked:** The security verification pipeline failed closed to protect system boundaries.",
                is_successful=False,
                error_message=f"Inspection exception: {scrubbed_err}",
                event_id=event_id
            )

        # Extract inspection telemetry
        decision = inspect_res["decision"]
        risk_score = float(inspect_res["risk_score"])
        is_blocked = (decision == "BLOCKED")
        layer_info = self.determine_responsible_layer(inspect_res)

        # Multi-Turn Crescendo Analysis
        multi_turn_analysis = None
        if self.conversation_guard is not None:
            try:
                multi_turn_analysis = self.conversation_guard.analyze_multi_turn(
                    session_id=session_id,
                    current_prompt=clean_user_prompt,
                    current_turn_id=turn_id,
                    guard_pipeline=self.guard
                )
                if multi_turn_analysis.is_crescendo_attack and not is_blocked:
                    is_blocked = True
                    decision = "BLOCKED"
                    risk_score = max(risk_score, multi_turn_analysis.multi_turn_risk)
                    layer_info = f"Multi-Turn Crescendo Guard ({', '.join(multi_turn_analysis.attack_vectors)})"
            except Exception as e:
                logger.warning(f"Conversation guard exception: {e}")

        if is_blocked:
            explanation = "Prompt was flagged as a prompt injection attack and was blocked before reaching the AI provider."
        else:
            explanation = "Prompt passed all seven security layers with risk below threshold."

        sec_analysis = SecurityAnalysis(
            decision=decision,
            is_blocked=is_blocked,
            risk_score=risk_score,
            responsible_layer=layer_info,
            explanation=explanation,
            matched_rules=inspect_res.get("layer2", {}).get("matched_rules", []),
            model_score=float(inspect_res.get("layer3", {}).get("model_score", 0.0)),
            rule_score=float(inspect_res.get("layer2", {}).get("rule_score", 0.0)),
            latency_ms=float(inspect_res.get("latency_ms", round((time.perf_counter() - t0) * 1000, 2))),
            threshold=float(self.guard.layer4.threshold)
        )

        # Step 2.5: Privacy & PII Redaction
        redacted_prompt = clean_user_prompt
        pii_detected = False
        pii_count = 0
        if self.privacy_guard is not None and enable_privacy_redaction:
            try:
                p_res = self.privacy_guard.redact(clean_user_prompt)
                redacted_prompt = p_res.redacted_text
                pii_detected = p_res.has_sensitive_data
                pii_count = p_res.total_redactions
            except Exception as e:
                logger.warning(f"Privacy guard error: {e}")

        # Step 3: Security Decision Gating
        event_id = None
        if self.security_db is not None:
            try:
                event_id = self.security_db.log_event(
                    event_type="chat",
                    decision=sec_analysis.decision,
                    risk_score=sec_analysis.risk_score,
                    threshold=sec_analysis.threshold,
                    detection_layer=sec_analysis.responsible_layer,
                    processing_latency=sec_analysis.latency_ms,
                    session_id=session_id,
                    provider_name=getattr(effective_ai_provider, "provider", "AI Provider"),
                    model_name=model_name,
                    pii_redaction_count=pii_count,
                    output_guard_status="N/A" if is_blocked else "PENDING",
                    user_prompt_sanitized=redacted_prompt
                )
            except Exception as e:
                logger.warning(f"Error logging event to security database: {e}")

        # Record turn in conversation guard
        if self.conversation_guard is not None:
            try:
                self.conversation_guard.record_turn(
                    session_id=session_id,
                    turn_id=turn_id,
                    role="user",
                    content=clean_user_prompt,
                    risk_score=sec_analysis.risk_score,
                    detected_layer=sec_analysis.responsible_layer,
                    is_blocked=sec_analysis.is_blocked
                )
            except Exception as e:
                logger.warning(f"Error recording turn in conversation guard: {e}")

        if is_blocked:
            # AI PROVIDER IS NEVER CALLED
            logger.info(f"Turn {turn_id}: BLOCKED at {layer_info} with risk={risk_score:.4f}. AI provider call skipped.")
            return GuardedChatTurn(
                turn_id=turn_id,
                user_prompt=clean_user_prompt,
                timestamp=timestamp,
                security_analysis=sec_analysis,
                ai_response=None,
                output_security=None,
                final_display_text=f"🛑 **Prompt Blocked by Security Guardrails**\n\n"
                                   f"**Reason:** Potential prompt injection detected by **{layer_info}** "
                                   f"(Risk Score: `{risk_score:.4f}` | Threshold: `{self.guard.layer4.threshold}`).\n\n"
                                   f"This request was neutralized and **never forwarded** to the AI model.",
                is_successful=True,
                pii_detected=pii_detected,
                pii_redaction_count=pii_count,
                redacted_prompt=redacted_prompt,
                multi_turn_analysis=multi_turn_analysis,
                event_id=event_id
            )

        # Step 4: AI Response Generation (Only for ALLOWED prompts - with redacted prompt)
        ai_provider = effective_ai_provider

        # Build message context for provider using redacted prompt
        messages = [{"role": "system", "content": system_prompt}]
        if conversation_history:
            for past in conversation_history[-6:]:  # Keep recent context
                messages.append(past)
        messages.append({"role": "user", "content": redacted_prompt})

        canary_token = inspect_res.get("layer5", {}).get("canary_token", "")

        ai_resp = ai_provider.generate(
            messages=messages,
            model=model_name,
            canary_token=canary_token
        )

        if not ai_resp.success:
            from privacy_guard import scrub_secrets_from_text
            scrubbed_err = scrub_secrets_from_text(ai_resp.error or "Unknown provider error")
            return GuardedChatTurn(
                turn_id=turn_id,
                user_prompt=clean_user_prompt,
                timestamp=timestamp,
                security_analysis=sec_analysis,
                ai_response=ai_resp,
                output_security=None,
                final_display_text=f"⚠️ **AI Provider Notice:** {scrubbed_err}",
                is_successful=False,
                error_message=scrubbed_err,
                pii_detected=pii_detected,
                pii_redaction_count=pii_count,
                redacted_prompt=redacted_prompt,
                multi_turn_analysis=multi_turn_analysis,
                event_id=event_id
            )

        # Step 5: Output Security Inspection (Layer 6 Output Guard)
        raw_output = ai_resp.content
        out_guard_res = self.guard.layer6.verify(
            output_text=raw_output,
            canary_token=canary_token,
            system_prompt=system_prompt
        )

        is_safe = out_guard_res["is_safe"]
        leak_detected = out_guard_res["leak_detected"]
        reasons = out_guard_res.get("reasons", [])

        out_sec = OutputSecurityAnalysis(
            decision="PASS" if is_safe else "BLOCKED",
            is_safe=is_safe,
            reasons=reasons,
            canary_leak=(canary_token in raw_output) if canary_token else False,
            system_prompt_leak=("System prompt excerpt detected in output!" in reasons),
            guarded_content=out_guard_res.get("guarded_output", raw_output)
        )

        # Step 6: Final Response Assembly
        if is_safe:
            final_text = raw_output
        else:
            final_text = (
                f"🛡️ **Output Security Alert:** The AI generated a response containing sensitive or unauthorized data.\n\n"
                f"**Reasons:** {', '.join(reasons)}\n\n"
                f"The response has been redacted by Layer 6 Output Guard to prevent information leakage."
            )

        return GuardedChatTurn(
            turn_id=turn_id,
            user_prompt=clean_user_prompt,
            timestamp=timestamp,
            security_analysis=sec_analysis,
            ai_response=ai_resp,
            output_security=out_sec,
            final_display_text=final_text,
            is_successful=True,
            pii_detected=pii_detected,
            pii_redaction_count=pii_count,
            redacted_prompt=redacted_prompt,
            multi_turn_analysis=multi_turn_analysis,
            event_id=event_id
        )
