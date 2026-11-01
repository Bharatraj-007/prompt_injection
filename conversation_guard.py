"""
Conversation Guard: Multi-Turn Crescendo Attack Detection Module.

Detects distributed prompt injection and privilege escalation attacks executed
across multiple conversation turns (e.g. crescendo attacks, token fragmentation,
gradual instruction escalation, and distributed system prompt extraction).

Key Architecture:
- Strict Session Isolation (keyed by session_id).
- Sliding History Window (default: 5 turns, max configurable: 10 turns).
- Trajectory Analysis: Detects incremental escalation of risk/directives.
- Context Stitching: Evaluates unified dialogue against the 7-layer security pipeline.
"""

import time
import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ConversationTurnRecord:
    """Represents a recorded conversation turn within a session."""
    turn_id: int
    role: str
    content: str
    timestamp: float
    risk_score: float = 0.0
    detected_layer: Optional[str] = None
    is_blocked: bool = False


@dataclass
class MultiTurnAnalysis:
    """Security assessment of multi-turn conversation trajectory."""
    is_crescendo_attack: bool
    multi_turn_risk: float
    decision: str  # "ALLOWED", "BLOCKED", "REVIEW REQUIRED"
    suspicious_turns: List[int]
    attack_vectors: List[str]
    explanation: str
    combined_context_preview: str
    latency_ms: float = 0.0


class ConversationGuard:
    """
    Guards conversational sessions against multi-turn crescendo attacks
    and fragmented prompt injections.
    """

    # Fragmented instruction triggers that indicate multi-turn assembly
    FRAGMENTED_KEYWORDS = [
        re.compile(r"(?i)\bremember\s+(?:the\s+word|this\s+part|token|phrase|word)\s*[:=]?\s*['\"]?([a-z0-9_]+)['\"]?"),
        re.compile(r"(?i)\bcombine\s+(?:the|those|these|all|previous)?\s*(?:words|tokens|parts|inputs)"),
        re.compile(r"(?i)\bput\s+(?:them|those|these|the\s+tokens|all)\s+together"),
        re.compile(r"(?i)\bnow\s+(?:execute|run|do|follow|apply)\s*(?:it|them|what\s+I\s+said|the\s+combined)?"),
        re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|original|base)\s+(?:rules|instructions|constraints|prompts)")
    ]

    ESCALATION_MARKERS = [
        re.compile(r"(?i)\bhypothetically\b"),
        re.compile(r"(?i)\bfor\s+research\s+purposes\s+only\b"),
        re.compile(r"(?i)\bjust\s+between\s+you\s+and\s+me\b"),
        re.compile(r"(?i)\bnow\s+that\s+we\s+established\s+that\b"),
        re.compile(r"(?i)\bstep\s+[0-9]+(?:\s+is\s+complete|\s+done)\b"),
        re.compile(r"(?i)\bdisable\s+safety\b|\bbypass\s+guard\b")
    ]

    def __init__(self, default_window_size: int = 5, max_window_size: int = 10, threshold: float = 0.60):
        self.default_window_size = default_window_size
        self.max_window_size = max_window_size
        self.threshold = threshold
        # Session storage: session_id -> List[ConversationTurnRecord]
        self._sessions: Dict[str, List[ConversationTurnRecord]] = {}

    def get_session_history(self, session_id: str, limit: Optional[int] = None) -> List[ConversationTurnRecord]:
        """Returns the conversation history for a specific session."""
        history = self._sessions.get(session_id, [])
        win = limit or self.default_window_size
        win = min(win, self.max_window_size)
        return history[-win:]

    def record_turn(
        self,
        session_id: str,
        turn_id: int,
        role: str,
        content: str,
        risk_score: float = 0.0,
        detected_layer: Optional[str] = None,
        is_blocked: bool = False
    ):
        """Records a completed turn in session memory."""
        if session_id not in self._sessions:
            self._sessions[session_id] = []
        
        record = ConversationTurnRecord(
            turn_id=turn_id,
            role=role,
            content=content,
            timestamp=time.time(),
            risk_score=risk_score,
            detected_layer=detected_layer,
            is_blocked=is_blocked
        )
        self._sessions[session_id].append(record)

        # Enforce memory safety cap per session (max 50 turns kept in memory)
        if len(self._sessions[session_id]) > 50:
            self._sessions[session_id] = self._sessions[session_id][-50:]

    def clear_session(self, session_id: str):
        """Resets conversation history for a given session."""
        if session_id in self._sessions:
            del self._sessions[session_id]

    def analyze_multi_turn(
        self,
        session_id: str,
        current_prompt: str,
        current_turn_id: int,
        guard_pipeline: Optional[Any] = None,
        window_size: Optional[int] = None
    ) -> MultiTurnAnalysis:
        """
        Evaluates current prompt in the context of recent turns to detect
        multi-turn crescendo, fragmented payloads, or progressive escalation.
        """
        t0 = time.perf_counter()
        win = window_size or self.default_window_size
        win = max(1, min(win, self.max_window_size))

        history = self.get_session_history(session_id, limit=win)
        # Only active, unblocked turns form the live conversational context that could lead to crescendo
        user_history = [t for t in history if t.role == "user" and not t.is_blocked]

        suspicious_turns: List[int] = []
        attack_vectors: List[str] = []
        combined_prompts: List[str] = [t.content for t in user_history] + [current_prompt]

        # 1. Fragmented Token & Word Assembly Detection
        fragment_hits = 0
        all_user_text = " \n ".join(combined_prompts)
        for pattern in self.FRAGMENTED_KEYWORDS:
            if pattern.search(all_user_text):
                fragment_hits += 1

        if fragment_hits >= 2:
            attack_vectors.append("FRAGMENTED_INSTRUCTION_ASSEMBLY")
            for t in user_history:
                suspicious_turns.append(t.turn_id)
            suspicious_turns.append(current_turn_id)

        # 2. Escalation Velocity (Trajectory Analysis)
        # Check if user prompts show increasing directive pressure or safety bypass markers
        escalation_hits = 0
        for pattern in self.ESCALATION_MARKERS:
            if pattern.search(all_user_text):
                escalation_hits += 1

        if escalation_hits >= 2:
            attack_vectors.append("GRADUAL_CRESCENDO_ESCALATION")
            suspicious_turns.append(current_turn_id)

        # 3. Context Stitching & Security Pipeline Evaluation
        # Stitch all user prompts together and run through guard pipeline if available
        stitched_text = " ".join([p.strip() for p in combined_prompts if p.strip()])
        stitched_risk = 0.0

        if guard_pipeline is not None and len(user_history) > 0:
            try:
                # Inspect combined conversational context
                # Disable LLM judge during combined check to prevent excessive latency
                orig_judge_state = getattr(guard_pipeline, "enable_llm_judge", False)
                guard_pipeline.enable_llm_judge = False
                res = guard_pipeline.inspect_and_defend(
                    user_input=stitched_text,
                    system_prompt="Analyze multi-turn conversation context."
                )
                guard_pipeline.enable_llm_judge = orig_judge_state
                
                # Authoritative pipeline risk score retrieval with fail-closed safety
                raw_stitched = res.get("risk_score")
                if raw_stitched is None:
                    raw_stitched = res.get("fused_score")
                
                if raw_stitched is not None:
                    try:
                        stitched_risk = float(raw_stitched)
                        if not (0.0 <= stitched_risk <= 1.0):
                            logger.warning(f"Invalid stitched_risk {stitched_risk}; failing closed to 1.0")
                            stitched_risk = 1.0
                    except (TypeError, ValueError) as err:
                        logger.warning(f"Unparseable stitched_risk '{raw_stitched}': {err}; failing closed to 1.0")
                        stitched_risk = 1.0
                elif res.get("decision") == "BLOCKED" or res.get("is_blocked") is True:
                    stitched_risk = 1.0
                else:
                    logger.warning("Missing risk_score in multi-turn inspection; failing closed to 1.0")
                    stitched_risk = 1.0

                if stitched_risk >= self.threshold:
                    if "STITCHED_CONTEXT_INJECTION" not in attack_vectors:
                        attack_vectors.append("STITCHED_CONTEXT_INJECTION")
                        for t in user_history:
                            if t.turn_id not in suspicious_turns:
                                suspicious_turns.append(t.turn_id)
                        if current_turn_id not in suspicious_turns:
                            suspicious_turns.append(current_turn_id)
            except Exception as e:
                logger.error(f"Fail-closed: Error in multi-turn context inspection: {e}")
                stitched_risk = 1.0
                if "CONTEXT_INSPECTION_ERROR" not in attack_vectors:
                    attack_vectors.append("CONTEXT_INSPECTION_ERROR")
                suspicious_turns.append(current_turn_id)

        # Calculate combined multi-turn risk
        base_crescendo_bonus = 0.0
        if fragment_hits >= 2:
            base_crescendo_bonus = max(base_crescendo_bonus, 0.65 + (fragment_hits - 2) * 0.10)
        if escalation_hits >= 2:
            base_crescendo_bonus = max(base_crescendo_bonus, 0.65 + (escalation_hits - 2) * 0.10)

        multi_turn_risk = min(1.0, max(stitched_risk, base_crescendo_bonus))

        # Check if benign discussion about cybersecurity or linguistics
        if "academic" in all_user_text.lower() or "research" in all_user_text.lower():
            if multi_turn_risk < 0.85:
                # Modulate false-positive risk for academic queries
                multi_turn_risk = max(0.0, multi_turn_risk - 0.20)

        # Decision
        is_attack = multi_turn_risk >= self.threshold and len(attack_vectors) > 0
        if is_attack:
            decision = "BLOCKED"
            explanation = (
                f"Multi-turn Crescendo Attack detected across {len(user_history) + 1} turns. "
                f"Attack vectors: {', '.join(attack_vectors)}. Combined Context Risk: {multi_turn_risk:.4f}."
            )
        elif multi_turn_risk >= 0.40 and len(attack_vectors) > 0:
            decision = "REVIEW REQUIRED"
            explanation = (
                f"Suspicious conversational escalation detected across recent turns. "
                f"Vectors: {', '.join(attack_vectors)}. Risk: {multi_turn_risk:.4f}."
            )
        else:
            decision = "ALLOWED"
            explanation = "Conversation history shows benign progression with no multi-turn instruction override."

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        preview = stitched_text[:200] + ("..." if len(stitched_text) > 200 else "")

        return MultiTurnAnalysis(
            is_crescendo_attack=is_attack,
            multi_turn_risk=round(multi_turn_risk, 4),
            decision=decision,
            suspicious_turns=sorted(list(set(suspicious_turns))),
            attack_vectors=attack_vectors,
            explanation=explanation,
            combined_context_preview=preview,
            latency_ms=latency_ms
        )
