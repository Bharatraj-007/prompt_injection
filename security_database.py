"""
Security Database Module for Hybrid AI Security Platform.

Provides a structured, indexed SQLite storage layer for security audit events,
redacted prompt metadata, and benchmark evaluation runs.

Security Invariants:
- Never stores raw passwords, API keys, or unredacted sensitive values.
- Never stores full uploaded document binary or text bodies.
- Uses strictly parameterized queries to eliminate SQL injection vulnerabilities.
- Maintains database indexes on timestamp, decision, and session identifiers.
"""

import os
import sqlite3
import hashlib
import time
import uuid
import logging
from typing import Dict, List, Optional, Any, Tuple

from config import DATA_DIR
from privacy_guard import scrub_secrets_from_text

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(DATA_DIR, "security_events.db")


def hash_session_id(session_id: str) -> str:
    """Hashes a session identifier using SHA-256 for privacy."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]


class SecurityDatabase:
    """SQLite database manager for security telemetry, audit logs, and benchmarks."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH
        self._mem_conn = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
        else:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes database schema and indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Security Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                iso_time TEXT NOT NULL,
                session_id_hash TEXT NOT NULL,
                event_type TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score REAL NOT NULL,
                threshold REAL NOT NULL,
                detection_layer TEXT NOT NULL,
                attack_category TEXT,
                processing_latency REAL NOT NULL,
                provider_name TEXT,
                model_name TEXT,
                document_scan_flag INTEGER DEFAULT 0,
                pii_redaction_count INTEGER DEFAULT 0,
                output_guard_status TEXT,
                user_prompt_sanitized TEXT,
                error_category TEXT
            );
            """)

            # Schema migration check: ensure error_category column exists
            cursor.execute("PRAGMA table_info(security_events);")
            cols = [col[1] for col in cursor.fetchall()]
            if "error_category" not in cols:
                try:
                    cursor.execute("ALTER TABLE security_events ADD COLUMN error_category TEXT;")
                except Exception:
                    pass

            # 2. Benchmark Runs Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS benchmark_runs (
                benchmark_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                iso_time TEXT NOT NULL,
                total_attacks INTEGER NOT NULL,
                detected_attacks INTEGER NOT NULL,
                missed_attacks INTEGER NOT NULL,
                total_benign INTEGER NOT NULL,
                false_positives INTEGER NOT NULL,
                detection_rate REAL NOT NULL,
                false_positive_rate REAL NOT NULL,
                precision_score REAL NOT NULL,
                recall_score REAL NOT NULL,
                f1_score REAL NOT NULL,
                avg_latency_ms REAL NOT NULL,
                notes TEXT
            );
            """)

            # 3. False Positive User Feedback Reports
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS false_positive_reports (
                report_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                user_note TEXT,
                FOREIGN KEY (event_id) REFERENCES security_events (event_id)
            );
            """)

            # Create Indexes for Fast Analytics
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events (timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_decision ON security_events (decision);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_layer ON security_events (detection_layer);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON security_events (session_id_hash);")
            conn.commit()

    def log_event(
        self,
        event_type: str,
        decision: str,
        risk_score: float,
        threshold: float,
        detection_layer: str,
        processing_latency: float,
        session_id: str = "default_session",
        attack_category: Optional[str] = None,
        provider_name: Optional[str] = None,
        model_name: Optional[str] = None,
        document_scan_flag: bool = False,
        pii_redaction_count: int = 0,
        output_guard_status: str = "PASSED",
        user_prompt_sanitized: Optional[str] = None,
        error_category: Optional[str] = None,
        request_id: Optional[str] = None,
        store_raw_prompt: bool = False
    ) -> str:
        """
        Logs a security decision event. Never accepts unredacted passwords, API keys,
        or full raw sensitive payloads. Enforces privacy scrubbing before disk write.
        """
        event_id = request_id or str(uuid.uuid4())[:12]
        now = time.time()
        iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        sess_hash = hash_session_id(session_id)

        # Apply deterministic privacy scrubbing
        clean_prompt = scrub_secrets_from_text(user_prompt_sanitized or "")
        clean_error = scrub_secrets_from_text(error_category) if error_category else None
        clean_attack_cat = scrub_secrets_from_text(attack_category) if attack_category else None

        # Privacy invariant: do not store complete raw prompts by default
        if not store_raw_prompt:
            sanitized_preview = (clean_prompt[:150] + "...") if len(clean_prompt) > 150 else clean_prompt
        else:
            sanitized_preview = (clean_prompt[:300] + "...") if len(clean_prompt) > 300 else clean_prompt

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO security_events (
                event_id, timestamp, iso_time, session_id_hash, event_type,
                decision, risk_score, threshold, detection_layer, attack_category,
                processing_latency, provider_name, model_name, document_scan_flag,
                pii_redaction_count, output_guard_status, user_prompt_sanitized,
                error_category
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                event_id, now, iso, sess_hash, event_type,
                decision, float(risk_score), float(threshold), detection_layer, clean_attack_cat,
                float(processing_latency), provider_name, model_name, 1 if document_scan_flag else 0,
                int(pii_redaction_count), output_guard_status, sanitized_preview,
                clean_error
            ))
            conn.commit()
        return event_id

    def log_benchmark_run(
        self,
        total_attacks: int,
        detected_attacks: int,
        missed_attacks: int,
        total_benign: int,
        false_positives: int,
        detection_rate: float,
        false_positive_rate: float,
        precision_score: float,
        recall_score: float,
        f1_score: float,
        avg_latency_ms: float,
        notes: str = ""
    ) -> str:
        """Logs an automated benchmark evaluation run."""
        benchmark_id = f"bench_{int(time.time())}_{str(uuid.uuid4())[:6]}"
        now = time.time()
        iso = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO benchmark_runs (
                benchmark_id, timestamp, iso_time, total_attacks, detected_attacks,
                missed_attacks, total_benign, false_positives, detection_rate,
                false_positive_rate, precision_score, recall_score, f1_score,
                avg_latency_ms, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                benchmark_id, now, iso, total_attacks, detected_attacks,
                missed_attacks, total_benign, false_positives, detection_rate,
                false_positive_rate, precision_score, recall_score, f1_score,
                avg_latency_ms, notes
            ))
            conn.commit()
        return benchmark_id

    def record_false_positive(self, event_id: str, user_note: str = "") -> str:
        """Records a user-reported false positive event."""
        report_id = f"fp_{str(uuid.uuid4())[:8]}"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO false_positive_reports (report_id, event_id, timestamp, user_note)
            VALUES (?, ?, ?, ?);
            """, (report_id, event_id, time.time(), user_note))
            conn.commit()
        return report_id

    def get_events(
        self,
        limit: int = 100,
        decision_filter: Optional[str] = None,
        layer_filter: Optional[str] = None,
        start_time: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves security events with optional filtering."""
        query = "SELECT * FROM security_events WHERE 1=1"
        params: List[Any] = []

        if decision_filter and decision_filter != "ALL":
            query += " AND decision = ?"
            params.append(decision_filter)
        if layer_filter and layer_filter != "ALL":
            query += " AND detection_layer LIKE ?"
            params.append(f"%{layer_filter}%")
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_kpi_summary(self) -> Dict[str, Any]:
        """Calculates aggregate KPI telemetry across all logged events."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM security_events;")
            total_inspected = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE decision = 'BLOCKED';")
            total_blocked = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE decision = 'ALLOWED';")
            total_allowed = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE decision = 'REVIEW REQUIRED';")
            total_review = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(processing_latency) FROM security_events;")
            avg_latency = cursor.fetchone()[0] or 0.0

            cursor.execute("SELECT COUNT(*) FROM false_positive_reports;")
            total_fp_reports = cursor.fetchone()[0]

            return {
                "total_inspected": total_inspected,
                "total_blocked": total_blocked,
                "total_allowed": total_allowed,
                "total_review": total_review,
                "avg_latency_ms": round(avg_latency, 2),
                "total_fp_reports": total_fp_reports
            }
