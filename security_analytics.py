"""
Security Analytics & Reporting Module.

Provides data aggregation, chart generation dataframes, CSV exports,
and professional PDF security audit reports using ReportLab.
"""

import io
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
import pandas as pd

from security_database import SecurityDatabase

logger = logging.getLogger(__name__)


class SecurityAnalytics:
    """Analytics and reporting engine for AI security telemetry."""

    def __init__(self, db: Optional[SecurityDatabase] = None):
        self.db = db or SecurityDatabase()

    def get_kpis(self) -> Dict[str, Any]:
        """Returns top-level metric counters."""
        return self.db.get_kpi_summary()

    def get_events_dataframe(self, limit: int = 500, decision_filter: str = "ALL") -> pd.DataFrame:
        """Retrieves events as a pandas DataFrame for UI tables and filtering."""
        events = self.db.get_events(limit=limit, decision_filter=decision_filter)
        if not events:
            return pd.DataFrame(columns=[
                "iso_time", "event_type", "decision", "risk_score", "threshold",
                "detection_layer", "attack_category", "processing_latency",
                "provider_name", "pii_redaction_count", "user_prompt_sanitized",
                "error_category"
            ])
        df = pd.DataFrame(events)
        return df

    def get_layer_distribution(self, df: pd.DataFrame) -> pd.DataFrame:
        """Aggregates blocked events by detection layer."""
        if df.empty or "detection_layer" not in df.columns:
            return pd.DataFrame(columns=["Layer", "Count"])
        blocked = df[df["decision"] == "BLOCKED"]
        if blocked.empty:
            return pd.DataFrame(columns=["Layer", "Count"])
        counts = blocked["detection_layer"].value_counts().reset_index()
        counts.columns = ["Layer", "Count"]
        return counts

    def get_decision_distribution(self, df: pd.DataFrame) -> pd.DataFrame:
        """Aggregates total events by security decision."""
        if df.empty or "decision" not in df.columns:
            return pd.DataFrame(columns=["Decision", "Count"])
        counts = df["decision"].value_counts().reset_index()
        counts.columns = ["Decision", "Count"]
        return counts

    # -----------------------------------------------------------------------
    # CSV Export
    # -----------------------------------------------------------------------

    def export_csv(self, limit: int = 1000) -> str:
        """Generates a CSV string containing sanitized security audit telemetry."""
        df = self.get_events_dataframe(limit=limit)
        # Drop internal or unneeded columns
        cols_to_export = [
            "event_id", "iso_time", "event_type", "decision", "risk_score",
            "threshold", "detection_layer", "attack_category", "processing_latency",
            "provider_name", "model_name", "document_scan_flag", "pii_redaction_count",
            "output_guard_status", "user_prompt_sanitized", "error_category"
        ]
        available_cols = [c for c in cols_to_export if c in df.columns]
        return df[available_cols].to_csv(index=False)

    # -----------------------------------------------------------------------
    # PDF Security Audit Report (ReportLab)
    # -----------------------------------------------------------------------

    def export_pdf_report(self) -> bytes:
        """
        Builds a comprehensive, professional PDF Security Audit Report using ReportLab.
        Includes title, timestamp, reporting period, KPI metrics, layer statistics,
        and documented security boundaries.
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#1E293B'),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#64748B'),
            spaceAfter=14
        )
        heading2_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=17,
            textColor=colors.HexColor('#0F172A'),
            spaceBefore=12,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )

        elements = []
        kpis = self.get_kpis()
        now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # Title & Header
        elements.append(Paragraph("AI Security Defense Platform: Comprehensive Audit Report", title_style))
        elements.append(Paragraph(f"Generated on {now_str} | System: Hybrid Prompt Injection Defender & LLM Judge", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#CBD5E1"), spaceAfter=14))

        # Section 1: KPI Telemetry Table
        elements.append(Paragraph("1. Executive Security Metrics & Telemetry", heading2_style))
        kpi_data = [
            ["Metric Name", "Value", "Operational Definition"],
            ["Total Prompts Inspected", str(kpis.get("total_inspected", 0)), "Total incoming user & document requests evaluated"],
            ["Total Prompts Blocked", str(kpis.get("total_blocked", 0)), "Malicious prompt injections & jailbreaks neutralized"],
            ["Total Prompts Allowed", str(kpis.get("total_allowed", 0)), "Verified benign requests safely delivered to AI"],
            ["Reviews Required", str(kpis.get("total_review", 0)), "Borderline or ambiguous requests flagged for inspection"],
            ["Average Pipeline Latency", f"{kpis.get('avg_latency_ms', 0.0):.1f} ms", "Mean processing time across all 7 security layers"],
            ["User False Positive Reports", str(kpis.get("total_fp_reports", 0)), "Innocent requests flagged by users for auditing"]
        ]

        kpi_table = Table(kpi_data, colWidths=[160, 80, 290])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ]))
        elements.append(kpi_table)
        elements.append(Spacer(1, 14))

        # Section 2: Layer-wise Detection Breakdown
        elements.append(Paragraph("2. Layer-wise Threat Detection Breakdown", heading2_style))
        df = self.get_events_dataframe(limit=500)
        layer_df = self.get_layer_distribution(df)
        
        layer_data = [["Security Layer", "Threats Neutralized", "% of Total Blocks"]]
        total_blocks = kpis.get("total_blocked", 0)
        if not layer_df.empty and total_blocks > 0:
            for _, row in layer_df.iterrows():
                cnt = int(row["Count"])
                pct = f"{(cnt / total_blocks) * 100:.1f}%"
                layer_data.append([str(row["Layer"])[:40], str(cnt), pct])
        else:
            layer_data.append(["No blocked events recorded yet", "0", "0.0%"])

        layer_table = Table(layer_data, colWidths=[280, 110, 140])
        layer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(layer_table)
        elements.append(Spacer(1, 14))

        # Section 3: Platform Architecture & Security Boundaries
        elements.append(Paragraph("3. Platform Architecture & Security Boundaries", heading2_style))
        sec_text = (
            "<b>Architectural Rigor:</b> All incoming interactions pass through the 7-Layer Hybrid Security Pipeline "
            "(Unicode & Hex Normalization, Rule Filtering, DistilBERT Classification, Noisy-OR Fusion, Canary Injection, "
            "Output Canary Auditing, and LLM Judge Validation). Production cutoff is hard-locked at <code>BLOCK_THRESHOLD = 0.60</code>.<br/><br/>"
            "<b>Data Privacy Assurance:</b> In compliance with corporate data protection standards, raw user credentials, "
            "passwords, API keys, and unredacted prompts are <u>never</u> stored in the SQLite database or written to disk. "
            "Privacy Guard strips high-confidence PII and authentication secrets prior to upstream model forwarding."
        )
        elements.append(Paragraph(sec_text, body_style))
        elements.append(Spacer(1, 14))

        # Section 4: Known Security Boundaries & Operational Guidance
        elements.append(Paragraph("4. Known Security Boundaries & Operational Notes", heading2_style))
        notes_text = (
            "1. <b>Model Capacity:</b> DistilBERT operates within a 128-token window with 64-token stride sliding inference. "
            "Ultra-long adversarial documents are scanned across segmented chunk windows.<br/>"
            "2. <b>Indirect Document Injections:</b> PDF and DOCX files with zero-width characters, micro-fonts (<4pt), "
            "or off-canvas coordinates receive automatic risk penalties.<br/>"
            "3. <b>Multi-turn Trajectories:</b> Conversational memory tracks up to 10 recent turns to intercept fragmented attacks."
        )
        elements.append(Paragraph(notes_text, body_style))

        # Build Document
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
