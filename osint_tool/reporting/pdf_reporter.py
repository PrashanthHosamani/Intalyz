"""
reporting/pdf_reporter.py
Phase III — Professional PDF Report Generator.
Produces a styled investigation report using ReportLab Platypus.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.platypus.flowables import HRFlowable
from reportlab.graphics.shapes import Drawing, Line, String, Rect
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.widgets.markers import makeMarker
from reportlab.graphics import renderPDF

from config import settings

logger = logging.getLogger(__name__)

# ── Brand colours ──────────────────────────────────────────────────────────────
C_DARK   = colors.HexColor("#0D1117")
C_ACCENT = colors.HexColor("#1F6FEB")
C_LIGHT  = colors.HexColor("#F6F8FA")
C_MUTED  = colors.HexColor("#8B949E")
C_RED    = colors.HexColor("#DA3633")
C_ORANGE = colors.HexColor("#D29922")
C_GREEN  = colors.HexColor("#3FB950")

SEVERITY_COLORS = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   colors.HexColor("#E3B341"),
    "LOW":      C_GREEN,
    "MINIMAL":  C_GREEN,
}


class PDFReporter:
    """Generates a professional OSINT investigation PDF report."""

    def __init__(self):
        os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
        self.styles = self._build_styles()

    def generate(
        self,
        entity:   str,
        resolved: Dict[str, Any],
        risk:     Dict[str, Any],
        raw_meta: Dict[str, Any],
    ) -> str:
        """
        Build and save the PDF.

        Returns:
            Absolute path to the generated PDF file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        slug      = entity.lower().replace(" ", "_")
        filename  = f"osint_report_{slug}_{timestamp}.pdf"
        filepath  = os.path.join(settings.OUTPUT_DIR, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2.5*cm, bottomMargin=2*cm,
            title=f"OSINT Report — {entity}",
            author="OSINT Tool v1.0",
        )

        story = []
        story.extend(self._cover_page(entity, risk, timestamp, resolved))
        story.append(PageBreak())
        story.extend(self._executive_summary(entity, resolved, risk))
        story.append(PageBreak())
        story.extend(self._verification_checklist(entity, resolved))
        story.append(PageBreak())
        story.extend(self._financial_overview(resolved))
        story.append(PageBreak())
        story.extend(self._data_tables(resolved))
        story.append(PageBreak())
        story.extend(self._discussions_section(resolved))
        story.append(PageBreak())
        story.extend(self._risk_breakdown(risk))
        story.append(PageBreak())
        story.extend(self._external_links_section(resolved))
        story.append(PageBreak())
        story.extend(self._false_positives_section(resolved))
        story.append(PageBreak())
        story.extend(self._audit_trail(resolved))

        doc.build(story, onFirstPage=self._header_footer, onLaterPages=self._header_footer)

        logger.info("📄 PDF report saved: %s", filepath)
        return filepath

    # ── Page sections ─────────────────────────────────────────────────────────

    def _cover_page(self, entity: str, risk: Dict, timestamp: str, resolved: Dict = None) -> list:
        s = self.styles
        severity     = risk.get("severity", "UNKNOWN")
        score        = risk.get("risk_score", 0)
        sev_color    = SEVERITY_COLORS.get(severity, C_MUTED)

        cell_s = ParagraphStyle("cover_cell", parent=s["body"], fontSize=9, leading=12, wordWrap='CJK')

        story = [
            Spacer(1, 2*cm),
            Paragraph("OSINT INVESTIGATION REPORT", s["cover_label"]),
            Spacer(1, 0.4*cm),
            Paragraph(entity, s["cover_title"]),
            Spacer(1, 0.2*cm),
            HRFlowable(width="100%", thickness=2, color=C_ACCENT),
            Spacer(1, 0.6*cm),
        ]

        # Risk score badge
        badge_data = [[Paragraph(
            f'<font color="white"><b>RISK SCORE: {score}/100 — {severity}</b></font>',
            s["center"]
        )]]
        badge = Table(badge_data, colWidths=["100%"])
        badge.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), sev_color),
            ("ROUNDEDCORNERS", [8]),
            ("TOPPADDING",   (0,0), (-1,-1), 10),
            ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ]))
        story.append(badge)
        story.append(Spacer(1, 0.8*cm))

        # ── Company Overview Section ──
        confirmed = resolved.get("confirmed", []) if resolved else []
        profile = next((f for f in confirmed if f.get("title") == "Financial Profile"), None)
        whois = next((f for f in confirmed if f.get("title") == "WHOIS Record"), None)
        wiki = next((f for f in confirmed if f.get("title") == "Wikipedia Summary"), None)

        import urllib.parse
        encoded = urllib.parse.quote_plus(entity)

        overview_rows = []

        # Website
        website = "N/A"
        if profile:
            website = profile.get("value", {}).get("website", "N/A")
        if website == "N/A" and whois:
            domain = whois.get("value", {}).get("domain", "")
            if domain:
                website = f"https://{domain}"
        overview_rows.append(["Website", Paragraph(str(website), cell_s)])

        # Industry & Sector
        if profile:
            pv = profile.get("value", {})
            overview_rows.append(["Industry", Paragraph(str(pv.get("industry", "N/A")), cell_s)])
            overview_rows.append(["Sector", Paragraph(str(pv.get("sector", "N/A")), cell_s)])
            overview_rows.append(["Country", Paragraph(str(pv.get("country", "N/A")), cell_s)])
            overview_rows.append(["Employees", Paragraph(str(pv.get("employees", "N/A")), cell_s)])
            overview_rows.append(["Exchange", Paragraph(str(pv.get("exchange", "N/A")), cell_s)])

        # Domain registrar from WHOIS
        if whois:
            wv = whois.get("value", {})
            overview_rows.append(["Domain Registrar", Paragraph(str(wv.get("registrar", "N/A")), cell_s)])

        # Social Media & Investigation Links
        social_links = [
            ["LinkedIn", f"https://www.linkedin.com/search/results/companies/?keywords={encoded}"],
            ["Twitter / X", f"https://twitter.com/search?q={encoded}&src=typed_query"],
            ["GitHub", f"https://github.com/search?q={encoded}&type=repositories"],
            ["Glassdoor", f"https://www.glassdoor.com/Search/results.htm?keyword={encoded}"],
            ["Crunchbase", f"https://www.crunchbase.com/textsearch?q={encoded}"],
            ["Google News", f"https://news.google.com/search?q={encoded}"],
        ]

        for name, url in social_links:
            overview_rows.append([name, Paragraph(url, cell_s)])

        if overview_rows:
            story.append(Paragraph("ENTITY PROFILE", s["sub_heading"]))
            story.append(Spacer(1, 0.2*cm))

            full_rows = [["Field", "Details"]]
            for row in overview_rows:
                full_rows.append(row)

            tbl = Table(full_rows, colWidths=[4*cm, 12*cm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), C_ACCENT),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (0,-1), 8),
                ("FONTNAME",      (0, 1), (0,-1), "Helvetica-Bold"),
                ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
                ("GRID",          (0, 0), (-1,-1), 0.3, C_MUTED),
                ("TOPPADDING",    (0, 0), (-1,-1), 4),
                ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
                ("LEFTPADDING",   (0, 0), (-1,-1), 6),
                ("VALIGN",        (0, 0), (-1,-1), "TOP"),
            ]))
            story.append(tbl)
            story.append(Spacer(1, 0.5*cm))

        # Meta info
        meta = [
            ["Generated:",  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
            ["Classification:", "CONFIDENTIAL"],
            ["Tool Version:", "OSINT Tool v1.0"],
        ]
        meta_tbl = Table(meta, colWidths=[4*cm, 12*cm])
        meta_tbl.setStyle(TableStyle([
            ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0), (-1,-1), 9),
            ("TEXTCOLOR", (0,0), (0,-1), C_MUTED),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(meta_tbl)
        return story

    def _executive_summary(self, entity: str, resolved: Dict, risk: Dict) -> list:
        s = self.styles
        confirmed  = resolved.get("confirmed", [])
        fp_count   = len(resolved.get("false_positives", []))
        categories = list(resolved.get("grouped_assets", {}).keys())
        score      = risk.get("risk_score", 0)
        severity   = risk.get("severity", "UNKNOWN")

        summary_text = (
            f"This report presents the results of an automated open-source intelligence "
            f"(OSINT) investigation conducted on the target entity <b>{entity}</b>. "
            f"A total of <b>{len(confirmed)} confirmed data points</b> were aggregated "
            f"across {len(categories)} source categories: "
            f"{', '.join(c.upper() for c in categories) if categories else 'N/A'}. "
            f"An additional {fp_count} findings were flagged as potential false positives "
            f"and excluded from primary analysis. "
            f"Based on the aggregated intelligence, the entity has been assigned a composite "
            f"<b>Risk Score of {score}/100</b> with a severity classification of "
            f"<b>{severity}</b>."
        )

        return [
            Paragraph("1. EXECUTIVE SUMMARY", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
            Paragraph(summary_text, s["body"]),
            Spacer(1, 0.5*cm),
            Paragraph("Key Statistics", s["sub_heading"]),
            Spacer(1, 0.2*cm),
            self._stats_table(resolved, risk),
            Spacer(1, 0.5*cm),
        ]

    def _stats_table(self, resolved: Dict, risk: Dict) -> Table:
        grouped   = resolved.get("grouped_assets", {})
        confirmed = resolved.get("confirmed", [])

        rows = [
            ["Metric", "Value"],
            ["Total Confirmed Findings",    str(len(confirmed))],
            ["False Positives Filtered",    str(len(resolved.get("false_positives", [])))],
            ["Duplicates Removed",          str(resolved.get("dedup_count", 0))],
            ["Source Categories",           str(len(grouped))],
            ["Composite Risk Score",        f"{risk.get('risk_score', 0)} / 100"],
            ["Severity Classification",     risk.get("severity", "N/A")],
        ]

        tbl = Table(rows, colWidths=[9*cm, 7*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1,-1), 0.5, C_MUTED),
            ("TOPPADDING",    (0, 0), (-1,-1), 6),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 6),
            ("LEFTPADDING",   (0, 0), (-1,-1), 8),
        ]))
        return tbl

    def _data_tables(self, resolved: Dict) -> list:
        s = self.styles
        story = [
            Paragraph("2. CATEGORISED FINDINGS", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
        ]

        grouped = resolved.get("grouped_assets", {})
        if not grouped:
            story.append(Paragraph("No confirmed findings to display.", s["body"]))
            return story

        for category, findings in grouped.items():
            story.append(Paragraph(f"2.{list(grouped.keys()).index(category)+1}  {category.upper()}", s["sub_heading"]))
            story.append(Spacer(1, 0.2*cm))

            for finding in findings:
                story.append(self._finding_card(finding))
                story.append(Spacer(1, 0.2*cm))

            story.append(Spacer(1, 0.4*cm))

        return story

    def _finding_card(self, finding: Dict) -> Table:
        """Render a single finding as a compact card table with text wrapping."""
        s = self.styles
        value = finding.get("value", {})

        # Style for wrapped cell text
        cell_style = ParagraphStyle(
            "cell_wrap", parent=s["body"],
            fontSize=8, leading=10, wordWrap='CJK',
        )
        header_style = ParagraphStyle(
            "cell_header", parent=s["body"],
            fontSize=8, leading=10, fontName="Helvetica-Bold",
            textColor=colors.white,
        )

        rows = [[Paragraph("Field", header_style), Paragraph("Value", header_style)]]

        if isinstance(value, dict):
            for k, v in value.items():
                if v is None:
                    continue
                display_v = str(v)[:200]
                rows.append([
                    Paragraph(k.replace("_", " ").title(), cell_style),
                    Paragraph(display_v, cell_style),
                ])
        else:
            rows.append([
                Paragraph("Value", cell_style),
                Paragraph(str(value)[:200], cell_style),
            ])

        src_url = str(finding.get("source_url", "N/A"))
        rows.append([Paragraph("Source URL", cell_style), Paragraph(src_url, cell_style)])
        rows.append([Paragraph("Retrieved At", cell_style), Paragraph(str(finding.get("retrieved_at", "N/A")), cell_style)])
        rows.append([Paragraph("Confidence", cell_style), Paragraph(f"{finding.get('confidence_score', 0):.0f}%", cell_style)])

        risk_tags = finding.get("risk_tags", [])
        if risk_tags:
            rows.append([Paragraph("Risk Tags", cell_style), Paragraph(", ".join(risk_tags), cell_style)])

        tbl = Table(rows, colWidths=[4*cm, 12*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_ACCENT),
            ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1,-1), 0.3, C_MUTED),
            ("TOPPADDING",    (0, 0), (-1,-1), 4),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
            ("LEFTPADDING",   (0, 0), (-1,-1), 6),
            ("VALIGN",        (0, 0), (-1,-1), "TOP"),
        ]))
        return tbl

    def _risk_breakdown(self, risk: Dict) -> list:
        s = self.styles
        breakdown = risk.get("breakdown", {})
        score     = risk.get("risk_score", 0)
        severity  = risk.get("severity", "N/A")

        story = [
            Paragraph("7. RISK ANALYSIS", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
            Paragraph(
                f"The entity received a composite Risk Score of <b>{score}/100</b> "
                f"with severity <b>{severity}</b>.",
                s["body"]
            ),
            Spacer(1, 0.2*cm),
            Paragraph(
                "<b>Scoring Methodology:</b> The risk score is calculated across 5 independent "
                "dimensions, each normalized to 0-100 and combined with industry-standard weights. "
                "This prevents low-risk findings (like public repos) from inflating the score — "
                "only genuine threats in Cyber, Reputation, and Financial health drive it up.",
                s["body"]
            ),
            Spacer(1, 0.3*cm),
        ]

        # ── Dimension Breakdown Table ──
        dimensions = risk.get("dimensions", {})
        dim_labels = {
            "cyber": "Cyber Exposure",
            "reputation": "Reputation",
            "digital": "Digital Presence",
            "financial": "Financial Health",
            "verification": "Verification Gap",
        }

        if dimensions:
            story.append(Paragraph("Risk Dimension Breakdown", s["sub_heading"]))
            story.append(Spacer(1, 0.2*cm))

            rows = [["Dimension", "Score", "Weight", "Contribution", "Severity"]]
            for dim_key in ["cyber", "reputation", "digital", "financial", "verification"]:
                dim = dimensions.get(dim_key, {})
                dim_score = dim.get("score", 0)
                if dim_score == "N/A":
                    score_display = "N/A"
                else:
                    score_display = f"{dim_score:.0f} / 100"
                rows.append([
                    dim_labels.get(dim_key, dim_key),
                    score_display,
                    str(dim.get("weight", "N/A")),
                    f"{dim.get('weighted_contribution', 0):.1f}",
                    str(dim.get("severity", "N/A")),
                ])
            rows.append(["", "", "", f"TOTAL: {score}/100", severity])

            tbl = Table(rows, colWidths=[4*cm, 2.5*cm, 2.5*cm, 3.5*cm, 3.5*cm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME",      (0,-1), (-1,-1), "Helvetica-Bold"),
                ("BACKGROUND",    (0,-1), (-1,-1), SEVERITY_COLORS.get(severity, C_MUTED)),
                ("TEXTCOLOR",     (0,-1), (-1,-1), colors.white),
                ("FONTSIZE",      (0, 0), (-1,-1), 9),
                ("ROWBACKGROUNDS",(0, 1), (-1,-2), [C_LIGHT, colors.white]),
                ("GRID",          (0, 0), (-1,-1), 0.5, C_MUTED),
                ("TOPPADDING",    (0, 0), (-1,-1), 6),
                ("BOTTOMPADDING", (0, 0), (-1,-1), 6),
                ("LEFTPADDING",   (0, 0), (-1,-1), 8),
                ("ALIGN",         (1, 0), (-1,-1), "CENTER"),
            ]))
            story.append(tbl)
            story.append(Spacer(1, 0.4*cm))

        # ── Individual Risk Factor Table (existing) ──
        if breakdown:
            story.append(Paragraph("Individual Risk Factors Detected", s["sub_heading"]))
            story.append(Spacer(1, 0.2*cm))

            rows = [["Risk Factor", "Dimension", "Occurrences", "Subtotal"]]
            for tag, info in sorted(breakdown.items(), key=lambda x: -x[1]["subtotal"]):
                rows.append([
                    tag.replace("_", " ").title(),
                    info.get("dimension", "N/A").title(),
                    str(info["count"]),
                    str(info["subtotal"]),
                ])

            tbl = Table(rows, colWidths=[5*cm, 4*cm, 3.5*cm, 3.5*cm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1,-1), 9),
                ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
                ("GRID",          (0, 0), (-1,-1), 0.5, C_MUTED),
                ("TOPPADDING",    (0, 0), (-1,-1), 5),
                ("BOTTOMPADDING", (0, 0), (-1,-1), 5),
                ("LEFTPADDING",   (0, 0), (-1,-1), 8),
                ("ALIGN",         (1, 0), (-1,-1), "CENTER"),
            ]))
            story.append(tbl)
        elif not dimensions:
            story.append(Paragraph("No risk factors identified.", s["body"]))

        return story

    # ── NEW: Verification Checklist ───────────────────────────────────────────

    def _verification_checklist(self, entity: str, resolved: Dict) -> list:
        s = self.styles
        confirmed = resolved.get("confirmed", [])
        results = [f for f in confirmed if f.get("title") == "Verification Result"]

        story = [
            Paragraph("3. COMPANY VERIFICATION RESULTS", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
            Paragraph(
                f"The system actively searched and verified <b>{entity}</b> across "
                f"multiple platforms. Each factor below was checked in real-time.",
                s["body"]
            ),
            Spacer(1, 0.3*cm),
        ]

        cell_s = ParagraphStyle("chk_cell", parent=s["body"], fontSize=8, leading=10, wordWrap='CJK')

        if results:
            rows = [["Factor", "Verdict", "Proof URL / Detail"]]
            for r in results:
                v = r.get("value", {})
                factor = str(v.get("factor", "N/A"))
                status = str(v.get("status", "N/A"))
                url = str(v.get("url", "N/A"))
                detail = str(v.get("detail", ""))

                # Build proof column: URL + detail
                if url and url != "N/A":
                    proof_text = f"{url}<br/><i>{detail}</i>"
                else:
                    proof_text = f"<i>{detail}</i>" if detail else "No data available"

                rows.append([
                    Paragraph(factor, cell_s),
                    Paragraph(status, cell_s),
                    Paragraph(proof_text, cell_s),
                ])

            tbl = Table(rows, colWidths=[6.0*cm, 2.5*cm, 7.5*cm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1,-1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
                ("GRID",          (0, 0), (-1,-1), 0.3, C_MUTED),
                ("TOPPADDING",    (0, 0), (-1,-1), 4),
                ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
                ("LEFTPADDING",   (0, 0), (-1,-1), 6),
                ("VALIGN",        (0, 0), (-1,-1), "TOP"),
            ]))
            story.append(tbl)
        else:
            story.append(Paragraph(
                "Verification module did not run. Enable the Company Intel adapter to verify.",
                s["body"]
            ))

        return story

    # ── NEW: Financial Overview ───────────────────────────────────────────────

    def _financial_overview(self, resolved: Dict) -> list:
        s = self.styles
        confirmed = resolved.get("confirmed", [])

        story = [
            Paragraph("4. FINANCIAL OVERVIEW", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
        ]

        # Find financial findings
        profile = next((f for f in confirmed if f.get("title") == "Financial Profile"), None)
        income  = next((f for f in confirmed if f.get("title") == "Income Statement Summary"), None)
        balance = next((f for f in confirmed if f.get("title") == "Balance Sheet Summary"), None)
        sources = next((f for f in confirmed if f.get("title") == "Financial Sources"), None)

        if not profile and not income and not balance and not sources:
            story.append(Paragraph(
                "Financial data is not available for this entity. The company may be too small "
                "or too new to have public financial records.",
                s["body"]
            ))
            return story

        if profile:
            story.append(Paragraph("Company Financial Profile", s["sub_heading"]))
            story.append(Spacer(1, 0.2*cm))
            story.append(self._finding_card(profile))
            story.append(Spacer(1, 0.3*cm))

        if income:
            story.append(Paragraph("Income Statement", s["sub_heading"]))
            story.append(Spacer(1, 0.2*cm))
            story.append(self._finding_card(income))
            story.append(Spacer(1, 0.3*cm))

        if balance:
            story.append(Paragraph("Balance Sheet", s["sub_heading"]))
            story.append(Spacer(1, 0.2*cm))
            story.append(self._finding_card(balance))
            story.append(Spacer(1, 0.3*cm))

        # Financial investigation sources
        if sources:
            story.append(Paragraph("Financial Investigation Sources", s["sub_heading"]))
            story.append(Spacer(1, 0.2*cm))
            story.append(self._finding_card(sources))
            story.append(Spacer(1, 0.3*cm))

        # Try to add stock price chart
        if profile:
            ticker_symbol = profile.get("value", {}).get("ticker", "")
            chart = self._build_stock_chart(ticker_symbol)
            if chart:
                story.append(Paragraph("Stock Price — Last 6 Months", s["sub_heading"]))
                story.append(Spacer(1, 0.2*cm))
                story.append(chart)

        return story

    def _build_stock_chart(self, ticker_symbol: str):
        """Build a line chart of stock price history using yfinance."""
        if not ticker_symbol:
            return None
        try:
            import yfinance as yf
            ticker = yf.Ticker(ticker_symbol)
            hist = ticker.history(period="6mo")
            if hist.empty or len(hist) < 5:
                return None

            # Sample ~30 points for clean chart
            step = max(1, len(hist) // 30)
            sampled = hist.iloc[::step]
            close_prices = sampled["Close"].tolist()
            dates = sampled.index.tolist()

            drawing = Drawing(480, 200)

            # Background
            bg = Rect(0, 0, 480, 200, fillColor=colors.HexColor("#F6F8FA"), strokeColor=None)
            drawing.add(bg)

            lp = LinePlot()
            lp.x = 50
            lp.y = 30
            lp.width = 400
            lp.height = 140
            lp.data = [list(enumerate(close_prices))]
            lp.lines[0].strokeColor = C_ACCENT
            lp.lines[0].strokeWidth = 2
            lp.xValueAxis.valueMin = 0
            lp.xValueAxis.valueMax = len(close_prices) - 1
            lp.xValueAxis.labels.fontSize = 6
            lp.xValueAxis.labels.textColor = C_MUTED
            lp.yValueAxis.labels.fontSize = 7
            lp.yValueAxis.labels.textColor = C_MUTED
            lp.yValueAxis.labelTextFormat = '%.0f'

            # Show a few date labels on x-axis
            label_step = max(1, len(dates) // 5)
            lp.xValueAxis.labelTextFormat = lambda x, dates=dates, step=label_step: (
                dates[int(x)].strftime("%b %d") if int(x) < len(dates) and int(x) % step == 0 else ""
            )

            drawing.add(lp)

            # Title
            title = String(240, 185, f"{ticker_symbol} Close Price",
                          fontSize=9, fillColor=C_DARK, textAnchor="middle",
                          fontName="Helvetica-Bold")
            drawing.add(title)

            return drawing
        except Exception as exc:
            logger.debug("Could not build stock chart: %s", exc)
            return None

    # ── NEW: Discussions & Sentiment ──────────────────────────────────────────

    def _discussions_section(self, resolved: Dict) -> list:
        s = self.styles
        confirmed = resolved.get("confirmed", [])
        discussions = [f for f in confirmed if f.get("title") == "Reddit Discussion"]

        story = [
            Paragraph("6. PUBLIC DISCUSSIONS & SENTIMENT", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
        ]

        if not discussions:
            story.append(Paragraph(
                "No public discussions were found for this entity on Reddit. "
                "This may indicate a low public profile or a very new company.",
                s["body"]
            ))
            return story

        story.append(Paragraph(
            f"Found <b>{len(discussions)} public discussions</b> mentioning the target entity.",
            s["body"]
        ))
        story.append(Spacer(1, 0.3*cm))

        rows = [["Title", "Subreddit", "Upvotes", "Comments"]]
        for d in discussions:
            v = d.get("value", {})
            rows.append([
                str(v.get("title", "N/A"))[:80],
                str(v.get("subreddit", "N/A")),
                str(v.get("upvotes", 0)),
                str(v.get("comments", 0)),
            ])

        tbl = Table(rows, colWidths=[8*cm, 3*cm, 2.5*cm, 2.5*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1,-1), 0.3, C_MUTED),
            ("TOPPADDING",    (0, 0), (-1,-1), 4),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
            ("LEFTPADDING",   (0, 0), (-1,-1), 6),
        ]))
        story.append(tbl)
        return story

    # ── NEW: External Investigation Links ─────────────────────────────────────

    def _external_links_section(self, resolved: Dict) -> list:
        s = self.styles
        confirmed = resolved.get("confirmed", [])
        results = [f for f in confirmed if f.get("title") == "Verification Result"]

        story = [
            Paragraph("8. VERIFICATION RESULTS", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
            Paragraph(
                "Each verification factor was actively searched. Results show whether "
                "the entity was found on each platform, with direct proof links where available.",
                s["body"]
            ),
            Spacer(1, 0.3*cm),
        ]

        if not results:
            story.append(Paragraph("No verification results available.", s["body"]))
            return story

        cell_s = ParagraphStyle("vr_cell", parent=s["body"], fontSize=8, leading=10, wordWrap='CJK')

        rows = [["Factor", "Status", "Proof / URL", "Details"]]
        for r in results:
            v = r.get("value", {})
            url = str(v.get("url", "N/A"))
            rows.append([
                str(v.get("factor", "N/A")),
                str(v.get("status", "N/A")),
                Paragraph(url if url != "N/A" else "No link", cell_s),
                Paragraph(str(v.get("detail", "")), cell_s),
            ])

        tbl = Table(rows, colWidths=[3.5*cm, 2.5*cm, 6*cm, 4*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1,-1), 0.3, C_MUTED),
            ("TOPPADDING",    (0, 0), (-1,-1), 4),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
            ("LEFTPADDING",   (0, 0), (-1,-1), 6),
            ("VALIGN",        (0, 0), (-1,-1), "TOP"),
        ]))
        story.append(tbl)
        return story

    def _audit_trail(self, resolved: Dict) -> list:
        s = self.styles
        confirmed = resolved.get("confirmed", [])

        story = [
            Paragraph("4. AUDIT TRAIL", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
            Paragraph(
                "All data points are listed below with their originating source URL "
                "and retrieval timestamp to ensure full auditability.",
                s["body"]
            ),
            Spacer(1, 0.3*cm),
        ]

        cell_s = ParagraphStyle("audit_cell", parent=s["body"], fontSize=7, leading=9, wordWrap='CJK')

        rows = [["#", "Title", "Source URL", "Retrieved At", "Conf."]]
        for idx, finding in enumerate(confirmed, 1):
            url = finding.get("source_url", "N/A")
            url_display = (url[:50] + "…") if len(url) > 50 else url
            rows.append([
                str(idx),
                Paragraph(str(finding.get("title", "N/A")), cell_s),
                Paragraph(url_display, cell_s),
                finding.get("retrieved_at", "N/A")[:19].replace("T", " "),
                f"{finding.get('confidence_score', 0):.0f}%",
            ])

        tbl = Table(rows, colWidths=[0.8*cm, 3.5*cm, 6.5*cm, 4*cm, 1.2*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1,-1), 7),
            ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1,-1), 0.3, C_MUTED),
            ("TOPPADDING",    (0, 0), (-1,-1), 4),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
            ("LEFTPADDING",   (0, 0), (-1,-1), 4),
            ("WORDWRAP",      (0, 0), (-1,-1), True),
        ]))
        story.append(tbl)
        return story

    def _false_positives_section(self, resolved: Dict) -> list:
        """Section showing findings filtered as potential false positives."""
        s = self.styles
        false_positives = resolved.get("false_positives", [])

        story = [
            Paragraph("5. POTENTIAL FALSE POSITIVES (LOW CONFIDENCE)", s["section_heading"]),
            HRFlowable(width="100%", thickness=1, color=C_ACCENT),
            Spacer(1, 0.3*cm),
        ]

        if not false_positives:
            story.append(Paragraph("No potential false positives detected.", s["body"]))
            return story

        story.append(Paragraph(
            f"The following {len(false_positives)} findings were identified but have confidence scores below "
            f"the {resolved.get('confirmed_threshold', 60)}% threshold and are presented for reference only. "
            "These may represent unrelated entities with similar names.",
            s["body"]
        ))
        story.append(Spacer(1, 0.3*cm))

        rows = [["#", "Title", "Confidence", "Value Preview"]]
        for idx, finding in enumerate(false_positives[:20], 1):  # Limit to first 20
            value = finding.get("value", {})
            if isinstance(value, dict):
                value_preview = ", ".join([f"{k}={str(v)[:30]}" for k, v in list(value.items())[:2]])
            else:
                value_preview = str(value)[:60]
            
            rows.append([
                str(idx),
                finding.get("title", "N/A")[:40],
                f"{finding.get('confidence_score', 0):.0f}%",
                value_preview + ("…" if len(value_preview) > 60 else ""),
            ])

        tbl = Table(rows, colWidths=[0.8*cm, 5*cm, 2*cm, 7.2*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_ACCENT),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1,-1), 0.3, C_MUTED),
            ("TOPPADDING",    (0, 0), (-1,-1), 4),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
            ("LEFTPADDING",   (0, 0), (-1,-1), 4),
        ]))
        story.append(tbl)
        return story

    # ── Page template ─────────────────────────────────────────────────────────

    def _header_footer(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # Header bar
        canvas.setFillColor(C_DARK)
        canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(2*cm, h - 0.8*cm, "OSINT INVESTIGATION REPORT — CONFIDENTIAL")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 2*cm, h - 0.8*cm, datetime.now(timezone.utc).strftime("%Y-%m-%d"))

        # Footer
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2*cm, 0.7*cm, "Generated by OSINT Tool v1.0 — For authorised use only")
        canvas.drawRightString(w - 2*cm, 0.7*cm, f"Page {doc.page}")

        canvas.restoreState()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _build_styles(self) -> Dict:
        base = getSampleStyleSheet()
        return {
            "cover_label": ParagraphStyle(
                "cover_label", parent=base["Normal"],
                fontSize=11, textColor=C_MUTED, alignment=TA_CENTER,
                fontName="Helvetica", spaceAfter=4,
            ),
            "cover_title": ParagraphStyle(
                "cover_title", parent=base["Title"],
                fontSize=28, textColor=C_DARK, alignment=TA_CENTER,
                fontName="Helvetica-Bold", spaceAfter=10, leading=34,
            ),
            "section_heading": ParagraphStyle(
                "section_heading", parent=base["Heading1"],
                fontSize=13, textColor=C_DARK, fontName="Helvetica-Bold",
                spaceBefore=12, spaceAfter=4,
            ),
            "sub_heading": ParagraphStyle(
                "sub_heading", parent=base["Heading2"],
                fontSize=10, textColor=C_ACCENT, fontName="Helvetica-Bold",
                spaceBefore=8, spaceAfter=2,
            ),
            "body": ParagraphStyle(
                "body", parent=base["Normal"],
                fontSize=9, leading=14, textColor=C_DARK,
            ),
            "center": ParagraphStyle(
                "center", parent=base["Normal"],
                alignment=TA_CENTER, fontSize=11,
            ),
            "muted": ParagraphStyle(
                "muted", parent=base["Normal"],
                fontSize=8, textColor=C_MUTED,
            ),
        }
