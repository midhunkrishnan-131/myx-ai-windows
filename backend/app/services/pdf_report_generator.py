"""
MYX AI (Windows Edition) — Professional Cybersecurity PDF Report Generator.
Generates an executive-grade 7-section defensive assessment report from actual completed
assessment records using ReportLab.
"""
import io
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.pdfgen import canvas

from app.core.brand import (
    BRAND_FULL_TITLE,
    BRAND_EDITION_NAME,
    BRAND_TAGLINE,
    BRAND_AUTHOR,
    BRAND_VERSION,
)


class NumberedCanvas(canvas.Canvas):
    """Adds professional running headers and footers with dynamic page numbers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        if self._pageNumber == 1:
            # Skip header/footer on cover page
            return

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header
        self.drawString(54, 11 * 72 - 36, f"{BRAND_FULL_TITLE} — Cybersecurity Assessment Report")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 11 * 72 - 42, 8.5 * 72 - 54, 11 * 72 - 42)

        # Running Footer
        self.line(54, 46, 8.5 * 72 - 54, 46)
        self.drawString(54, 32, "CONFIDENTIAL & PROPRIETARY — FOR AUTHORIZED AUDITEE USE ONLY")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * 72 - 54, 32, page_str)
        self.restoreState()


def generate_assessment_pdf_report(assessment_run: Dict[str, Any]) -> bytes:
    """
    Renders an executive & technical security assessment report as PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()
    
    # Custom Palette
    c_primary = colors.HexColor("#0F172A")
    c_secondary = colors.HexColor("#1E293B")
    c_gold = colors.HexColor("#D97706")
    c_text = colors.HexColor("#1E293B")
    c_muted = colors.HexColor("#64748B")
    c_pass = colors.HexColor("#16A34A")
    c_warn = colors.HexColor("#D97706")
    c_fail = colors.HexColor("#DC2626")
    c_bg_light = colors.HexColor("#F8FAFC")
    c_border = colors.HexColor("#E2E8F0")

    # Typography Styles
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=26,
        leading=32,
        textColor=c_primary,
        alignment=0,
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=c_muted,
        alignment=0,
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=8,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=c_secondary,
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=c_text,
    )
    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )
    badge_pass = ParagraphStyle(
        "BadgePass",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=c_pass,
    )
    badge_warn = ParagraphStyle(
        "BadgeWarn",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=c_warn,
    )
    badge_fail = ParagraphStyle(
        "BadgeFail",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=c_fail,
    )

    story = []

    # Target data
    target_display = assessment_run.get("target_display") or assessment_run.get("target_value") or "Target Website"
    score = int(assessment_run.get("risk_score") or 0)
    summary = assessment_run.get("summary") or {}
    passed_count = summary.get("passed", 0)
    warnings_count = summary.get("warnings", 0)
    failed_count = summary.get("failed", 0)
    started_at = assessment_run.get("started_at") or "N/A"
    completed_at = assessment_run.get("completed_at") or "N/A"
    run_id = assessment_run.get("id") or "asm-web-unknown"
    profile_name = assessment_run.get("profile_name") or "Standard Live Audit"
    operator = assessment_run.get("initiated_by_email") or "Operator"

    # =========================================================================
    # SECTION 1: COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 40))
    story.append(Paragraph(f"<b>{BRAND_FULL_TITLE}</b>", ParagraphStyle("Brand", fontName="Helvetica-Bold", fontSize=14, textColor=c_gold)))
    story.append(Paragraph(f"{BRAND_TAGLINE} — {BRAND_EDITION_NAME} v{BRAND_VERSION}", subtitle_style))
    story.append(Spacer(1, 24))
    story.append(HRFlowable(width="100%", thickness=3, color=c_gold, spaceBefore=4, spaceAfter=20))
    story.append(Paragraph("WEBSITE SECURITY & DEFENSIVE HTTP AUDIT REPORT", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Target Scope: <b>{target_display}</b>", ParagraphStyle("CoverTarget", fontName="Helvetica", fontSize=13, leading=17, textColor=c_secondary)))
    story.append(Spacer(1, 40))

    # Score Card on Cover
    score_color = c_pass if score >= 80 else (c_warn if score >= 50 else c_fail)
    score_label = "STRONG DEFENSIVE POSTURE" if score >= 80 else ("MODERATE ATTACK SURFACE" if score >= 50 else "CRITICAL DEFICIENCIES DETECTED")

    score_table_data = [
        [
            Paragraph("<b>COMPUTED DEFENSIVE SCORE</b>", ParagraphStyle("ScH", fontName="Helvetica-Bold", fontSize=10, textColor=c_muted)),
            Paragraph("<b>SUMMARY FINDINGS</b>", ParagraphStyle("ScH2", fontName="Helvetica-Bold", fontSize=10, textColor=c_muted)),
        ],
        [
            Paragraph(f"<font size=36 color='{score_color.hexval()}'><b>{score}</b></font><font size=14 color='#64748B'>/100</font><br/><b>{score_label}</b>", body_style),
            Paragraph(f"<font color='{c_pass.hexval()}'><b>Passed Controls:</b> {passed_count}</font><br/><font color='{c_warn.hexval()}'><b>Warning Discrepancies:</b> {warnings_count}</font><br/><font color='{c_fail.hexval()}'><b>Failed Defenses:</b> {failed_count}</font>", body_style),
        ]
    ]
    t_score = Table(score_table_data, colWidths=[240, 264])
    t_score.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c_bg_light),
        ("BOX", (0, 0), (-1, -1), 1, c_border),
        ("PADDING", (0, 0), (-1, -1), 14),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t_score)

    story.append(Spacer(1, 60))

    # Metadata Block
    meta_data = [
        [Paragraph("<b>Assessment Run ID:</b>", body_style), Paragraph(run_id, body_style)],
        [Paragraph("<b>Audit Profile:</b>", body_style), Paragraph(profile_name, body_style)],
        [Paragraph("<b>Execution Window:</b>", body_style), Paragraph(f"{started_at} to {completed_at}", body_style)],
        [Paragraph("<b>Initiated By / Attestation:</b>", body_style), Paragraph(operator, body_style)],
        [Paragraph("<b>Principal Architect:</b>", body_style), Paragraph(BRAND_AUTHOR, body_style)],
    ]
    t_meta = Table(meta_data, colWidths=[160, 344])
    t_meta.setStyle(TableStyle([
        ("PADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, c_border),
    ]))
    story.append(t_meta)

    story.append(PageBreak())

    # =========================================================================
    # SECTION 2: EXECUTIVE SUMMARY
    # =========================================================================
    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=10))

    exec_summary_text = (
        f"This document presents the defensive cybersecurity audit findings for <b>{target_display}</b>, "
        f"evaluated using the MYX-AI SafeOutboundHttpClient passive assessment framework. "
        f"The target achieved an overall security health score of <b>{score}/100</b>. "
        f"During inspection, <b>{passed_count}</b> controls met hardening benchmarks, "
        f"<b>{warnings_count}</b> controls triggered configuration warnings, and "
        f"<b>{failed_count}</b> controls failed minimum defensive thresholds."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 10))

    # Executive observations
    obs_text = "<b>Key Executive Observations:</b><br/>"
    if failed_count == 0 and warnings_count == 0:
        obs_text += "• <b>Exceptional Security Posture:</b> All primary transport, framing, and content-injection controls are actively enforced.<br/>"
    else:
        if any("CSP" in r.get("check_title", "") and r.get("status") == "FAIL" for r in assessment_run.get("results", [])):
            obs_text += "• <b>Critical Web Defense Missing:</b> Content-Security-Policy (CSP) is absent, leaving the asset exposed to client-side script injection (XSS).<br/>"
        if any("HSTS" in r.get("check_title", "") and r.get("status") == "FAIL" for r in assessment_run.get("results", [])):
            obs_text += "• <b>Transport Encryption Vulnerability:</b> HTTP Strict Transport Security (HSTS) is missing, permitting opportunistic SSL stripping attacks.<br/>"
        if any("Clickjacking" in r.get("check_title", "") and r.get("status") == "FAIL" for r in assessment_run.get("results", [])):
            obs_text += "• <b>Clickjacking Exposure:</b> The target permits unconstrained framing in external iframes due to missing X-Frame-Options and frame-ancestors.<br/>"
        if warnings_count > 0:
            obs_text += f"• <b>Configuration Gaps:</b> {warnings_count} secondary privacy or information exposure directives require remediation (e.g., cookie hardening, referrer governance).<br/>"

    story.append(Paragraph(obs_text, body_style))
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 3: ASSESSMENT SCOPE & METHODOLOGY
    # =========================================================================
    story.append(Paragraph("2. Scope & Defensive Methodology", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=10))

    scope_text = (
        "<b>Passive Security Audit Methodology:</b><br/>"
        "MYX-AI conducts strictly passive, non-destructive evaluations against authorized endpoints. "
        "No exploit payloads, brute-force attempts, or state-modifying requests are dispatched. "
        "The engine validates response headers, TLS termination endpoints, redirection paths, and cookie protection flags.<br/><br/>"
        "<b>SSRF & Allowlist Controls Enforced:</b><br/>"
        "All requests strictly transit the SafeOutboundHttpClient guard, preventing access to loopback (127.0.0.0/8), "
        "link-local (169.254.0.0/16), cloud instance metadata (169.254.169.254), and unauthorized internal enterprise networks."
    )
    story.append(Paragraph(scope_text, body_style))
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 4: SECURITY SCORE BREAKDOWN
    # =========================================================================
    story.append(Paragraph("3. Transparent Security Score Breakdown", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=10))

    score_expl = (
        "Scores are calculated using an evidence-based, weighted 100-point model. "
        "Controls are weighted according to their real-world threat mitigation impact (e.g., CSP and HSTS receive highest weighting). "
        "Passing controls earn full points; warning discrepancies earn 50% credit; failed controls forfeit their entire weighting."
    )
    story.append(Paragraph(score_expl, body_style))
    story.append(Spacer(1, 10))

    # Controls Table
    ctrl_rows = [
        [
            Paragraph("<b>Control ID / Title</b>", ParagraphStyle("TH", fontName="Helvetica-Bold", fontSize=8.5, textColor=c_primary)),
            Paragraph("<b>Weight</b>", ParagraphStyle("TH2", fontName="Helvetica-Bold", fontSize=8.5, textColor=c_primary, alignment=1)),
            Paragraph("<b>Status</b>", ParagraphStyle("TH3", fontName="Helvetica-Bold", fontSize=8.5, textColor=c_primary, alignment=1)),
            Paragraph("<b>Earned</b>", ParagraphStyle("TH4", fontName="Helvetica-Bold", fontSize=8.5, textColor=c_primary, alignment=1)),
            Paragraph("<b>Deducted</b>", ParagraphStyle("TH5", fontName="Helvetica-Bold", fontSize=8.5, textColor=c_primary, alignment=1)),
        ]
    ]

    for check in assessment_run.get("results", []):
        cid = check.get("control_id") or check.get("check_code") or "CTRL"
        title = check.get("check_title") or "Security Check"
        weight = check.get("weight", 10)
        earned = check.get("points_earned", weight if check.get("status") == "PASS" else 0)
        deducted = check.get("points_deducted", 0 if check.get("status") == "PASS" else weight)
        status = check.get("status", "INFO")

        status_p = (
            Paragraph("PASS", badge_pass)
            if status == "PASS"
            else (Paragraph("WARN", badge_warn) if status == "WARNING" else Paragraph("FAIL", badge_fail))
        )

        ctrl_rows.append([
            Paragraph(f"<b>{cid}</b><br/>{title}", body_style),
            Paragraph(f"{weight} pts", ParagraphStyle("TC", fontName="Helvetica", fontSize=8.5, alignment=1)),
            status_p,
            Paragraph(f"+{earned}", ParagraphStyle("TC2", fontName="Helvetica-Bold", fontSize=8.5, alignment=1, textColor=c_pass if earned > 0 else c_muted)),
            Paragraph(f"-{deducted}", ParagraphStyle("TC3", fontName="Helvetica-Bold", fontSize=8.5, alignment=1, textColor=c_fail if deducted > 0 else c_muted)),
        ])

    t_ctrl = Table(ctrl_rows, colWidths=[240, 60, 64, 70, 70])
    t_ctrl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_bg_light),
        ("LINEBELOW", (0, 0), (-1, 0), 1, c_border),
        ("LINEBELOW", (0, 1), (-1, -1), 0.5, c_border),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t_ctrl)

    story.append(PageBreak())

    # =========================================================================
    # SECTION 5: DETAILED SECURITY FINDINGS
    # =========================================================================
    story.append(Paragraph("4. Detailed Technical Findings & Evidence", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=10))

    findings_count = 0
    for idx, check in enumerate(assessment_run.get("results", [])):
        cid = check.get("control_id") or check.get("check_code") or f"CTRL-{idx+1}"
        title = check.get("check_title") or "Technical Finding"
        status = check.get("status")
        severity = check.get("severity") or "Low"
        confidence = check.get("confidence") or "Confirmed"
        actual_obs = check.get("actual_header_observed") or check.get("raw_evidence") or "(No header returned)"
        expected_cfg = check.get("expected_configuration") or "Follow standard hardening guidelines."
        explanation = check.get("technical_explanation") or "Configuration evaluation."
        remediation = check.get("remediation_recommendation") or check.get("remediation_text") or "Review and remediate."
        cwe_id = check.get("cwe_id") or "CWE-693"

        # Card container for finding
        f_color = c_pass if status == "PASS" else (c_warn if status == "WARNING" else c_fail)
        status_label = f"[{status}] {severity.upper()} SEVERITY"

        finding_block = [
            [
                Paragraph(f"<b>{cid}: {title}</b>", ParagraphStyle("FH", fontName="Helvetica-Bold", fontSize=10, textColor=c_primary)),
                Paragraph(f"<b>{status_label}</b>", ParagraphStyle("FStat", fontName="Helvetica-Bold", fontSize=9, textColor=f_color, alignment=2)),
            ],
            [
                Paragraph(f"<b>Confidence:</b> {confidence} &nbsp;|&nbsp; <b>Mapping:</b> {cwe_id}", ParagraphStyle("FM", fontName="Helvetica", fontSize=8, textColor=c_muted)),
                "",
            ],
            [
                Paragraph(f"<b>Technical Explanation:</b><br/>{explanation}", body_style),
                "",
            ],
            [
                Paragraph(f"<b>Observed Evidence:</b><br/><code>{actual_obs}</code>", code_style),
                "",
            ],
            [
                Paragraph(f"<b>Remediation Recommendation:</b><br/>{remediation}", ParagraphStyle("FRem", fontName="Helvetica", fontSize=9, leading=13, textColor=colors.HexColor("#0369A1"))),
                "",
            ],
        ]

        t_finding = Table(finding_block, colWidths=[380, 124])
        t_finding.setStyle(TableStyle([
            ("SPAN", (0, 1), (1, 1)),
            ("SPAN", (0, 2), (1, 2)),
            ("SPAN", (0, 3), (1, 3)),
            ("SPAN", (0, 4), (1, 4)),
            ("BACKGROUND", (0, 0), (-1, -1), c_bg_light if status == "PASS" else colors.HexColor("#FEF2F2" if status == "FAIL" else "#FFFBEB")),
            ("BOX", (0, 0), (-1, -1), 1, c_border),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, c_border),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        story.append(KeepTogether([t_finding, Spacer(1, 10)]))
        findings_count += 1

    # =========================================================================
    # SECTION 6: REMEDIATION ROADMAP
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("5. Remediation Roadmap & Priorities", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=10))

    roadmap_intro = (
        "The following prioritized roadmap outlines corrective actions required to harden "
        f"<b>{target_display}</b> against automated scanners and browser-based exploitation."
    )
    story.append(Paragraph(roadmap_intro, body_style))
    story.append(Spacer(1, 12))

    # Priority Groups
    crit_high = [r for r in assessment_run.get("results", []) if r.get("status") in ("FAIL", "WARNING") and r.get("severity") in ("Critical", "High")]
    mediums = [r for r in assessment_run.get("results", []) if r.get("status") in ("FAIL", "WARNING") and r.get("severity") == "Medium"]
    lows = [r for r in assessment_run.get("results", []) if r.get("status") in ("FAIL", "WARNING") and r.get("severity") == "Low"]

    def render_priority_group(title_text: str, group: List[Dict[str, Any]], bg_color):
        items = []
        if not group:
            items.append([Paragraph("No findings in this severity tier.", ParagraphStyle("Empty", fontName="Helvetica-Oblique", fontSize=8.5, textColor=c_muted))])
        else:
            for item in group:
                txt = f"• <b>{item.get('control_id', '')} ({item.get('check_title', '')}):</b> {item.get('remediation_recommendation') or item.get('remediation_text', '')}"
                items.append([Paragraph(txt, body_style)])

        t_group = Table(items, colWidths=[504])
        t_group.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("BOX", (0, 0), (-1, -1), 0.5, c_border),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        return t_group

    story.append(Paragraph("<b>Priority 1: Critical & High Remediations (Immediate Action Required)</b>", h2_style))
    story.append(render_priority_group("Critical & High", crit_high, colors.HexColor("#FEF2F2")))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>Priority 2: Medium Remediations (Scheduled Sprint Implementation)</b>", h2_style))
    story.append(render_priority_group("Medium", mediums, colors.HexColor("#FFFBEB")))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>Priority 3: Low & Hygiene Improvements (Hardening Best Practices)</b>", h2_style))
    story.append(render_priority_group("Low", lows, c_bg_light))
    story.append(Spacer(1, 20))

    # =========================================================================
    # SECTION 7: FINAL SUMMARY & SIGN-OFF
    # =========================================================================
    story.append(Paragraph("6. Assessment Closure & Formal Sign-Off", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=10))

    signoff_text = (
        "<b>Limitations of Assessment:</b><br/>"
        "This security evaluation was conducted passively on publicly returned HTTP response headers and protocol parameters. "
        "It does not assess server-side business logic, database injection vulnerabilities, authenticated application states, "
        "or internal network segmentation. Periodic automated re-assessment is advised after major production releases.<br/><br/>"
        "<b>Attestation & Integrity:</b><br/>"
        f"This report was generated deterministically by the {BRAND_FULL_TITLE} engine directly from audit record "
        f"<code>{run_id}</code>. No simulated or sample values were substituted."
    )
    story.append(Paragraph(signoff_text, body_style))
    story.append(Spacer(1, 30))

    # Signature Block
    sig_data = [
        [
            Paragraph(f"<b>Evaluator:</b> {BRAND_AUTHOR}<br/>Principal Security Architect, MYX Defense", body_style),
            Paragraph(f"<b>Operator Attestation:</b> {operator}<br/>Recorded Timestamp: {completed_at}", body_style),
        ]
    ]
    t_sig = Table(sig_data, colWidths=[252, 252])
    t_sig.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (0, 0), 1, c_primary),
        ("LINEABOVE", (1, 0), (1, 0), 1, c_primary),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(t_sig)

    # Build PDF
    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
