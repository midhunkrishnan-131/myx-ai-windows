"""
MYX AI (Windows Edition) — Professional Wi-Fi Security & Password Audit PDF Report Generator.
Strict Privacy Rule: NEVER writes, outputs, or embeds actual passwords into PDF documents.
Uses ReportLab to generate clean, executive-grade wireless security reports.
"""
import io
import datetime
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
from app.core.brand import BRAND_FULL_TITLE, BRAND_TAGLINE, BRAND_VERSION


class WifiReportNumberedCanvas(canvas.Canvas):
    """Dynamic page numbers and confidentiality header for Wi-Fi security reports."""
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
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header
        self.drawString(54, 11 * 72 - 36, f"{BRAND_FULL_TITLE} — Wi-Fi Security & Password Audit")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 11 * 72 - 42, 8.5 * 72 - 54, 11 * 72 - 42)

        # Running Footer
        self.line(54, 46, 8.5 * 72 - 54, 46)
        self.drawString(54, 32, "CONFIDENTIAL WIRELESS ASSESSMENT — PASSWORDS REDACTED BY DESIGN")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * 72 - 54, 32, page_str)
        self.restoreState()


def generate_wifi_audit_pdf(audit_data: Dict[str, Any]) -> bytes:
    """
    Renders an executive and technical Wi-Fi security audit report as PDF bytes.
    PRIVACY GUARANTEE: Never prints actual recovered passwords.
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

    # Custom typography
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )
    bold_body = ParagraphStyle(
        "BoldBody",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    mono_style = ParagraphStyle(
        "MonoText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )

    story: List[Any] = []

    ssid = audit_data.get("ssid", "Wireless Network")
    protocol = audit_data.get("security_protocol", "WPA2-Personal")
    cipher = audit_data.get("cipher", "CCMP (AES)")
    wps_status = "Enabled (Action Required)" if audit_data.get("wps_enabled") else "Disabled / Undetected (Hardened)"
    pwd_strength = audit_data.get("password_strength", "Strong")
    pwd_entropy = audit_data.get("password_entropy", 64.0)
    findings = audit_data.get("findings", [])
    recommendations = audit_data.get("recommendations", [])

    # Header / Title block
    story.append(Paragraph(f"{BRAND_FULL_TITLE}", bold_body))
    story.append(Paragraph("Wi-Fi Security Posture & Credential Strength Audit", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Audited Target SSID: <b>{ssid}</b> · Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#D97706"), spaceBefore=4, spaceAfter=14))

    # 1. Executive Summary Table
    story.append(Paragraph("1. Executive Wireless Summary", h2_style))
    summary_data = [
        [Paragraph("Target Wireless Network (SSID)", bold_body), Paragraph(ssid, mono_style)],
        [Paragraph("Authentication Protocol", bold_body), Paragraph(protocol, mono_style)],
        [Paragraph("Encryption Cipher", bold_body), Paragraph(cipher, mono_style)],
        [Paragraph("WPS (Wi-Fi Protected Setup)", bold_body), Paragraph(wps_status, body_style)],
        [Paragraph("Password Complexity Category", bold_body), Paragraph(f"<b>{pwd_strength}</b> (Entropy: {pwd_entropy} bits)", body_style)],
        [Paragraph("Overall Wireless Posture", bold_body), Paragraph(audit_data.get("overall_posture", "SECURE"), bold_body)],
    ]
    t = Table(summary_data, colWidths=[200, 304])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # 2. What Does This Mean? (Beginner-Friendly Explanation)
    story.append(Paragraph("2. What Does This Wireless Posture Mean?", h2_style))
    story.append(Paragraph(
        f"Your Wi-Fi network uses <b>{protocol}</b> encryption. "
        f"Wireless signals travel through physical walls into neighboring spaces and streets. "
        f"A strong encryption cipher like AES combined with a complex, high-entropy password ensures that "
        f"unauthorized parties outside your home or office cannot eavesdrop on network traffic or access connected printers and computers.",
        body_style
    ))
    story.append(Spacer(1, 10))

    # 3. Security Findings
    story.append(Paragraph(f"3. Identified Wireless Findings ({len(findings)})", h2_style))
    if not findings:
        story.append(Paragraph("No critical or high severity wireless vulnerabilities were detected. The network adheres to modern WPA2/WPA3 AES security guidelines.", body_style))
    else:
        for idx, f in enumerate(findings):
            f_box = [
                [Paragraph(f"<b>Finding #{idx+1}: {f.get('title')}</b>", bold_body), Paragraph(f"Severity: <b>{f.get('severity', 'Medium')}</b>", bold_body)],
                [Paragraph(f"<b>Impact:</b> {f.get('impact', '')}", body_style), Paragraph(f"<b>Remediation:</b> {f.get('remediation', '')}", body_style)]
            ]
            f_table = Table(f_box, colWidths=[250, 254])
            f_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FEF3C7") if f.get('severity') != "Critical" else colors.HexColor("#FEE2E2")),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FFFFFF")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(f_table)
            story.append(Spacer(1, 8))

    story.append(Spacer(1, 10))

    # 4. Remediation Recommendations
    story.append(Paragraph("4. Recommended Defensive Actions", h2_style))
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", body_style))
        story.append(Spacer(1, 3))

    # 5. Assessment Limitations & Privacy Notice
    story.append(Spacer(1, 12))
    story.append(Paragraph("5. Scope, Limitations & Privacy Boundaries", h2_style))
    privacy_notice = (
        "<b>Privacy Guarantee:</b> MYX AI strictly respects credential confidentiality. "
        "Actual passwords are never embedded, saved, or exported in audit reports. "
        "This evaluation is defensive and non-destructive: it does not perform packet injection, "
        "deauthentication frames, or unauthorized cracking."
    )
    story.append(Paragraph(privacy_notice, body_style))

    # Build PDF document
    doc.build(story, canvasmaker=WifiReportNumberedCanvas)
    return buffer.getvalue()
