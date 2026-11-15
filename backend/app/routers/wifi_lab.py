"""
MYX AI (Windows Edition) — Wi-Fi Password Lab & Wireless Security Analyzer Router.
Strict Privacy Guarantees:
- Discovers saved profiles locally via Windows 'netsh wlan'.
- Recovers local keys strictly on-demand; never persists or logs credentials.
- Audits passwords offline without external network transmission.
- Generates downloadable PDF reports with passwords completely redacted.
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field

from app.services.wifi_service import (
    discover_saved_wifi_profiles,
    recover_local_wifi_password,
    audit_password_strength_offline,
    generate_strong_wifi_passphrase,
    analyze_wireless_security_posture,
)
from app.services.wifi_pdf_report_service import generate_wifi_audit_pdf

router = APIRouter(prefix="/api/v1/wifi", tags=["Wi-Fi Password Lab & Wireless Security"])


class RecoverPasswordRequest(BaseModel):
    ssid: str = Field(..., description="SSID name of previously saved Wi-Fi network profile")


class AuditPasswordRequest(BaseModel):
    password: str = Field(..., description="Password string to audit offline")


class GeneratePasswordRequest(BaseModel):
    length: Optional[int] = Field(16, ge=8, le=64, description="Length of generated Wi-Fi passphrase")


class AnalyzeNetworkRequest(BaseModel):
    ssid: str = Field(..., description="Target wireless network SSID")
    securityProtocol: Optional[str] = Field("WPA2-Personal", description="WPA2-Personal, WPA3, WEP, Open")
    cipher: Optional[str] = Field("CCMP (AES)", description="CCMP, TKIP, None")
    wpsEnabled: Optional[bool] = Field(False, description="WPS PIN status")
    passwordScore: Optional[int] = Field(None, description="Offline audited password score (0-100)")


class ExportPdfRequest(BaseModel):
    ssid: str = Field(..., description="Audited network SSID")
    securityProtocol: Optional[str] = Field("WPA2-Personal")
    cipher: Optional[str] = Field("CCMP (AES)")
    wpsEnabled: Optional[bool] = Field(False)
    passwordStrength: Optional[str] = Field("Strong")
    passwordEntropy: Optional[float] = Field(64.0)
    overallPosture: Optional[str] = Field("SECURE")
    findings: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    recommendations: Optional[List[str]] = Field(default_factory=list)


@router.get("/profiles", summary="Discover saved Wi-Fi profiles on user's Windows computer")
def get_saved_profiles():
    profiles = discover_saved_wifi_profiles()
    return {
        "ok": True,
        "count": len(profiles),
        "profiles": profiles,
        "environment": "Microsoft Windows 10 / 11",
    }


@router.post("/recover-password", summary="Locally recover saved Wi-Fi password on authenticated Windows device")
def recover_password(req: RecoverPasswordRequest):
    # Strictly local execution via netsh wlan show profile key=clear
    result = recover_local_wifi_password(req.ssid)
    return {
        "ok": result["recovered"],
        "data": result,
        "privacy_notice": "Recovered credential is kept in volatile local memory only. Zero persistence or logging.",
    }


@router.post("/audit-password", summary="Deterministic offline password strength evaluation")
def audit_password(req: AuditPasswordRequest):
    audit_res = audit_password_strength_offline(req.password)
    return {
        "ok": True,
        "audit": audit_res,
        "privacy_notice": "Password evaluated locally via Shannon entropy and dictionary matching. Never transmitted externally.",
    }


@router.post("/generate-password", summary="Generate cryptographically strong random Wi-Fi passphrase")
def generate_password(req: GeneratePasswordRequest):
    strong_pwd = generate_strong_wifi_passphrase(length=req.length or 16)
    audit_meta = audit_password_strength_offline(strong_pwd)
    return {
        "passphrase": strong_pwd,
        "audit": audit_meta,
    }


@router.post("/analyze-network", summary="Defensive wireless network security architecture analysis")
def analyze_network(req: AnalyzeNetworkRequest):
    posture = analyze_wireless_security_posture(
        ssid=req.ssid,
        security_protocol=req.securityProtocol or "WPA2-Personal",
        cipher=req.cipher or "CCMP (AES)",
        wps_enabled=req.wpsEnabled or False,
        password_score=req.passwordScore,
    )
    return {
        "ok": True,
        "posture": posture,
    }


@router.post("/export-pdf", summary="Generate downloadable Wi-Fi security assessment PDF report")
def export_wifi_pdf(req: ExportPdfRequest):
    pdf_bytes = generate_wifi_audit_pdf({
        "ssid": req.ssid,
        "security_protocol": req.securityProtocol,
        "cipher": req.cipher,
        "wps_enabled": req.wpsEnabled,
        "password_strength": req.passwordStrength,
        "password_entropy": req.passwordEntropy,
        "overall_posture": req.overallPosture,
        "findings": req.findings or [],
        "recommendations": req.recommendations or [],
    })

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=\"MYX_AI_WiFi_Security_Audit_{req.ssid.replace(' ', '_')}.pdf\"",
            "X-Report-Classification": "CONFIDENTIAL-PASSWORDS-REDACTED",
        }
    )
