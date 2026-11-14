"""
Hardened Outbound SSRF & DNS Rebinding Guard (SafeOutboundHttpClient).
Blocks loopback (127.0.0.0/8, ::1, localhost), RFC 1918 private ranges (unless lab mode + admin approval),
link-local (169.254.0.0/16), cloud metadata (169.254.169.254 unconditionally), and non-HTTP schemes.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from app.core.config import settings

ALLOWED_SCHEMES = {"http", "https"}
CLOUD_METADATA_IP = ipaddress.ip_address("169.254.169.254")


class SsrfBlockedError(ValueError):
    pass


def validate_ip_address(
    ip_str: str,
    allow_controlled_lab: bool = False,
    admin_lab_approved: bool = False,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    addr = ipaddress.ip_address(ip_str)

    # Unconditional block on AWS/GCP/Azure Cloud Metadata (169.254.169.254)
    if addr == CLOUD_METADATA_IP or addr.is_link_local:
        raise SsrfBlockedError(
            f"SSRF Guard: Link-local / Cloud Metadata address ({addr}) is unconditionally blocked."
        )

    if addr.is_loopback or addr.is_unspecified:
        raise SsrfBlockedError(f"SSRF Guard: Loopback address ({addr}) is unconditionally blocked.")

    if addr.is_multicast or (isinstance(addr, ipaddress.IPv4Address) and str(addr) == "255.255.255.255"):
        raise SsrfBlockedError(f"SSRF Guard: Multicast/Broadcast address ({addr}) is blocked.")

    if addr.is_private:
        if not (allow_controlled_lab and admin_lab_approved):
            raise SsrfBlockedError(
                f"SSRF Guard: Private RFC 1918 address ({addr}) is blocked unless ALLOW_CONTROLLED_LAB_TARGETS=true and ADMIN lab approval is active."
            )

    return addr


def validate_and_resolve_target_url(
    url: str,
    allow_controlled_lab: bool = False,
    admin_lab_approved: bool = False,
    custom_resolver=None,
) -> tuple[str, str]:
    """
    Validates scheme, hostname, and resolves A/AAAA records to prevent DNS rebinding.
    Returns (normalized_url, pinned_ip_string).
    """
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SsrfBlockedError(f"SSRF Guard: Disallowed protocol scheme '{scheme}://'. Only http/https allowed.")

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        raise SsrfBlockedError("SSRF Guard: Missing hostname in target URL.")

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise SsrfBlockedError("SSRF Guard: localhost is unconditionally blocked.")

    # Direct IP literal check
    try:
        ip_obj = validate_ip_address(hostname, allow_controlled_lab, admin_lab_approved)
        return url.strip(), str(ip_obj)
    except ValueError as exc:
        if isinstance(exc, SsrfBlockedError):
            raise

    # Resolve DNS records and validate EVERY returned IP to defeat DNS rebinding
    resolved_ips: list[str] = (
        custom_resolver(hostname)
        if custom_resolver is not None
        else [info[4][0] for info in socket.getaddrinfo(hostname, parsed.port or (443 if scheme == "https" else 80))]
    )

    if not resolved_ips:
        raise SsrfBlockedError(f"SSRF Guard: Could not resolve DNS records for '{hostname}'.")

    validated_ips: list[str] = []
    for candidate_ip in resolved_ips:
        checked = validate_ip_address(candidate_ip, allow_controlled_lab, admin_lab_approved)
        validated_ips.append(str(checked))

    return url.strip(), validated_ips[0]
