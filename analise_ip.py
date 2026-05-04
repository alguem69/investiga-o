"""Analise OSINT focada em endereco IP (geolocalizacao, ASN, portas, reverse DNS)."""

from typing import Any

from bloco2_infraestrutura_tecnica import (
    SPAM_ASNS,
    analyze_asn_bgp,
    analyze_geolocation,
    analyze_proxy_and_rdap,
    reverse_ip_lookup,
    scan_open_ports,
)


def _compute_ip_risk_score(analyses: dict[str, Any]) -> tuple[int, list[str]]:
    """Score 0-100: maior = mais risco/suspeita para o IP."""
    score = 0
    flags: list[str] = []
    proxy = analyses.get("proxy_rdap") or {}
    if proxy.get("proxy_detected"):
        score += 25
        flags.append("Proxy detectado no IP")
    if proxy.get("hosting"):
        score += 10
        flags.append("IP classificado como hosting/datacenter")

    asn = analyses.get("asn_bgp") or {}
    asn_val = (asn.get("asn") or "").upper()
    asn_name = (asn.get("asn_name") or "").upper()
    if asn_val in SPAM_ASNS or "OVH" in asn_name:
        score += 20
        flags.append("ASN associado a datacenter de alto volume")

    rev = analyses.get("reverse_ip") or {}
    cnt = rev.get("domains_count")
    if isinstance(cnt, int) and cnt > 10:
        score += 15
        flags.append("Muitos dominios no mesmo IP (reverse lookup)")

    ports = analyses.get("open_ports") or {}
    open_p = ports.get("open_ports") or []
    if 22 in open_p or 3389 in open_p:
        score += 10
        flags.append("Portas administrativas expostas (22/3389)")

    return min(100, score), flags


def analise_ip(ip: str) -> dict[str, Any]:
    """
    Analisa um IPv4/IPv6 com APIs e utilitarios ja usados no Bloco 2.
    Retorna JSON estruturado + ip_risk_score alinhado ao dashboard.
    """
    ip_clean = (ip or "").strip()
    if not ip_clean:
        return {
            "ip": "",
            "ip_risk_score": 0,
            "red_flags": [],
            "analyses": {},
            "error": "IP vazio.",
        }

    analyses = {
        "geolocation": analyze_geolocation(ip_clean),
        "asn_bgp": analyze_asn_bgp(ip_clean),
        "proxy_rdap": analyze_proxy_and_rdap(ip_clean),
        "open_ports": scan_open_ports(ip_clean),
        "reverse_ip": reverse_ip_lookup(ip_clean),
    }
    risk, flags = _compute_ip_risk_score(analyses)
    return {
        "ip": ip_clean,
        "ip_risk_score": risk,
        "red_flags": flags,
        "analyses": analyses,
    }
