import os
import socket
import ssl
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import requests
import streamlit as st
import whois


def normalize_domain(raw_input: str) -> str:
    """Extrai e normaliza dominio principal sem protocolo/www."""
    candidate = (raw_input or "").strip().lower()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    parsed = urlparse(candidate)
    host = parsed.netloc or parsed.path
    host = host.split("@")[-1].split(":")[0].strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _first_value(value: Any) -> Any:
    if isinstance(value, list) and value:
        return value[0]
    return value


def _to_datetime(value: Any) -> datetime | None:
    val = _first_value(value)
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
    return None


def analyze_whois(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "creation_date": None,
        "age_days": None,
        "registrar": None,
        "whois_privacy": False,
        "raw_name_servers": [],
    }
    try:
        info = whois.whois(domain)
        creation_date = _to_datetime(info.creation_date)
        if creation_date:
            result["creation_date"] = creation_date.strftime("%Y-%m-%d")
            result["age_days"] = (datetime.utcnow() - creation_date).days
        registrar = _first_value(getattr(info, "registrar", None))
        result["registrar"] = registrar
        ns = getattr(info, "name_servers", None)
        if isinstance(ns, Iterable) and not isinstance(ns, (str, bytes)):
            result["raw_name_servers"] = sorted({str(item).lower() for item in ns if item})
        privacy_signals = [
            str(getattr(info, "org", "")),
            str(getattr(info, "name", "")),
            str(getattr(info, "registrant_name", "")),
            str(getattr(info, "emails", "")),
            str(getattr(info, "text", "")),
        ]
        haystack = " ".join(privacy_signals).lower()
        result["whois_privacy"] = any(
            term in haystack
            for term in [
                "privacy",
                "redacted for privacy",
                "whoisguard",
                "domains by proxy",
                "contact privacy",
            ]
        )
    except Exception as exc:
        result["error"] = f"WHOIS indisponivel: {exc}"
    return result


def _resolve_records(domain: str, record_type: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 4.0
    try:
        answers = resolver.resolve(domain, record_type)
    except Exception:
        return []
    records = []
    for ans in answers:
        text = str(ans).strip().rstrip(".")
        if text:
            records.append(text)
    return sorted(set(records))


def analyze_dns(domain: str) -> dict[str, Any]:
    a_records = _resolve_records(domain, "A")
    mx_records = _resolve_records(domain, "MX")
    txt_records = _resolve_records(domain, "TXT")
    nameservers = _resolve_records(domain, "NS")

    spf_records = [txt for txt in txt_records if "v=spf1" in txt.lower()]
    dmarc_records = _resolve_records(f"_dmarc.{domain}", "TXT")
    dkim_hits: dict[str, list[str]] = {}
    for selector in ["default", "google", "selector1", "selector2", "k1", "dkim"]:
        dkim_txt = _resolve_records(f"{selector}._domainkey.{domain}", "TXT")
        if dkim_txt:
            dkim_hits[selector] = dkim_txt

    return {
        "a_records": a_records,
        "mx_records": mx_records,
        "txt_records": txt_records,
        "spf": {"present": len(spf_records) > 0, "records": spf_records},
        "dmarc": {"present": len(dmarc_records) > 0, "records": dmarc_records},
        "dkim": {"present": len(dkim_hits) > 0, "selectors_found": dkim_hits},
        "nameservers": nameservers,
    }


def analyze_ssl(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_to": None,
        "is_lets_encrypt": False,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        issuer_parts = cert.get("issuer", [])
        subject_parts = cert.get("subject", [])
        issuer = "/".join("=".join(item) for group in issuer_parts for item in group)
        subject = "/".join("=".join(item) for group in subject_parts for item in group)
        result["issuer"] = issuer
        result["subject"] = subject
        result["valid_from"] = cert.get("notBefore")
        result["valid_to"] = cert.get("notAfter")
        result["is_lets_encrypt"] = "let's encrypt" in issuer.lower() or "lets encrypt" in issuer.lower()
    except Exception as exc:
        result["error"] = f"SSL indisponivel: {exc}"
    return result


def classify_nameservers(nameservers: list[str]) -> dict[str, Any]:
    lowered = [item.lower() for item in nameservers]
    suspicious_terms = [
        "hostinger",
        "namecheap",
        "contabo",
        "digitalocean",
        "vultr",
        "ovh",
        "hetzner",
    ]
    cloudflare = [ns for ns in lowered if "cloudflare" in ns]
    suspicious = [ns for ns in lowered if any(term in ns for term in suspicious_terms)]
    return {
        "cloudflare_detected": len(cloudflare) > 0,
        "suspicious_nameservers": sorted(set(suspicious)),
        "all": nameservers,
    }


def enumerate_common_subdomains(domain: str) -> dict[str, list[str]]:
    common_subs = [
        "www",
        "mail",
        "smtp",
        "webmail",
        "admin",
        "api",
        "app",
        "portal",
        "crm",
        "dev",
        "staging",
        "m",
        "cdn",
    ]
    found: dict[str, list[str]] = {}
    for sub in common_subs:
        fqdn = f"{sub}.{domain}"
        ips = _resolve_records(fqdn, "A")
        if ips:
            found[fqdn] = ips
    return found


def analyze_dns_history(domain: str) -> dict[str, Any]:
    api_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()
    if not api_key:
        return {
            "provider": "securitytrails",
            "available": False,
            "changes_last_6_months": None,
            "note": "Configure SECURITYTRAILS_API_KEY para habilitar historico DNS.",
        }

    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=8)
        if response.status_code == 429:
            return {
                "provider": "securitytrails",
                "available": False,
                "changes_last_6_months": None,
                "error": "Rate limit da API de historico DNS.",
            }
        response.raise_for_status()
        payload = response.json()
        records = payload.get("records", [])
        six_months_ago = datetime.utcnow().replace(microsecond=0) - timedelta(days=182)
        changes = 0
        for item in records:
            first_seen = item.get("first_seen")
            if not first_seen:
                continue
            try:
                stamp = datetime.fromisoformat(first_seen.replace("Z", "+00:00")).replace(tzinfo=None)
                if stamp >= six_months_ago:
                    changes += 1
            except ValueError:
                continue
        return {
            "provider": "securitytrails",
            "available": True,
            "changes_last_6_months": changes,
            "raw_records_count": len(records),
        }
    except requests.RequestException as exc:
        return {
            "provider": "securitytrails",
            "available": False,
            "changes_last_6_months": None,
            "error": f"Falha ao consultar historico DNS: {exc}",
        }


def build_suspicion_score(analysis: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    red_flags: list[str] = []

    whois_data = analysis["whois"]
    if whois_data.get("whois_privacy"):
        score += 20
        red_flags.append("WHOIS Privacy ativado")

    age_days = whois_data.get("age_days")
    if isinstance(age_days, int) and age_days < 365:
        score += 25
        red_flags.append("Dominio com menos de 1 ano")

    ssl_data = analysis["ssl"]
    if ssl_data.get("is_lets_encrypt"):
        score += 15
        red_flags.append("Certificado Let's Encrypt em empresa potencialmente grande")

    ns_class = analysis["nameserver_classification"]
    if ns_class.get("suspicious_nameservers") or ns_class.get("cloudflare_detected"):
        score += 10
        red_flags.append("Nameservers suspeitos ou com ocultacao (Cloudflare)")

    dns_data = analysis["dns"]
    has_spf = dns_data["spf"]["present"]
    has_dkim = dns_data["dkim"]["present"]
    has_dmarc = dns_data["dmarc"]["present"]
    if not (has_spf and has_dkim and has_dmarc):
        score += 15
        red_flags.append("Ausencia de SPF/DKIM/DMARC completo")

    dns_history = analysis["dns_history"]
    changes = dns_history.get("changes_last_6_months")
    if isinstance(changes, int) and changes > 3:
        score += 10
        red_flags.append("Historico DNS com mudancas frequentes (>3 em 6 meses)")

    return min(score, 100), red_flags


def run_domain_investigation(raw_url: str) -> dict[str, Any]:
    domain = normalize_domain(raw_url)
    if not domain:
        return {
            "domain": "",
            "analysis": {},
            "suspicion_score": 0,
            "red_flags": ["Dominio invalido ou vazio"],
            "error": "Informe uma URL ou dominio valido.",
        }

    whois_data = analyze_whois(domain)
    dns_data = analyze_dns(domain)
    ssl_data = analyze_ssl(domain)
    nameserver_classification = classify_nameservers(dns_data.get("nameservers", []))
    subdomains = enumerate_common_subdomains(domain)
    dns_history = analyze_dns_history(domain)

    analysis = {
        "whois": whois_data,
        "dns": dns_data,
        "ssl": ssl_data,
        "nameserver_classification": nameserver_classification,
        "subdomains_exposed": subdomains,
        "dns_history": dns_history,
    }
    suspicion_score, red_flags = build_suspicion_score(analysis)
    return {
        "domain": domain,
        "analysis": analysis,
        "suspicion_score": suspicion_score,
        "red_flags": red_flags,
    }


def render_tab_domain_investigation() -> None:
    st.subheader("🌐 BLOCO 1 - Investigacao de Dominio")
    st.write("Analise tecnica de dominio para detecao de sinais de fraude em operacoes de trading.")
    target_url = st.text_input(
        "URL ou dominio da empresa suspeita",
        placeholder="Ex.: www.xyztrade.com",
        key="domain_input",
    )
    analyze_clicked = st.button("Analisar Dominio", type="primary", use_container_width=True)

    if not analyze_clicked:
        return
    if not target_url.strip():
        st.error("Informe uma URL/dominio antes de iniciar a analise.")
        return

    with st.spinner("Coletando WHOIS, DNS, SSL e historico DNS..."):
        result = run_domain_investigation(target_url)

    score = result.get("suspicion_score", 0)
    st.metric("Score de Suspeita", f"{score}/100")
    if score >= 70:
        st.error("Risco elevado detectado.")
    elif score >= 40:
        st.warning("Risco moderado detectado.")
    else:
        st.success("Risco baixo no bloco tecnico de dominio.")

    flags = result.get("red_flags", [])
    if flags:
        st.write("### Red Flags")
        for item in flags:
            st.write(f"- {item}")
    else:
        st.info("Nenhuma red flag automatica acionada.")

    st.write("### JSON Estruturado")
    st.json(result)
