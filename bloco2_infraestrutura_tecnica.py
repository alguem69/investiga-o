import os
import socket
import time
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import requests
import shodan
import streamlit as st
import whois
from bs4 import BeautifulSoup
from geoip2.database import Reader


LOW_COST_HOSTING_TERMS = ["contabo", "hostinger", "ovh", "hetzner", "vultr", "digitalocean"]
WAF_SIGNALS = ["cloudflare", "imperva", "sucuri", "akamai", "incapsula", "f5"]
GENERIC_SERVER_TERMS = ["cloudflare", "nginx", "apache", "litespeed", "iis"]
COMMON_PORTS = [80, 443, 22, 3389]
SPAM_ASNS = {"AS16276", "AS20473", "AS14061"}


def normalize_domain(url: str) -> str:
    candidate = (url or "").strip().lower()
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


def get_ip_from_domain(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def fetch_url(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {"url": None, "status_code": None, "headers": {}, "html": "", "error": None}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(url, timeout=8, allow_redirects=True)
            result["url"] = resp.url
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["html"] = resp.text[:250000]
            return result
        except requests.RequestException as exc:
            result["error"] = str(exc)
            continue
    return result


def detect_server(headers: dict[str, str]) -> dict[str, Any]:
    server_header = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    server_value = f"{server_header} {powered}".strip() or "desconhecido"
    server_l = server_value.lower()
    detected = "desconhecido"
    for option in ["apache", "nginx", "iis", "litespeed", "openresty", "cloudflare"]:
        if option in server_l:
            detected = option
            break
    return {"raw": server_value, "detected": detected}


def detect_waf(headers: dict[str, str]) -> dict[str, Any]:
    compact_headers = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    waf_matches = [name for name in WAF_SIGNALS if name in compact_headers]
    cloudflare_header = any(key.lower().startswith("cf-") for key in headers)
    if cloudflare_header and "cloudflare" not in waf_matches:
        waf_matches.append("cloudflare")
    return {"detected": len(waf_matches) > 0, "providers": sorted(set(waf_matches))}


def detect_hosting_provider(ip: str | None, whois_registrar: str | None) -> dict[str, Any]:
    if not ip:
        return {"provider": "desconhecido", "source": "sem_ip", "strength": "desconhecido"}
    provider_raw = ""
    source = "ipinfo"
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=6)
        if resp.ok:
            data = resp.json()
            provider_raw = (data.get("org") or "").strip()
    except requests.RequestException:
        provider_raw = ""

    if not provider_raw:
        provider_raw = whois_registrar or "desconhecido"
        source = "whois"

    provider_l = provider_raw.lower()
    strength = "forte"
    if any(term in provider_l for term in LOW_COST_HOSTING_TERMS):
        strength = "fraco"
    elif any(term in provider_l for term in ["amazon", "aws", "google", "microsoft", "azure"]):
        strength = "forte"
    return {"provider": provider_raw or "desconhecido", "source": source, "strength": strength}


def analyze_proxy_and_rdap(ip: str | None) -> dict[str, Any]:
    if not ip:
        return {"ip": None, "proxy_detected": None, "hosting": None, "rdap_network": None}
    result = {"ip": ip, "proxy_detected": None, "hosting": None, "rdap_network": None}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,org,message",
            timeout=6,
        )
        if resp.ok:
            data = resp.json()
            if data.get("status") == "success":
                result["proxy_detected"] = bool(data.get("proxy"))
                result["hosting"] = bool(data.get("hosting"))
                result["isp"] = data.get("isp")
                result["org"] = data.get("org")
    except requests.RequestException:
        pass

    try:
        rdap = requests.get(f"https://rdap.org/ip/{ip}", timeout=6)
        if rdap.ok:
            data = rdap.json()
            result["rdap_network"] = data.get("name") or data.get("handle")
    except requests.RequestException:
        pass
    return result


def analyze_asn_bgp(ip: str | None) -> dict[str, Any]:
    if not ip:
        return {"asn": None, "asn_name": None, "bgp_prefixes": [], "error": "IP nao resolvido"}
    asn = None
    asn_name = None
    bgp_prefixes: list[str] = []
    try:
        ipinfo = requests.get(f"https://ipinfo.io/{ip}/json", timeout=6)
        if ipinfo.ok:
            data = ipinfo.json()
            asn_payload = data.get("asn", {})
            if isinstance(asn_payload, dict):
                asn = asn_payload.get("asn")
                asn_name = asn_payload.get("name")
            if not asn:
                asn = data.get("org", "").split(" ")[0] or None
                asn_name = data.get("org")
    except requests.RequestException:
        pass

    if asn and asn.upper().startswith("AS"):
        asn_number = asn.upper().replace("AS", "")
        try:
            bgp = requests.get(f"https://api.bgpview.io/asn/{asn_number}/prefixes", timeout=8)
            if bgp.ok:
                payload = bgp.json()
                prefixes = payload.get("data", {}).get("ipv4_prefixes", [])
                bgp_prefixes = [item.get("prefix", "") for item in prefixes[:15] if item.get("prefix")]
        except requests.RequestException:
            pass

    return {"asn": asn, "asn_name": asn_name, "bgp_prefixes": bgp_prefixes}


def analyze_site_speed(url: str | None, html: str) -> dict[str, Any]:
    if not url:
        return {"load_seconds": None, "bytes": 0, "mbps": None, "slow": None}
    started = time.perf_counter()
    total_bytes = len(html.encode("utf-8"))
    try:
        resp = requests.get(url, timeout=12)
        load_seconds = time.perf_counter() - started
        total_bytes = len(resp.content)
    except requests.RequestException:
        load_seconds = time.perf_counter() - started
    mbps = None
    if load_seconds > 0:
        mbps = (total_bytes / (1024 * 1024)) / load_seconds
    slow = bool(load_seconds > 5 or (mbps is not None and mbps < 1))
    return {
        "load_seconds": round(load_seconds, 3),
        "bytes": total_bytes,
        "mbps": round(mbps, 3) if mbps is not None else None,
        "slow": slow,
    }


def analyze_scripts(html: str) -> dict[str, Any]:
    if not html:
        return {"total_scripts": 0, "signals": [], "uses_wordpress": False, "uses_elementor": False}
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script")
    script_sources = " ".join(
        [tag.get("src", "") for tag in scripts] + [tag.text[:1000] for tag in scripts[:20]]
    ).lower()
    signals: list[str] = []
    uses_wordpress = any(token in script_sources for token in ["wp-content", "wp-includes", "wordpress"])
    uses_elementor = "elementor" in script_sources
    if uses_wordpress:
        signals.append("wordpress")
    if uses_elementor:
        signals.append("elementor")
    for token in ["theme", "template", "envato"]:
        if token in script_sources and token not in signals:
            signals.append(token)
    return {
        "total_scripts": len(scripts),
        "signals": signals,
        "uses_wordpress": uses_wordpress,
        "uses_elementor": uses_elementor,
    }


def analyze_geolocation(ip: str | None) -> dict[str, Any]:
    if not ip:
        return {"ip": None, "country": None, "city": None, "source": None, "error": "IP nao resolvido"}
    db_path = os.getenv("GEOLITE2_DB_PATH", "GeoLite2-City.mmdb")
    if os.path.exists(db_path):
        try:
            with Reader(db_path) as reader:
                data = reader.city(ip)
            return {
                "ip": ip,
                "country": data.country.name,
                "city": data.city.name,
                "latitude": data.location.latitude,
                "longitude": data.location.longitude,
                "source": "GeoLite2",
            }
        except Exception as exc:
            return {"ip": ip, "source": "GeoLite2", "error": str(exc)}
    try:
        fallback = requests.get(f"https://ipinfo.io/{ip}/json", timeout=6)
        if fallback.ok:
            data = fallback.json()
            return {
                "ip": ip,
                "country": data.get("country"),
                "city": data.get("city"),
                "region": data.get("region"),
                "loc": data.get("loc"),
                "source": "ipinfo_fallback",
            }
    except requests.RequestException:
        pass
    return {"ip": ip, "source": "desconhecido", "error": "GeoLite2 ausente e fallback indisponivel"}


def analyze_ip_history(domain: str) -> dict[str, Any]:
    api_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()
    if not api_key:
        return {
            "changes_last_6_months": None,
            "available": False,
            "note": "Configure SECURITYTRAILS_API_KEY para consultar historico de IP.",
        }
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    try:
        response = requests.get(url, headers=headers, timeout=8)
        if response.status_code == 429:
            return {"changes_last_6_months": None, "available": False, "error": "Rate limit da API."}
        response.raise_for_status()
        records = response.json().get("records", [])
        cutoff = datetime.utcnow() - timedelta(days=182)
        changes = 0
        for row in records:
            first_seen = row.get("first_seen")
            if not first_seen:
                continue
            try:
                stamp = datetime.fromisoformat(first_seen.replace("Z", "+00:00")).replace(tzinfo=None)
                if stamp >= cutoff:
                    changes += 1
            except ValueError:
                continue
        return {"changes_last_6_months": changes, "available": True, "raw_records": len(records)}
    except requests.RequestException as exc:
        return {"changes_last_6_months": None, "available": False, "error": str(exc)}


def reverse_ip_lookup(ip: str | None) -> dict[str, Any]:
    if not ip:
        return {"domains_count": None, "sample": [], "available": False}
    try:
        resp = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=8)
        if not resp.ok:
            return {"domains_count": None, "sample": [], "available": False, "error": "Falha no lookup"}
        body = resp.text.strip()
        if "error" in body.lower():
            return {"domains_count": None, "sample": [], "available": False, "error": body}
        domains = [line.strip() for line in body.splitlines() if line.strip()]
        return {"domains_count": len(domains), "sample": domains[:20], "available": True}
    except requests.RequestException as exc:
        return {"domains_count": None, "sample": [], "available": False, "error": str(exc)}


def scan_open_ports(ip: str | None) -> dict[str, Any]:
    if not ip:
        return {"method": "none", "open_ports": [], "available": False}
    shodan_key = os.getenv("SHODAN_API_KEY", "").strip()
    if shodan_key:
        try:
            api = shodan.Shodan(shodan_key)
            host = api.host(ip)
            ports = sorted(host.get("ports", []))
            return {"method": "shodan", "open_ports": ports, "available": True}
        except Exception as exc:
            shodan_error = str(exc)
        else:
            shodan_error = None
    else:
        shodan_error = "Sem SHODAN_API_KEY"

    open_ports: list[int] = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            sock.close()
    return {"method": "socket_scan", "open_ports": open_ports, "available": True, "shodan_error": shodan_error}


def get_whois_registrar(domain: str) -> str | None:
    try:
        info = whois.whois(domain)
        registrar = getattr(info, "registrar", None)
        if isinstance(registrar, list):
            return registrar[0] if registrar else None
        return registrar
    except Exception:
        return None


def calculate_infra_score(analyses: dict[str, Any]) -> tuple[int, list[str]]:
    score = 100
    red_flags: list[str] = []

    hosting = analyses["hosting"]
    if hosting.get("strength") == "fraco":
        score -= 20
        red_flags.append("Hospedagem em provedor low-cost/suspeito")

    waf = analyses["waf"]
    if "cloudflare" in waf.get("providers", []):
        score -= 10
        red_flags.append("WAF Cloudflare detectado (possivel ocultacao)")

    ip_hist = analyses["ip_history"]
    changes = ip_hist.get("changes_last_6_months")
    if isinstance(changes, int) and changes > 3:
        score -= 20
        red_flags.append("Historico IP com mudancas frequentes (>3 em 6 meses)")

    server = analyses["server"]
    if server.get("detected") == "desconhecido":
        score -= 12
        red_flags.append("Servidor generico/desconhecido")

    speed = analyses["speed"]
    if speed.get("slow"):
        score -= 15
        red_flags.append("Site lento (load alto ou throughput baixo)")

    scripts = analyses["scripts"]
    if scripts.get("uses_wordpress") and scripts.get("uses_elementor"):
        score -= 12
        red_flags.append("Uso de WordPress + Elementor/template amador")

    asn_data = analyses["asn_bgp"]
    asn = (asn_data.get("asn") or "").upper()
    if asn in SPAM_ASNS or "OVH" in (asn_data.get("asn_name") or "").upper():
        score -= 15
        red_flags.append("ASN associado a datacenter de alto abuso/spam")

    reverse = analyses["reverse_ip"]
    if isinstance(reverse.get("domains_count"), int) and reverse["domains_count"] > 10:
        score -= 10
        red_flags.append("Mais de 10 dominios no mesmo IP")

    return max(0, min(100, score)), red_flags


def classify_risk_level(score: int) -> str:
    if score <= 35:
        return "alto"
    if score <= 70:
        return "medio"
    return "baixo"


def analyze_infra(url: str) -> dict[str, Any]:
    domain = normalize_domain(url)
    if not domain:
        return {
            "domain": "",
            "infra_score": 0,
            "analyses": {},
            "red_flags": ["Dominio invalido"],
            "risk_level": "alto",
            "error": "Informe URL/dominio valido.",
        }

    page_data = fetch_url(domain)
    headers = page_data.get("headers", {})
    ip = get_ip_from_domain(domain)
    registrar = get_whois_registrar(domain)

    analyses = {
        "server": detect_server(headers),
        "hosting": detect_hosting_provider(ip, registrar),
        "waf": detect_waf(headers),
        "ip_proxy_rdap": analyze_proxy_and_rdap(ip),
        "asn_bgp": analyze_asn_bgp(ip),
        "speed": analyze_site_speed(page_data.get("url"), page_data.get("html", "")),
        "scripts": analyze_scripts(page_data.get("html", "")),
        "geolocation": analyze_geolocation(ip),
        "ip_history": analyze_ip_history(domain),
        "open_ports": scan_open_ports(ip),
        "reverse_ip": reverse_ip_lookup(ip),
        "network": {"domain": domain, "resolved_ip": ip, "http_status": page_data.get("status_code")},
    }

    infra_score, red_flags = calculate_infra_score(analyses)
    risk_level = classify_risk_level(infra_score)
    return {
        "domain": domain,
        "infra_score": infra_score,
        "analyses": analyses,
        "red_flags": red_flags,
        "risk_level": risk_level,
    }


def render_tab_infraestrutura_tecnica() -> None:
    st.subheader("🖥️ BLOCO 2 - Infraestrutura Tecnica")
    st.write("Analise tecnica de infraestrutura para identificar sinais comuns de scams em trading.")
    target_url = st.text_input(
        "URL ou dominio para analise de infraestrutura",
        placeholder="Ex.: www.xyztrade.com",
        key="infra_domain_input",
    )
    analyze_clicked = st.button("Analisar Infraestrutura", type="primary", use_container_width=True)
    if not analyze_clicked:
        return
    if not target_url.strip():
        st.error("Informe uma URL/dominio antes da analise.")
        return

    with st.spinner("Executando BLOCO 2 (servidor, hosting, ASN, IP, scripts, portas)..."):
        result = analyze_infra(target_url)

    score = int(result.get("infra_score", 0))
    st.metric("Infra Score", f"{score}/100")
    st.progress(min(100, max(0, score)))

    if result.get("risk_level") == "alto":
        st.error("Risco de infraestrutura: ALTO")
    elif result.get("risk_level") == "medio":
        st.warning("Risco de infraestrutura: MEDIO")
    else:
        st.success("Risco de infraestrutura: BAIXO")

    red_flags = result.get("red_flags", [])
    if red_flags:
        st.write("### Red Flags")
        for flag in red_flags:
            st.write(f"- {flag}")
    else:
        st.info("Nenhuma red flag automatica acionada no BLOCO 2.")

    st.write("### JSON Estruturado")
    st.json(result)


def render_bloco2_standalone_app() -> None:
    st.set_page_config(page_title="DESTROYER OSINT - Bloco 2", page_icon="🖥️", layout="wide")
    st.title("DESTROYER OSINT - Bloco 2")
    render_tab_infraestrutura_tecnica()

