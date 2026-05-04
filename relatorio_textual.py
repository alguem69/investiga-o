"""
Gera relatorio narrativo (diretoria + linguagem simples) a partir dos Blocos 1 e 2 e analise de IP.
"""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime
from io import BytesIO
from typing import Any

from analise_ip import analise_ip
from bloco1_investigacao_dominio import run_domain_investigation
from bloco2_infraestrutura_tecnica import analyze_infra


def coletar_dados_investigacao(dominio: str | None, ip: str | None) -> dict[str, Any]:
    """Executa apenas os modulos aplicaveis com base no dominio e/ou IP informados."""
    dom = (dominio or "").strip()
    ip_val = (ip or "").strip()
    feedback: list[str] = []
    blocos: list[str] = []
    out: dict[str, Any] = {
        "bloco1": None,
        "bloco2": None,
        "analise_ip": None,
        "feedback": feedback,
        "blocos_executados": blocos,
    }

    if dom:
        out["bloco1"] = run_domain_investigation(dom)
        out["bloco2"] = analyze_infra(dom)
        blocos.extend(["bloco1", "bloco2"])
    else:
        feedback.append(
            "Dominio nao informado na aba Investigacao de Dominio — Bloco 1 e Bloco 2 nao foram executados."
        )

    if ip_val:
        out["analise_ip"] = analise_ip(ip_val)
        blocos.append("analise_ip")
    else:
        feedback.append(
            "IP nao informado na aba Infraestrutura Tecnica — analise de IP nao foi executada."
        )

    out["blocos_executados"] = blocos
    return out


def consolidar_score_final(dados: dict[str, Any]) -> tuple[float, str, str]:
    """
    Retorna (score 0-100, nivel, mensagem_auxiliar).
    Maior score = mais risco. Bloco 2: converte infra_score (maior=melhor) em risco (100-infra).
    """
    partes: list[float] = []
    if dados.get("bloco1"):
        partes.append(float(dados["bloco1"]["suspicion_score"]))
    if dados.get("bloco2"):
        partes.append(100.0 - float(dados["bloco2"]["infra_score"]))
    if dados.get("analise_ip"):
        partes.append(float(dados["analise_ip"].get("ip_risk_score", 0)))

    if not partes:
        return 0.0, "INDETERMINADO", "Nenhum dado tecnico foi coletado; o score reflete apenas o contexto narrativo."

    media = sum(partes) / len(partes)
    if media >= 70:
        nivel = "ALTO"
    elif media >= 40:
        nivel = "MEDIO"
    else:
        nivel = "BAIXO"
    return round(media, 1), nivel, ""


def _sim_nao(val: bool | None) -> str:
    if val is True:
        return "Sim"
    if val is False:
        return "Nao"
    return "Nao informado"


def _lista_ou_traco(items: list[str] | None, max_items: int = 12) -> str:
    if not items:
        return "  (sem registros)"
    lines = []
    for it in items[:max_items]:
        lines.append(f"  - {it}")
    if len(items) > max_items:
        lines.append(f"  ... e mais {len(items) - max_items} itens")
    return "\n".join(lines)


def montar_secao_achados(
    dominio_ctx: str,
    ip_ctx: str,
    dados: dict[str, Any],
) -> str:
    """Secao 1 — fatos em linguagem legivel."""
    linhas: list[str] = []
    linhas.append("CONTEXTO INFORMADO PELO INVESTIGADOR")
    linhas.append(f"  Dominio alvo (aba): {dominio_ctx or '(nao informado)'}")
    linhas.append(f"  IP alvo (aba): {ip_ctx or '(nao informado)'}")
    linhas.append("")

    b1 = dados.get("bloco1")
    if b1:
        a = b1.get("analysis") or {}
        whois = a.get("whois") or {}
        ssl_d = a.get("ssl") or {}
        dns = a.get("dns") or {}
        ns_class = a.get("nameserver_classification") or {}

        linhas.append("DOMINIO E REGISTRO (BLOCO 1)")
        linhas.append(f"  DOMINIO ANALISADO: {b1.get('domain', '')}")
        cri = whois.get("creation_date") or "desconhecida"
        idade = whois.get("age_days")
        if isinstance(idade, int):
            anos = round(idade / 365.25, 1)
            linhas.append(f"  Criacao WHOIS: {cri} (aprox. {idade} dias / ~{anos} anos)")
        else:
            linhas.append(f"  Criacao WHOIS: {cri}")
        linhas.append(f"  Registrador: {whois.get('registrar') or 'nao identificado'}")
        priv = whois.get("whois_privacy")
        linhas.append(f"  WHOIS Privacy (ocultar dono): {_sim_nao(priv)}{' ⚠️' if priv else ''}")
        linhas.append(f"  SSL emissor: {ssl_d.get('issuer') or 'indisponivel'}")
        linhas.append(f"  SSL validade (fim): {ssl_d.get('valid_to') or 'indisponivel'}")
        linhas.append(f"  Let's Encrypt: {_sim_nao(ssl_d.get('is_lets_encrypt'))}")
        linhas.append("  Nameservers (DNS):")
        linhas.append(_lista_ou_traco(dns.get("nameservers")))
        if ns_class.get("cloudflare_detected"):
            linhas.append("  Classificacao NS: Cloudflare detectado (camada extra na frente do site).")
        if ns_class.get("suspicious_nameservers"):
            linhas.append(f"  NS com perfil low-cost/suspeito: {', '.join(ns_class['suspicious_nameservers'])}")
        linhas.append(f"  Red flags automaticas (dominio): {', '.join(b1.get('red_flags') or ['nenhuma'])}")
        linhas.append(f"  Score de suspeita (dominio): {b1.get('suspicion_score', 0)}/100")
        linhas.append("")

    b2 = dados.get("bloco2")
    if b2:
        an = b2.get("analyses") or {}
        srv = an.get("server") or {}
        host = an.get("hosting") or {}
        waf = an.get("waf") or {}
        net = an.get("network") or {}
        geo = an.get("geolocation") or {}

        linhas.append("INFRAESTRUTURA E SITE (BLOCO 2)")
        linhas.append(f"  Site analisado: {b2.get('domain', '')}")
        linhas.append(f"  Servidor (cabecalho HTTP): {srv.get('detected', 'desconhecido')} — detalhe: {srv.get('raw', '')}")
        linhas.append(
            f"  Hospedagem / ASN (estimativa): {host.get('provider', '')} "
            f"(forca percebida: {host.get('strength', 'n/d')})"
        )
        linhas.append(f"  WAF / protecao na borda: {', '.join(waf.get('providers') or ['nenhum detectado'])}")
        linhas.append(f"  IP resolvido do site: {net.get('resolved_ip') or 'n/d'}")
        linhas.append(
            f"  Geolocalizacao (estimativa pelo IP): "
            f"{geo.get('country') or geo.get('city') or geo.get('region') or 'indisponivel'}"
        )
        spd = an.get("speed") or {}
        linhas.append(
            f"  Velocidade (teste simples): {spd.get('load_seconds', 'n/d')} s; "
            f"throughput ~{spd.get('mbps', 'n/d')} MB/s"
        )
        linhas.append(f"  Red flags (infra): {', '.join(b2.get('red_flags') or ['nenhuma'])}")
        linhas.append(f"  Score de infraestrutura (quanto maior, 'melhor' o quadro tecnico): {b2.get('infra_score', 0)}/100")
        linhas.append("")

    ipd = dados.get("analise_ip")
    if ipd:
        an = ipd.get("analyses") or {}
        geo = an.get("geolocation") or {}
        asn = an.get("asn_bgp") or {}
        linhas.append("ANALISE DIRETA DO IP")
        linhas.append(f"  IP: {ipd.get('ip', '')}")
        linhas.append(f"  Pais / cidade (estimativa): {geo.get('country') or ''} {geo.get('city') or ''}".strip())
        linhas.append(f"  ASN: {asn.get('asn') or 'n/d'} — {asn.get('asn_name') or ''}")
        linhas.append(f"  Red flags (IP): {', '.join(ipd.get('red_flags') or ['nenhuma'])}")
        linhas.append(f"  Score de risco do IP: {ipd.get('ip_risk_score', 0)}/100")
        linhas.append("")

    if not (b1 or b2 or ipd):
        linhas.append("NENHUM DADO TECNICO COLETADO")
        linhas.append("  Use as abas superiores para informar dominio e/ou IP antes de clicar em Analisar.")
        linhas.append("")

    return "\n".join(linhas).strip()


def montar_secao_analise(
    observacoes: str,
    dados: dict[str, Any],
    score: float,
    nivel: str,
) -> str:
    """Secao 2 — interpretacao para diretoria e explicacao simples."""
    b1 = dados.get("bloco1")
    b2 = dados.get("bloco2")
    ipd = dados.get("analise_ip")

    partes: list[str] = []
    partes.append("PARA A DIRETORIA (visao executiva)")
    partes.append(
        "Este relatorio resume sinais tecnicos publicos sobre dominio e infraestrutura. "
        "Ele nao prova crime nem fraude; apenas ajuda a decidir se vale aprofundar a diligencia "
        "antes de assinar contratos ou enviar dinheiro."
    )
    partes.append("")

    if observacoes.strip():
        partes.append("CONTEXTO QUE VOCE DESCREVEU")
        partes.append(observacoes.strip())
        partes.append("")

    if nivel == "INDETERMINADO":
        partes.append(
            "RESULTADO ATUAL: sem medicoes tecnicas porque nao havia dominio nem IP para consultar. "
            "Analogia: e como tentar avaliar uma loja sem saber o endereco nem o telefone — "
            "precisamos de pelo menos um dado concreto nas abas superiores."
        )
        return "\n\n".join(partes)

    partes.append(
        f"SCORE CONSOLIDADO (media dos blocos executados): {score}/100 — nivel {nivel}. "
        "Quanto maior o numero, mais alertas empilhados apareceram nos checagens automaticas."
    )
    partes.append("")

    if b1:
        priv = (b1.get("analysis") or {}).get("whois", {}).get("whois_privacy")
        le = (b1.get("analysis") or {}).get("ssl", {}).get("is_lets_encrypt")
        partes.append("O QUE O BLOCO DE DOMINIO SUGERE")
        if priv:
            partes.append(
                "- WHOIS Privacy: o cadastro esconde o nome do responsavel. Isso e comum e legitimo, "
                "mas tambem e usado por golpes para dificultar quem investiga. "
                "Nao e prova de fraude; e um 'sinal amarelo' para olhar com mais cuidado."
            )
        if le:
            partes.append(
                "- Certificado Let's Encrypt: e um 'cadeado' gratuito e valido, como uma tranca padrao de porta. "
                "Grandes bancos costumam usar cadeados mais caros e personalizados (certificados pagos). "
                "Portanto, Let's Encrypt sozinho nao diz que e golpe, mas combina com sites montados rapido."
            )
        if b1.get("red_flags"):
            partes.append(
                "- Lista de alertas automaticos: " + "; ".join(b1["red_flags"]) + "."
            )
        else:
            partes.append(
                "- Nenhum alerta automatico forte foi listado no dominio; isso nao elimina riscos de negocio."
            )
        partes.append("")

    if b2:
        host = (b2.get("analyses") or {}).get("hosting") or {}
        waf = (b2.get("analyses") or {}).get("waf") or {}
        partes.append("O QUE O BLOCO DE INFRAESTRUTURA SUGERE")
        if host.get("strength") == "fraco":
            partes.append(
                "- Hospedagem em provedor de baixo custo: e como uma empresa montar escritorio "
                "num espaco compartilhado barato. Pode ser startup honesta, mas tambem e padrao frequente "
                "em operacoes que querem gastar pouco e mudar de lugar com facilidade."
            )
        if waf.get("detected"):
            partes.append(
                "- WAF (ex.: Cloudflare): e uma 'cortina na vitrine'. Protege contra ataques, "
                "mas tambem esconde detalhes do servidor real. Em investigacoes, isso exige mais passos "
                "para ver o que esta atras."
            )
        partes.append("")

    if ipd:
        partes.append("O QUE A ANALISE DO IP MOSTRA")
        partes.append(
            "O endereco IP e como o CEP do computador na internet. Ele ajuda a ver pais, empresa de internet "
            "e se o endereco parece datacenter, proxy ou servidor compartilhado."
        )
        if ipd.get("red_flags"):
            partes.append("- Alertas no IP: " + "; ".join(ipd["red_flags"]) + ".")
        partes.append("")

    partes.append("PARA QUEM TEM 13 ANOS (explicacao bem simples)")
    partes.append(
        "Imagine que voce vai comprar um videogame online. O relatorio olha: "
        "ha quanto tempo o site existe, quem registrou o nome, se o cadeado do site e simples, "
        "onde o computador do site 'mora' no mundo e se tem muitas 'bandeiras vermelhas' automaticas. "
        "Se aparecerem muitas bandeiras, nao significa que e mentira — significa 'desconfie e pergunte mais'."
    )
    partes.append("")

    partes.append("CONCLUSAO E RECOMENDACAO")
    if nivel == "ALTO":
        partes.append(
            "O conjunto de sinais automaticos ficou forte. Recomendacao: nao avance com pagamentos ou dados "
            "sensiveis ate um profissional revisar documentos, regulacao e identidade da contraparte."
        )
    elif nivel == "MEDIO":
        partes.append(
            "Ha pontos de atencao, mas nada disso substitui analise humana. Recomendacao: pedir comprovantes "
            "independentes (registro, licencas, referencias) e manter trilha de evidencias."
        )
    else:
        partes.append(
            "Os sinais automaticos estao mais calmos, mas isso nao substitui senso comum. "
            "Recomendacao: ainda valide negocio, pessoas e documentos fora do que o computador consegue ver."
        )

    return "\n\n".join(partes)


def montar_relatorio_completo(
    observacoes: str,
    dominio_ctx: str,
    ip_ctx: str,
    dados: dict[str, Any],
) -> dict[str, Any]:
    """Monta titulo, secoes e texto unificado para tela, PDF e banco."""
    score, nivel, extra = consolidar_score_final(dados)
    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sec1 = montar_secao_achados(dominio_ctx, ip_ctx, dados)
    sec2 = montar_secao_analise(observacoes, dados, score, nivel)
    if extra:
        sec2 = f"{sec2}\n\nNOTA TECNICA: {extra}"

    titulo = "RELATORIO DE INVESTIGACAO DESTROYER OSINT"
    cabecalho = f"{titulo}\nData/Hora: {agora}\nScore consolidado: {score}/100 (nivel {nivel})\n"
    obs_bloco = ""
    if observacoes.strip():
        obs_bloco = "\n---\nOBSERVACOES INICIAIS\n" + observacoes.strip() + "\n"

    texto_plano = (
        cabecalho
        + obs_bloco
        + "\n=== SECAO 1 - O QUE FOI ENCONTRADO ===\n"
        + sec1
        + "\n\n=== SECAO 2 - ANALISE E CONCLUSOES ===\n"
        + sec2
    )

    return {
        "titulo": titulo,
        "data_hora": agora,
        "score_final": score,
        "nivel_risco": nivel,
        "secao_encontrado": sec1,
        "secao_analise": sec2,
        "texto_plano_completo": texto_plano,
        "dados_json": dados,
    }


def exportar_pdf_simples(texto: str) -> bytes:
    """
    Gera PDF basico (texto). Acentos sao transliterados para compatibilidade com fonte core Helvetica.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        raise RuntimeError("Instale fpdf2: pip install fpdf2") from None

    def fold(s: str) -> str:
        return "".join(
            c
            for c in unicodedata.normalize("NFD", s)
            if unicodedata.category(c) != "Mn"
        )

    safe = fold(texto)
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=9)
    for line in safe.split("\n"):
        pdf.multi_cell(0, 4.5, line[:2000] if len(line) > 2000 else line)
    buffer = BytesIO()
    pdf.output(buffer)
    return buffer.getvalue()


def relatorio_para_bytes_pdf(relatorio: dict[str, Any]) -> bytes:
    return exportar_pdf_simples(relatorio["texto_plano_completo"])


def dados_para_json_armazenar(
    observacoes: str,
    dominio_ctx: str,
    ip_ctx: str,
    dados: dict[str, Any],
    relatorio: dict[str, Any],
) -> str:
    payload = {
        "observacoes": observacoes,
        "dominio_contexto": dominio_ctx,
        "ip_contexto": ip_ctx,
        "dados_brutos": dados,
        "relatorio_meta": {
            "titulo": relatorio["titulo"],
            "data_hora": relatorio["data_hora"],
            "score_final": relatorio["score_final"],
            "nivel_risco": relatorio["nivel_risco"],
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
