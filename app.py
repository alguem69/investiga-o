import json
import sqlite3
from datetime import date, datetime
from pathlib import Path
from typing import Any

import streamlit as st

from analise_ip import analise_ip
from bloco1_investigacao_dominio import render_tab_domain_investigation, run_domain_investigation
from bloco2_infraestrutura_tecnica import analyze_infra, render_tab_infraestrutura_tecnica
from bloco3_registros_empresariais import bloco3_registros_empresariais


# ---------------------------
# Configuracoes globais
# ---------------------------
APP_TITLE = "DESTROYER - Sistema OSINT de Investigacao de Fraude"
APP_SUBTITLE = "Investigacao pesada de empresas globais"
DB_PATH = "investigacoes.db"
UPLOAD_DIR = Path("uploads")
APP_VERSION = "v1.0.0 - Fase 1 (Dashboard)"


COUNTRIES = [
    "Afeganistao", "Africa do Sul", "Albania", "Alemanha", "Andorra", "Angola",
    "Antigua e Barbuda", "Arabia Saudita", "Argelia", "Argentina", "Armenia", "Australia",
    "Austria", "Azerbaijao", "Bahamas", "Bahrein", "Bangladesh", "Barbados",
    "Belarus", "Belgica", "Belize", "Benim", "Bolivia", "Bosnia e Herzegovina",
    "Botsuana", "Brasil", "Brunei", "Bulgaria", "Burkina Faso", "Burundi",
    "Butao", "Cabo Verde", "Camaroes", "Camboja", "Canada", "Catar",
    "Cazaquistao", "Chade", "Chile", "China", "Chipre", "Cingapura",
    "Colombia", "Comores", "Congo", "Coreia do Norte", "Coreia do Sul", "Costa do Marfim",
    "Costa Rica", "Croacia", "Cuba", "Dinamarca", "Djibuti", "Dominica",
    "Egito", "El Salvador", "Emirados Arabes Unidos", "Equador", "Eritreia", "Eslovaquia",
    "Eslovenia", "Espanha", "Estados Unidos", "Estonia", "Eswatini", "Etiopia",
    "Fiji", "Filipinas", "Finlandia", "Franca", "Gabao", "Gambia",
    "Gana", "Georgia", "Granada", "Grecia", "Guatemala", "Guiana",
    "Guine", "Guine-Bissau", "Guine Equatorial", "Haiti", "Honduras", "Hungria",
    "Iemen", "Ilhas Marshall", "India", "Indonesia", "Ira", "Iraque",
    "Irlanda", "Islandia", "Israel", "Italia", "Jamaica", "Japao",
    "Jordania", "Kiribati", "Kuwait", "Laos", "Lesoto", "Letonia",
    "Libano", "Liberia", "Libia", "Liechtenstein", "Lituania", "Luxemburgo",
    "Macedonia do Norte", "Madagascar", "Malasia", "Malawi", "Maldivas", "Mali",
    "Malta", "Marrocos", "Mauricio", "Mauritania", "Mexico", "Micronesia",
    "Mocambique", "Moldavia", "Monaco", "Mongolia", "Montenegro", "Myanmar",
    "Namibia", "Nauru", "Nepal", "Nicaragua", "Niger", "Nigeria",
    "Noruega", "Nova Zelandia", "Oma", "Paises Baixos", "Palau", "Panama",
    "Papua-Nova Guine", "Paquistao", "Paraguai", "Peru", "Polonia", "Portugal",
    "Quenia", "Quirguistao", "Reino Unido", "Republica Centro-Africana", "Republica Democratica do Congo", "Republica Dominicana",
    "Republica Tcheca", "Romenia", "Ruanda", "Russia", "Samoa", "San Marino",
    "Santa Lucia", "Sao Cristovao e Nevis", "Sao Tome e Principe", "Sao Vicente e Granadinas", "Seicheles", "Senegal",
    "Serra Leoa", "Servia", "Siria", "Somalia", "Sri Lanka", "Sudao",
    "Sudao do Sul", "Suecia", "Suica", "Suriname", "Tailandia", "Taiwan",
    "Tanzania", "Tajiquistao", "Timor-Leste", "Togo", "Tonga", "Trinidad e Tobago",
    "Tunisia", "Turcomenistao", "Turquia", "Tuvalu", "Ucrania", "Uganda",
    "Uruguai", "Uzbequistao", "Vanuatu", "Vaticano", "Venezuela", "Vietna",
    "Zambia", "Zimbabue",
]

COMPANY_TYPES = ["Trading", "Financeira", "Importadora", "Outra"]
STATUS_OPTIONS = ["Pendente", "Em andamento", "Concluida"]


def init_dirs_and_db() -> None:
    """Cria estrutura local de armazenamento e tabela base."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                company_name TEXT NOT NULL,
                website TEXT,
                country TEXT,
                company_type TEXT,
                directors TEXT,
                legal_address TEXT,
                additional_info TEXT,
                uploaded_files TEXT,
                risk_score INTEGER,
                status TEXT
            )
            """
        )
        conn.commit()


def init_session_state() -> None:
    """Inicializa estados usados no fluxo da UI."""
    defaults: dict[str, Any] = {
        "progress": 0,
        "chat_history": [],
        "last_saved_id": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def save_uploaded_files(files: list[Any]) -> list[str]:
    """Salva anexos em /uploads e retorna os nomes salvos."""
    saved_names: list[str] = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for index, file in enumerate(files):
        safe_name = f"{timestamp}_{index}_{file.name}"
        target = UPLOAD_DIR / safe_name
        with open(target, "wb") as out:
            out.write(file.getbuffer())
        saved_names.append(safe_name)
    return saved_names


def save_investigation(payload: dict[str, Any]) -> int:
    """Persiste uma investigacao no SQLite e retorna o ID."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO investigations (
                created_at,
                company_name,
                website,
                country,
                company_type,
                directors,
                legal_address,
                additional_info,
                uploaded_files,
                risk_score,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                payload["company_name"],
                payload["website"],
                payload["country"],
                payload["company_type"],
                payload["directors"],
                payload["legal_address"],
                payload["additional_info"],
                json.dumps(payload["uploaded_files"], ensure_ascii=True),
                payload["risk_score"],
                payload["status"],
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def load_investigations() -> list[dict[str, Any]]:
    """Retorna investigacoes em ordem decrescente por data."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM investigations ORDER BY datetime(created_at) DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def delete_investigation(investigation_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
        conn.commit()


def clear_history() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM investigations")
        conn.commit()


def export_history_json(records: list[dict[str, Any]]) -> str:
    return json.dumps(records, ensure_ascii=False, indent=2)


def investigar_empresa(
    dominio: str | None = None,
    nome: str | None = None,
    ip: str | None = None,
) -> dict[str, Any]:
    """Investiga com dados parciais: executa apenas os blocos aplicaveis."""
    dom = (dominio or "").strip()
    company = (nome or "").strip()
    ip_val = (ip or "").strip()

    feedback: list[str] = []
    blocos_executados: list[str] = []
    result: dict[str, Any] = {
        "bloco1": None,
        "bloco2": None,
        "bloco3": None,
        "analise_ip": None,
        "feedback": feedback,
        "blocos_executados": blocos_executados,
    }

    if dom:
        result["bloco1"] = run_domain_investigation(dom)
        result["bloco2"] = analyze_infra(dom)
        blocos_executados.extend(["bloco1", "bloco2"])
    else:
        feedback.append("Domínio não fornecido - pulando Bloco 1")
        feedback.append("Domínio não fornecido - pulando Bloco 2")

    if company:
        result["bloco3"] = bloco3_registros_empresariais(company)
        blocos_executados.append("bloco3")
    else:
        feedback.append("Nome da empresa não fornecido - pulando Bloco 3")

    if ip_val:
        result["analise_ip"] = analise_ip(ip_val)
        blocos_executados.append("analise_ip")
    else:
        feedback.append("IP não fornecido - pulando análise de IP")

    result["blocos_executados"] = blocos_executados
    return result


def consolidar_relatorio(dados: dict[str, Any]) -> dict[str, Any]:
    """
    Agrega scores dos blocos executados.
    suspicion_score (B1) e ip_risk_score / corporate_risk_score: maior = mais risco.
    infra_score (B2): maior = infra 'melhor'; converte para risco como (100 - infra_score).
    """
    componentes: list[float] = []

    if dados.get("bloco1"):
        componentes.append(float(dados["bloco1"]["suspicion_score"]))
    if dados.get("bloco2"):
        componentes.append(100.0 - float(dados["bloco2"]["infra_score"]))
    if dados.get("bloco3"):
        componentes.append(float(dados["bloco3"].get("corporate_risk_score", 0)))
    if dados.get("analise_ip"):
        componentes.append(float(dados["analise_ip"].get("ip_risk_score", 0)))

    if not componentes:
        final = 0.0
    else:
        final = sum(componentes) / len(componentes)

    if final >= 70:
        risk_level = "alto"
    elif final >= 40:
        risk_level = "medio"
    else:
        risk_level = "baixo"

    out = {**dados, "final_risk_score": round(final, 1), "risk_level": risk_level}
    out["scores_por_bloco"] = {
        "bloco1_suspicion": dados["bloco1"]["suspicion_score"] if dados.get("bloco1") else None,
        "bloco2_infra": dados["bloco2"]["infra_score"] if dados.get("bloco2") else None,
        "bloco2_risco_derivado": round(100.0 - float(dados["bloco2"]["infra_score"]), 1)
        if dados.get("bloco2")
        else None,
        "bloco3_corporate": dados["bloco3"].get("corporate_risk_score") if dados.get("bloco3") else None,
        "analise_ip_risco": dados["analise_ip"].get("ip_risk_score") if dados.get("analise_ip") else None,
    }
    return out


def render_home() -> None:
    st.set_page_config(
        page_title="DESTROYER OSINT",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.title(f"🛡️ {APP_TITLE}")
    st.caption(APP_SUBTITLE)
    st.markdown("---")


def render_tab_new_investigation() -> None:
    st.subheader("🧭 Nova Investigacao")
    st.caption("Preencha pelo menos um campo. Nenhum dado e obrigatorio — use qualquer combinacao.")

    user_prompt = st.chat_input("Digite observacoes iniciais ou contexto da investigacao...")
    if user_prompt:
        st.session_state.chat_history.append(
            {"role": "user", "content": user_prompt, "ts": datetime.now().isoformat()}
        )

    if st.session_state.chat_history:
        with st.expander("💬 Conversa da Sessao", expanded=False):
            for msg in st.session_state.chat_history[-8:]:
                role = "Investigador" if msg["role"] == "user" else "Sistema"
                st.write(f"**{role}:** {msg['content']}")

    st.session_state.progress = min(st.session_state.progress, 100)
    st.progress(st.session_state.progress, text=f"Progresso da investigacao: {st.session_state.progress}%")

    c1, c2, c3 = st.columns(3)
    with c1:
        have_domain = st.checkbox("Tenho dominio", key="flex_have_domain")
    with c2:
        have_name = st.checkbox("Tenho nome", key="flex_have_name")
    with c3:
        have_ip = st.checkbox("Tenho IP", key="flex_have_ip")

    domain_input = ""
    name_input = ""
    ip_input = ""
    if have_domain:
        domain_input = st.text_input(
            "Dominio ou site",
            placeholder="Ex.: www.xyztrade.com ou https://empresa.com",
            key="flex_domain",
        )
    if have_name:
        name_input = st.text_input(
            "Nome da empresa",
            placeholder="Ex.: Atlas Global Trading Ltd",
            key="flex_company",
        )
    if have_ip:
        ip_input = st.text_input(
            "Endereco IP",
            placeholder="Ex.: 203.0.113.10",
            key="flex_ip",
        )

    with st.expander("Metadados opcionais (para salvar no historico)", expanded=False):
        col_a, col_b = st.columns(2)
        with col_a:
            meta_country = st.selectbox("Pais", options=COUNTRIES, index=COUNTRIES.index("Brasil"), key="flex_country")
            meta_type = st.selectbox("Tipo de Empresa", options=COMPANY_TYPES, key="flex_ctype")
        with col_b:
            meta_directors = st.text_area("Socios/Diretores", key="flex_directors")
            meta_address = st.text_area("Endereco legal", key="flex_address")
        meta_extra = st.text_area("Informacoes adicionais", key="flex_extra")
        uploaded_docs = st.file_uploader(
            "Upload de documentos (opcional)",
            type=["pdf", "png", "jpg", "jpeg", "webp"],
            accept_multiple_files=True,
            key="flex_uploads",
        )

    analyze_flex = st.button("Analisar", type="primary", use_container_width=True)

    dom_s = (domain_input or "").strip()
    name_s = (name_input or "").strip()
    ip_s = (ip_input or "").strip()

    if analyze_flex:
        if not have_domain and not have_name and not have_ip:
            st.error("Marque pelo menos uma opcao: Tenho dominio, Tenho nome ou Tenho IP.")
            return

        if not dom_s and not name_s and not ip_s:
            st.error("Preencha pelo menos um campo (dominio, nome ou IP).")
            return

        if have_domain and not dom_s:
            st.warning("Voce marcou 'Tenho dominio', mas o campo esta vazio — Bloco 1 e 2 serao ignorados.")
        if have_name and not name_s:
            st.warning("Voce marcou 'Tenho nome', mas o campo esta vazio — Bloco 3 sera ignorado.")
        if have_ip and not ip_s:
            st.warning("Voce marcou 'Tenho IP', mas o campo esta vazio — analise de IP sera ignorada.")

        st.info("Analisando com dados disponiveis...")
        with st.spinner("Executando blocos aplicaveis..."):
            bruto = investigar_empresa(dominio=dom_s or None, nome=name_s or None, ip=ip_s or None)
            relatorio = consolidar_relatorio(bruto)

        st.session_state["ultimo_relatorio_osint"] = relatorio
        st.session_state["ultimo_inputs_osint"] = {
            "dom_s": dom_s,
            "name_s": name_s,
            "ip_s": ip_s,
        }
        st.session_state.progress = 100

    relatorio = st.session_state.get("ultimo_relatorio_osint")
    if relatorio:
        for msg in relatorio.get("feedback", []):
            st.caption(msg)

        final_score = relatorio.get("final_risk_score", 0)
        st.metric("Score consolidado de risco", f"{final_score}/100")
        st.progress(min(100, max(0, int(final_score))))
        st.write(f"**Nivel:** {relatorio.get('risk_level', 'n/d').upper()}")
        st.write(f"**Blocos executados:** {', '.join(relatorio.get('blocos_executados', [])) or 'nenhum'}")

        st.markdown("### Relatorio por bloco (apenas os executados)")
        if relatorio.get("bloco1"):
            with st.expander("Bloco 1 — Investigacao de dominio", expanded=True):
                st.json(relatorio["bloco1"])
        if relatorio.get("bloco2"):
            with st.expander("Bloco 2 — Infraestrutura tecnica", expanded=True):
                st.json(relatorio["bloco2"])
        if relatorio.get("bloco3"):
            with st.expander("Bloco 3 — Registros empresariais", expanded=True):
                st.json(relatorio["bloco3"])
        if relatorio.get("analise_ip"):
            with st.expander("Analise de IP", expanded=True):
                st.json(relatorio["analise_ip"])

        with st.expander("JSON consolidado completo"):
            st.json(relatorio)

        inputs_snap = st.session_state.get("ultimo_inputs_osint") or {}
        dom_save = inputs_snap.get("dom_s") or ""
        name_save = inputs_snap.get("name_s") or ""
        ip_save = inputs_snap.get("ip_s") or ""

        save_col1, save_col2 = st.columns(2)
        with save_col1:
            if st.button("Salvar no historico (opcional)", key="flex_save_hist"):
                saved_files = save_uploaded_files(uploaded_docs or [])
                display_name = name_save or dom_save or ip_save or "Investigacao sem identificador"
                payload = {
                    "company_name": display_name,
                    "website": dom_save or "",
                    "country": meta_country,
                    "company_type": meta_type,
                    "directors": (meta_directors or "").strip(),
                    "legal_address": (meta_address or "").strip(),
                    "additional_info": (meta_extra or "").strip(),
                    "uploaded_files": saved_files,
                    "risk_score": int(round(float(final_score))),
                    "status": "Em andamento",
                }
                investigation_id = save_investigation(payload)
                st.session_state.last_saved_id = investigation_id
                st.success(f"Caso salvo com ID #{investigation_id} (score consolidado: {payload['risk_score']}).")
        with save_col2:
            st.download_button(
                "Baixar relatorio JSON",
                data=json.dumps(relatorio, ensure_ascii=False, indent=2),
                file_name=f"destroyer_relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )


def render_tab_history() -> None:
    st.subheader("📚 Historico")
    all_data = load_investigations()

    col_filter_1, col_filter_2, col_filter_3 = st.columns(3)
    with col_filter_1:
        selected_date = st.date_input("Filtrar por data", value=None)
    with col_filter_2:
        country_options = ["Todos"] + sorted({row["country"] or "N/A" for row in all_data})
        selected_country = st.selectbox("Filtrar por pais", options=country_options)
    with col_filter_3:
        max_score = st.slider("Filtrar por score de risco maximo", min_value=0, max_value=100, value=100)

    filtered = []
    for row in all_data:
        row_date = datetime.strptime(row["created_at"], "%Y-%m-%d %H:%M:%S").date()
        country_match = selected_country == "Todos" or (row["country"] or "N/A") == selected_country
        date_match = selected_date is None or row_date == selected_date
        score = row["risk_score"] if row["risk_score"] is not None else 0
        score_match = score <= max_score
        if country_match and date_match and score_match:
            filtered.append(row)

    if not filtered:
        st.info("Nenhuma investigacao encontrada com os filtros atuais.")
        return

    st.write("### Investigacoes Registradas")
    for row in filtered:
        c1, c2, c3, c4, c5, c6 = st.columns([1.3, 2, 1.2, 1, 1.2, 2.5])
        c1.write(row["created_at"])
        c2.write(row["company_name"])
        c3.write(row["country"] or "N/A")
        c4.write(int(row["risk_score"] or 0))
        c5.write(row["status"] or "Pendente")
        with c6:
            b1, b2, b3 = st.columns(3)
            with b1:
                if st.button("Ver Relatorio", key=f"view_{row['id']}"):
                    st.info(f"Relatorio da investigacao #{row['id']} sera exibido na Fase 2.")
            with b2:
                if st.button("Reabrir", key=f"reopen_{row['id']}"):
                    st.success(f"Investigacao #{row['id']} reaberta.")
            with b3:
                if st.button("Deletar", key=f"delete_{row['id']}"):
                    delete_investigation(int(row["id"]))
                    st.warning(f"Investigacao #{row['id']} removida.")
                    st.rerun()


def render_tab_settings() -> None:
    st.subheader("⚙️ Configuracoes")
    st.write("Ajustes de dados locais e versao do dashboard.")

    cfg_col_1, cfg_col_2 = st.columns(2)
    with cfg_col_1:
        if st.button("🧹 Limpar Historico", type="secondary", use_container_width=True):
            clear_history()
            st.success("Historico local apagado com sucesso.")
            st.rerun()

    with cfg_col_2:
        records = load_investigations()
        st.download_button(
            "📤 Exportar Dados (JSON)",
            data=export_history_json(records),
            file_name=f"historico_investigacoes_{date.today().isoformat()}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.markdown("---")
    st.info(f"Versao atual: **{APP_VERSION}**")


def main() -> None:
    init_dirs_and_db()
    init_session_state()
    render_home()

    tab_new, tab_domain, tab_infra, tab_history, tab_settings = st.tabs(
        [
            "🆕 Nova Investigacao",
            "🌐 Investigacao de Dominio",
            "🖥️ Infraestrutura Tecnica",
            "📚 Historico",
            "⚙️ Configuracoes",
        ]
    )

    with tab_new:
        render_tab_new_investigation()
    with tab_domain:
        render_tab_domain_investigation()
    with tab_infra:
        render_tab_infraestrutura_tecnica()
    with tab_history:
        render_tab_history()
    with tab_settings:
        render_tab_settings()


if __name__ == "__main__":
    main()
