import json
import os
import sqlite3
from datetime import date, datetime
from pathlib import Path
from typing import Any

import streamlit as st


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
    st.write("Preencha os dados abaixo para iniciar uma nova analise OSINT.")

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

    with st.form("new_investigation_form", clear_on_submit=False):
        col_a, col_b = st.columns(2)

        with col_a:
            company_name = st.text_input("Nome da Empresa *", placeholder="Ex.: Atlas Global Trading Ltd")
            website = st.text_input("Site/URL", placeholder="https://empresa.com")
            country = st.selectbox("Pais", options=COUNTRIES, index=COUNTRIES.index("Brasil"))
            company_type = st.selectbox("Tipo de Empresa", options=COMPANY_TYPES)

        with col_b:
            directors = st.text_area("Nomes de Socios/Diretores", placeholder="Liste nomes, cargos e documentos conhecidos")
            legal_address = st.text_area("Endereco Legal", placeholder="Endereco completo, cidade, estado e CEP")
            uploaded_docs = st.file_uploader(
                "Upload de Documentos",
                type=["pdf", "png", "jpg", "jpeg", "webp"],
                accept_multiple_files=True,
                help="Envie contratos, certidoes, capturas de tela e documentos de suporte.",
            )

        additional_info = st.text_area(
            "Informacoes Adicionais",
            placeholder="Qualquer contexto extra: denuncias, links, noticias, IDs fiscais, etc.",
        )

        start = st.form_submit_button("🚀 Iniciar Investigacao", type="primary", use_container_width=True)

    if start:
        errors = []
        if not company_name.strip():
            errors.append("Nome da Empresa e obrigatorio.")
        if website and not (
            website.startswith("http://") or website.startswith("https://")
        ):
            errors.append("Site/URL deve comecar com http:// ou https://")

        if errors:
            for err in errors:
                st.error(f"❌ {err}")
            st.session_state.progress = 10
            return

        saved_files = save_uploaded_files(uploaded_docs or [])
        payload = {
            "company_name": company_name.strip(),
            "website": website.strip(),
            "country": country,
            "company_type": company_type,
            "directors": directors.strip(),
            "legal_address": legal_address.strip(),
            "additional_info": additional_info.strip(),
            "uploaded_files": saved_files,
            "risk_score": 0,
            "status": "Em andamento",
        }

        investigation_id = save_investigation(payload)
        st.session_state.last_saved_id = investigation_id
        st.session_state.progress = 100

        st.success(f"✅ Investigacao iniciada com sucesso! ID: #{investigation_id}")
        btn_col1, btn_col2 = st.columns(2)
        with btn_col1:
            if st.button("📄 Gerar Relatorio", use_container_width=True):
                st.info("Modulo de geracao de relatorio sera conectado na Fase 2.")
        with btn_col2:
            if st.button("🔍 Continuar Investigacao", use_container_width=True):
                st.info("Continue anexando evidencias e refinando os dados da empresa.")


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

    tab_new, tab_history, tab_settings = st.tabs(
        ["🆕 Nova Investigacao", "📚 Historico", "⚙️ Configuracoes"]
    )

    with tab_new:
        render_tab_new_investigation()
    with tab_history:
        render_tab_history()
    with tab_settings:
        render_tab_settings()


if __name__ == "__main__":
    main()
