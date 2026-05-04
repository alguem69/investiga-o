"""
DESTROYER - Fase 1: Dashboard OSINT para investigacao de fraude empresarial.

Execucao recomendada:
    streamlit run app.py

Tambem e possivel:
    python app.py
    (inicia o servidor Streamlit via subprocess)
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

# ---------------------------------------------------------------------------
# Configuracao global
# ---------------------------------------------------------------------------
APP_TITLE = "DESTROYER - Sistema OSINT de Investigacao de Fraude"
APP_SUBTITLE = "Investigacao pesada de empresas globais"
APP_VERSION = "Fase 1.0.0 - Dashboard"
DB_PATH = "investigacoes.db"
UPLOAD_DIR = Path("uploads")

# Lista de paises para o dropdown (ordem alfabetica em PT-BR aproximada)
COUNTRIES = [
    "Afeganistao",
    "Africa do Sul",
    "Albania",
    "Alemanha",
    "Andorra",
    "Angola",
    "Antigua e Barbuda",
    "Arabia Saudita",
    "Argelia",
    "Argentina",
    "Armenia",
    "Australia",
    "Austria",
    "Azerbaijao",
    "Bahamas",
    "Bahrein",
    "Bangladesh",
    "Barbados",
    "Belarus",
    "Belgica",
    "Belize",
    "Benim",
    "Bolivia",
    "Bosnia e Herzegovina",
    "Botsuana",
    "Brasil",
    "Brunei",
    "Bulgaria",
    "Burkina Faso",
    "Burundi",
    "Butao",
    "Cabo Verde",
    "Camaroes",
    "Camboja",
    "Canada",
    "Catar",
    "Cazaquistao",
    "Chade",
    "Chile",
    "China",
    "Chipre",
    "Cingapura",
    "Colombia",
    "Comores",
    "Congo",
    "Coreia do Norte",
    "Coreia do Sul",
    "Costa do Marfim",
    "Costa Rica",
    "Croacia",
    "Cuba",
    "Dinamarca",
    "Djibuti",
    "Dominica",
    "Egito",
    "El Salvador",
    "Emirados Arabes Unidos",
    "Equador",
    "Eritreia",
    "Eslovaquia",
    "Eslovenia",
    "Espanha",
    "Estados Unidos",
    "Estonia",
    "Eswatini",
    "Etiopia",
    "Fiji",
    "Filipinas",
    "Finlandia",
    "Franca",
    "Gabao",
    "Gambia",
    "Gana",
    "Georgia",
    "Granada",
    "Grecia",
    "Guatemala",
    "Guiana",
    "Guine",
    "Guine-Bissau",
    "Guine Equatorial",
    "Haiti",
    "Honduras",
    "Hungria",
    "Iemen",
    "Ilhas Marshall",
    "India",
    "Indonesia",
    "Ira",
    "Iraque",
    "Irlanda",
    "Islandia",
    "Israel",
    "Italia",
    "Jamaica",
    "Japao",
    "Jordania",
    "Kiribati",
    "Kuwait",
    "Laos",
    "Lesoto",
    "Letonia",
    "Libano",
    "Liberia",
    "Libia",
    "Liechtenstein",
    "Lituania",
    "Luxemburgo",
    "Macedonia do Norte",
    "Madagascar",
    "Malasia",
    "Malawi",
    "Maldivas",
    "Mali",
    "Malta",
    "Marrocos",
    "Mauricio",
    "Mauritania",
    "Mexico",
    "Micronesia",
    "Mocambique",
    "Moldavia",
    "Monaco",
    "Mongolia",
    "Montenegro",
    "Myanmar",
    "Namibia",
    "Nauru",
    "Nepal",
    "Nicaragua",
    "Niger",
    "Nigeria",
    "Noruega",
    "Nova Zelandia",
    "Oma",
    "Paises Baixos",
    "Palau",
    "Panama",
    "Papua-Nova Guine",
    "Paquistao",
    "Paraguai",
    "Peru",
    "Polonia",
    "Portugal",
    "Quenia",
    "Quirguistao",
    "Reino Unido",
    "Republica Centro-Africana",
    "Republica Democratica do Congo",
    "Republica Dominicana",
    "Republica Tcheca",
    "Romenia",
    "Ruanda",
    "Russia",
    "Samoa",
    "San Marino",
    "Santa Lucia",
    "Sao Cristovao e Nevis",
    "Sao Tome e Principe",
    "Sao Vicente e Granadinas",
    "Seicheles",
    "Senegal",
    "Serra Leoa",
    "Servia",
    "Siria",
    "Somalia",
    "Sri Lanka",
    "Sudao",
    "Sudao do Sul",
    "Suecia",
    "Suica",
    "Suriname",
    "Tailandia",
    "Taiwan",
    "Tanzania",
    "Tajiquistao",
    "Timor-Leste",
    "Togo",
    "Tonga",
    "Trinidad e Tobago",
    "Tunisia",
    "Turcomenistao",
    "Turquia",
    "Tuvalu",
    "Ucrania",
    "Uganda",
    "Uruguai",
    "Uzbequistao",
    "Vanuatu",
    "Vaticano",
    "Venezuela",
    "Vietna",
    "Zambia",
    "Zimbabue",
]

COMPANY_TYPES = ["Trading", "Financeira", "Importadora", "Outra"]
STATUS_DEFAULT = "Em andamento"


# ---------------------------------------------------------------------------
# Banco de dados e arquivos
# ---------------------------------------------------------------------------
def init_dirs_and_db() -> None:
    """Garante pasta de uploads e tabela SQLite."""
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
    """Estado persistente entre reruns do Streamlit."""
    if "progress" not in st.session_state:
        st.session_state.progress = 0
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "last_saved_id" not in st.session_state:
        st.session_state.last_saved_id = None


def save_uploaded_files(files: list[Any]) -> list[str]:
    """Persiste anexos em /uploads e retorna nomes salvos."""
    saved: list[str] = []
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    for i, f in enumerate(files):
        name = f"{ts}_{i}_{f.name}"
        path = UPLOAD_DIR / name
        path.write_bytes(f.getbuffer())
        saved.append(name)
    return saved


def save_investigation(payload: dict[str, Any]) -> int:
    """Insere registro e retorna o ID."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            """
            INSERT INTO investigations (
                created_at, company_name, website, country, company_type,
                directors, legal_address, additional_info, uploaded_files,
                risk_score, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        return int(cur.lastrowid)


def load_investigations() -> list[dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM investigations ORDER BY datetime(created_at) DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_investigation(inv_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
        conn.commit()


def clear_all_investigations() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM investigations")
        conn.commit()


def export_json() -> str:
    return json.dumps(load_investigations(), ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Tema visual TOP SECRET / CLASSIFIED (apenas CSS e marcação — sem alterar fluxos)
# ---------------------------------------------------------------------------
def apply_destroyer_theme() -> None:
    """Injeta estilos globais: paleta militar, watermark, sidebar, tabs, inputs, botões."""
    st.markdown(
        """
<style>
    /* Raiz do app Streamlit */
    .stApp,
    [data-testid="stAppViewContainer"],
    section.main > div {
        background-color: #0a0a0a !important;
        color: #FFFFFF !important;
    }

    /* Watermark diagonal repetido (camada fixa, não bloqueia cliques) */
    .stApp::before {
        content: "";
        position: fixed;
        inset: 0;
        z-index: 0;
        pointer-events: none;
        opacity: 1;
        background-image:
            repeating-linear-gradient(
                -35deg,
                transparent 0px,
                transparent 100px,
                rgba(255, 255, 255, 0.05) 100px,
                rgba(255, 255, 255, 0.05) 101px
            ),
            repeating-linear-gradient(
                -35deg,
                rgba(255, 255, 255, 0) 0px,
                rgba(255, 255, 255, 0) 220px,
                rgba(255, 255, 255, 0.02) 220px,
                rgba(255, 255, 255, 0.02) 440px
            );
    }

    .destroyer-watermark-text {
        position: fixed;
        inset: -20%;
        width: 200%;
        height: 200%;
        z-index: 0;
        pointer-events: none;
        overflow: hidden;
        opacity: 0.05;
        color: #FFFFFF;
        font-size: clamp(28px, 4vw, 52px);
        font-weight: 700;
        letter-spacing: 0.15em;
        white-space: pre-wrap;
        transform: rotate(-35deg);
        transform-origin: center;
        line-height: 1.6;
        user-select: none;
    }

    .block-container {
        position: relative;
        z-index: 1 !important;
        padding-top: 1rem;
        max-width: 1200px;
    }

    /* Header Streamlit */
    header[data-testid="stHeader"] {
        background-color: #0a0a0a !important;
        border-bottom: 3px solid #8B0000 !important;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #1a1a1a !important;
        border-right: 2px solid #8B0000 !important;
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] span {
        color: #FFFFFF !important;
    }
    [data-testid="stSidebar"] svg {
        fill: #D4AF37 !important;
        color: #D4AF37 !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover,
    [data-testid="stSidebar"] [data-baseweb="button"]:hover {
        background-color: #2a2a2a !important;
    }

    /* Tipografia base */
    .stApp, .stApp p, .stApp span, .stApp label {
        font-family: Arial, Helvetica, sans-serif !important;
        color: #FFFFFF !important;
    }

    /* Cabeçalho custom DESTROYER */
    .destroyer-header-wrap {
        border-bottom: 4px solid #8B0000;
        padding-bottom: 12px;
        margin-bottom: 8px;
    }
    .destroyer-title-main {
        font-size: 2.1rem;
        font-weight: 800;
        color: #8B0000 !important;
        letter-spacing: 0.08em;
        margin: 0;
    }
    .destroyer-classified-stamp {
        display: inline-block;
        margin-top: 8px;
        padding: 6px 14px;
        border: 3px double #8B0000;
        color: #8B0000 !important;
        font-weight: 800;
        letter-spacing: 0.2em;
        font-size: 0.85rem;
        background: rgba(139, 0, 0, 0.12);
    }
    .destroyer-sub {
        color: #D4AF37 !important;
        margin-top: 6px;
        font-size: 0.95rem;
    }

    /* Faixa CONFIDENTIAL acima das abas */
    .confidential-strip {
        display: block;
        color: #8B0000 !important;
        font-weight: 800;
        letter-spacing: 0.35em;
        font-size: 0.72rem;
        margin: 12px 0 8px 0;
        border-left: 4px solid #8B0000;
        padding-left: 10px;
    }

    /* Cards / área principal */
    .main .block-container {
        border: 2px solid #8B0000;
        background-color: #1a1a1a !important;
        border-radius: 6px;
        padding: 16px 20px 24px 20px;
        box-shadow: 0 0 0 1px rgba(212, 175, 55, 0.15);
    }

    /* Botões primários e secundários */
    .stButton > button {
        background-color: #8B0000 !important;
        color: #FFFFFF !important;
        border: 2px solid #8B0000 !important;
        font-weight: bold !important;
        border-radius: 4px !important;
    }
    .stButton > button:hover {
        background-color: #D4AF37 !important;
        color: #0a0a0a !important;
        border: 2px solid #D4AF37 !important;
    }
    .stDownloadButton > button {
        background-color: #8B0000 !important;
        color: #FFFFFF !important;
        border: 2px solid #8B0000 !important;
        font-weight: bold !important;
    }
    .stDownloadButton > button:hover {
        background-color: #D4AF37 !important;
        color: #0a0a0a !important;
        border-color: #D4AF37 !important;
    }

    /* Inputs */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    [data-baseweb="textarea"] textarea {
        background-color: #1a1a1a !important;
        color: #FFFFFF !important;
        border: 1px solid #8B0000 !important;
        border-radius: 4px !important;
    }
    [data-baseweb="select"] > div,
    [data-baseweb="input"] input {
        background-color: #1a1a1a !important;
        color: #FFFFFF !important;
        border-color: #8B0000 !important;
    }
    [data-testid="stDateInput"] input {
        background-color: #1a1a1a !important;
        color: #FFFFFF !important;
        border: 1px solid #8B0000 !important;
    }
    [data-testid="stSlider"] {
        color: #D4AF37 !important;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 2px solid #8B0000 !important;
        background-color: transparent !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: #FFFFFF !important;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        color: #D4AF37 !important;
        border-bottom: 3px solid #D4AF37 !important;
    }

    /* Progress bar */
    .stProgress > div > div > div > div {
        background-color: #D4AF37 !important;
    }

    /* Chat input */
    [data-testid="stChatInput"] textarea {
        background-color: #1a1a1a !important;
        color: #FFFFFF !important;
        border: 1px solid #8B0000 !important;
    }

    /* Upload */
    [data-testid="stFileUploader"] section {
        border: 1px dashed #8B0000 !important;
        background-color: #1a1a1a !important;
        border-radius: 4px;
    }

    /* Alerts */
    .stAlert {
        background-color: #1a1a1a !important;
        border: 1px solid #8B0000 !important;
        color: #FFFFFF !important;
    }

    /* Badges */
    .badge-clearance {
        display: inline-block;
        background-color: #D4AF37;
        color: #0a0a0a !important;
        padding: 8px 12px;
        border-radius: 4px;
        font-weight: bold;
        margin-right: 8px;
        margin-bottom: 8px;
        font-size: 0.78rem;
        letter-spacing: 0.06em;
    }
    .badge-threat {
        display: inline-block;
        background-color: #8B0000;
        color: #FFFFFF !important;
        padding: 8px 12px;
        border-radius: 4px;
        font-weight: bold;
        margin-right: 8px;
        margin-bottom: 8px;
        font-size: 0.78rem;
        letter-spacing: 0.06em;
    }
    .badge-status {
        display: inline-block;
        background-color: #FFFFFF;
        color: #0a0a0a !important;
        padding: 8px 12px;
        border-radius: 4px;
        font-weight: bold;
        margin-bottom: 8px;
        font-size: 0.78rem;
        letter-spacing: 0.06em;
    }

    /* Rodapé classificado */
    .classified-footer {
        background-color: #8B0000;
        color: #FFFFFF !important;
        padding: 16px;
        text-align: center;
        border-top: 3px solid #D4AF37;
        margin-top: 24px;
        font-size: 0.82rem;
        letter-spacing: 0.08em;
    }
    .classified-footer strong {
        color: #FFFFFF !important;
    }

    hr {
        border-color: #8B0000 !important;
        opacity: 0.6;
    }

    /* Links */
    a {
        color: #D4AF37 !important;
    }

    /* Subtítulos Streamlit */
    .stApp h2, .stApp h3 {
        color: #D4AF37 !important;
    }
</style>
""",
        unsafe_allow_html=True,
    )

    # Texto repetido para watermark legível (FOR OFFICIAL USE ONLY)
    wm_text = "FOR OFFICIAL USE ONLY    " * 80
    st.markdown(
        f'<div class="destroyer-watermark-text">{wm_text}</div>',
        unsafe_allow_html=True,
    )


def render_classified_header() -> None:
    """Título DESTROYER em vermelho militar + carimbo TOP SECRET + subtítulo."""
    st.markdown(
        f"""
<div class="destroyer-header-wrap">
  <div class="destroyer-title-main">DESTROYER</div>
  <div class="destroyer-classified-stamp">TOP SECRET / CLASSIFIED</div>
  <div class="destroyer-sub">{APP_SUBTITLE}</div>
</div>
""",
        unsafe_allow_html=True,
    )


def render_sidebar_classified() -> None:
    """Sidebar com badges de clearance / threat / status (somente visual)."""
    with st.sidebar:
        st.markdown(
            """
<div style="margin-bottom:12px;">
  <span class="badge-clearance">CLEARANCE: LEVEL 4</span>
  <span class="badge-threat">THREAT: MONITORED</span>
  <span class="badge-status">STATUS: OPERATIONAL</span>
</div>
<hr style="border-color:#8B0000;opacity:0.5;" />
<p style="font-size:0.75rem;color:#D4AF37;letter-spacing:0.12em;">SIDEBAR // FIELD OPS</p>
""",
            unsafe_allow_html=True,
        )


def render_classified_footer() -> None:
    """Rodapé com classificação e timestamp de acesso."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    st.markdown(
        f"""
<div class="classified-footer">
  <strong>CLASSIFICATION: TOP SECRET / SCI</strong><br/>
  AUTHORIZED PERSONNEL ONLY<br/>
  <span style="opacity:0.9;">ACCESS TIMESTAMP: {ts}</span>
</div>
""",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Interface - Home
# ---------------------------------------------------------------------------
def render_home() -> None:
    st.set_page_config(
        page_title="DESTROYER OSINT",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    apply_destroyer_theme()
    render_sidebar_classified()
    render_classified_header()


def render_tab_nova() -> None:
    """Aba principal: chat + formulario estruturado."""
    st.subheader("🧭 Nova Investigacao")
    st.markdown(
        "Use o **chat** para notas rapidas e o **formulario** para registrar o caso com estrutura."
    )

    # Chat interativo (mensagens ficam em session_state)
    prompt = st.chat_input("Mensagem ou observacao sobre a investigacao...")
    if prompt:
        st.session_state.chat_history.append(
            {"role": "user", "content": prompt, "ts": datetime.now().isoformat()}
        )

    if st.session_state.chat_history:
        with st.expander("💬 Historico do chat desta sessao", expanded=False):
            for msg in st.session_state.chat_history[-12:]:
                prefix = "👤 Voce" if msg["role"] == "user" else "🤖 Sistema"
                st.markdown(f"**{prefix}:** {msg['content']}")

    # Barra de progresso (simulada ate integracao com modulos OSINT)
    st.session_state.progress = min(max(st.session_state.progress, 0), 100)
    st.progress(
        st.session_state.progress / 100.0,
        text=f"Progresso da investigacao: {st.session_state.progress}%",
    )

    # Formulario em duas colunas para layout responsivo
    with st.form("form_nova_investigacao", clear_on_submit=False):
        col_esq, col_dir = st.columns(2)

        with col_esq:
            st.markdown("##### Dados da empresa")
            company_name = st.text_input(
                "Nome da Empresa *",
                placeholder="Ex.: Atlas Global Trading Ltd",
                help="Campo obrigatorio para iniciar o registro.",
            )
            website = st.text_input(
                "Site / URL (opcional)",
                placeholder="https://www.empresa.com",
            )
            country = st.selectbox("Pais", options=COUNTRIES, index=COUNTRIES.index("Brasil"))
            company_type = st.selectbox("Tipo de Empresa", options=COMPANY_TYPES)

        with col_dir:
            st.markdown("##### Pessoas e endereco")
            directors = st.text_area(
                "Nomes de Socios / Diretores",
                placeholder="Nomes, cargos e documentos conhecidos",
                height=120,
            )
            legal_address = st.text_area(
                "Endereco Legal",
                placeholder="Endereco completo, cidade, estado, CEP",
                height=120,
            )

        st.markdown("##### Documentos e contexto extra")
        uploads = st.file_uploader(
            "Upload de documentos (PDF ou imagem)",
            type=["pdf", "png", "jpg", "jpeg", "webp"],
            accept_multiple_files=True,
            help="Arquivos ficam salvos localmente na pasta uploads/.",
        )
        additional = st.text_area(
            "Informacoes adicionais",
            placeholder="Denuncias, links, IDs fiscais, notas do chat, etc.",
            height=100,
        )

        submitted = st.form_submit_button(
            "🚀 Iniciar Investigacao",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        erros: list[str] = []

        # Validacao: nome obrigatorio
        if not (company_name or "").strip():
            erros.append("O **Nome da Empresa** e obrigatorio.")

        # Validacao: URL opcional, mas se preenchida deve ter protocolo
        site = (website or "").strip()
        if site and not (site.startswith("http://") or site.startswith("https://")):
            erros.append("O **Site/URL** deve comecar com `http://` ou `https://`.")

        if erros:
            for e in erros:
                st.error(f"❌ {e}")
            st.session_state.progress = min(st.session_state.progress, 25)
            return

        # Salva anexos e persiste no SQLite
        files_saved = save_uploaded_files(uploads or [])
        payload = {
            "company_name": company_name.strip(),
            "website": site,
            "country": country,
            "company_type": company_type,
            "directors": (directors or "").strip(),
            "legal_address": (legal_address or "").strip(),
            "additional_info": (additional or "").strip(),
            "uploaded_files": files_saved,
            "risk_score": 0,
            "status": STATUS_DEFAULT,
        }
        new_id = save_investigation(payload)
        st.session_state.last_saved_id = new_id
        st.session_state.progress = 100

        st.success(f"✅ Investigacao registrada com sucesso! **ID #{new_id}**")
        st.balloons()

        ac1, ac2 = st.columns(2)
        with ac1:
            if st.button("📄 Gerar Relatorio", use_container_width=True, key="btn_rel"):
                st.info("O modulo de relatorio sera integrado nas proximas fases.")
        with ac2:
            if st.button("🔍 Continuar Investigacao", use_container_width=True, key="btn_cont"):
                st.info("Continue adicionando notas no chat ou edite os dados em nova submissao.")


def render_tab_historico() -> None:
    """Lista investigacoes com filtros e acoes."""
    st.subheader("📚 Historico")
    dados = load_investigations()

    if not dados:
        st.info("Nenhuma investigacao cadastrada ainda.")
        return

    # Filtros em colunas
    f1, f2, f3 = st.columns(3)
    with f1:
        filtro_data = st.date_input("Filtrar por data", value=None, key="filtro_dt")
    with f2:
        paises_opts = ["Todos"] + sorted({d.get("country") or "N/A" for d in dados})
        filtro_pais = st.selectbox("Filtrar por pais", options=paises_opts, key="filtro_pais")
    with f3:
        filtro_score = st.slider("Score de risco maximo", 0, 100, 100, key="filtro_score")

    filtrados: list[dict[str, Any]] = []
    for row in dados:
        dt = datetime.strptime(row["created_at"], "%Y-%m-%d %H:%M:%S").date()
        ok_data = filtro_data is None or dt == filtro_data
        ok_pais = filtro_pais == "Todos" or (row.get("country") or "N/A") == filtro_pais
        sc = int(row.get("risk_score") or 0)
        ok_score = sc <= filtro_score
        if ok_data and ok_pais and ok_score:
            filtrados.append(row)

    if not filtrados:
        st.warning("Nenhum registro com os filtros atuais.")
        return

    st.markdown("##### Registros")
    # Cabecalho tipo tabela
    h1, h2, h3, h4, h5, h6 = st.columns([1.2, 2.0, 1.0, 0.8, 1.0, 2.2])
    h1.markdown("**Data**")
    h2.markdown("**Empresa**")
    h3.markdown("**Pais**")
    h4.markdown("**Score**")
    h5.markdown("**Status**")
    h6.markdown("**Acoes**")
    st.divider()

    for row in filtrados:
        c1, c2, c3, c4, c5, c6 = st.columns([1.2, 2.0, 1.0, 0.8, 1.0, 2.2])
        c1.write(row["created_at"])
        c2.write(row.get("company_name", ""))
        c3.write(row.get("country") or "N/A")
        c4.write(int(row.get("risk_score") or 0))
        c5.write(row.get("status") or STATUS_DEFAULT)
        with c6:
            a1, a2, a3 = st.columns(3)
            with a1:
                if st.button("Ver", key=f"v_{row['id']}", help="Ver relatorio"):
                    st.info(f"Relatorio completo do caso **#{row['id']}** — disponivel nas proximas fases.")
            with a2:
                if st.button("Reabrir", key=f"r_{row['id']}"):
                    st.success(f"Caso **#{row['id']}** marcado para continuacao (fluxo manual).")
            with a3:
                if st.button("🗑️", key=f"d_{row['id']}", help="Deletar"):
                    delete_investigation(int(row["id"]))
                    st.toast("Registro removido.", icon="🗑️")
                    st.rerun()


def render_tab_config() -> None:
    st.subheader("⚙️ Configuracoes")
    st.markdown("Gerenciamento local dos dados e informacoes do sistema.")

    c1, c2 = st.columns(2)
    with c1:
        if st.button("🧹 Limpar todo o historico", type="secondary", use_container_width=True):
            clear_all_investigations()
            st.success("Historico apagado.")
            st.rerun()
    with c2:
        st.download_button(
            "📤 Exportar investigacoes (JSON)",
            data=export_json(),
            file_name=f"destroyer_export_{date.today().isoformat()}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.markdown("---")
    st.markdown(
        f"**Versao:** `{APP_VERSION}`  \n"
        f"**Banco:** `{DB_PATH}`  \n"
        f"**Uploads:** `{UPLOAD_DIR.resolve()}`"
    )


def main() -> None:
    init_dirs_and_db()
    init_session_state()
    render_home()

    st.markdown(
        '<span class="confidential-strip">CONFIDENTIAL — MAIN OPERATIONS</span>',
        unsafe_allow_html=True,
    )
    tab1, tab2, tab3 = st.tabs(["🆕 Nova Investigacao", "📚 Historico", "⚙️ Configuracoes"])
    with tab1:
        st.markdown(
            '<p style="color:#8B0000;font-size:0.7rem;font-weight:800;letter-spacing:0.25em;margin:0 0 8px 0;">CONFIDENTIAL</p>',
            unsafe_allow_html=True,
        )
        render_tab_nova()
    with tab2:
        st.markdown(
            '<p style="color:#8B0000;font-size:0.7rem;font-weight:800;letter-spacing:0.25em;margin:0 0 8px 0;">CONFIDENTIAL</p>',
            unsafe_allow_html=True,
        )
        render_tab_historico()
    with tab3:
        st.markdown(
            '<p style="color:#8B0000;font-size:0.7rem;font-weight:800;letter-spacing:0.25em;margin:0 0 8px 0;">CONFIDENTIAL</p>',
            unsafe_allow_html=True,
        )
        render_tab_config()

    render_classified_footer()


def _executando_dentro_do_streamlit() -> bool:
    """True quando o arquivo foi carregado pelo `streamlit run` (contexto de script)."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx

        return get_script_run_ctx() is not None
    except Exception:
        return False


if __name__ == "__main__":
    # `streamlit run app.py` -> entra no if e chama main()
    # `python app.py` -> sobe o servidor via subprocess (equivalente ao streamlit run)
    if _executando_dentro_do_streamlit():
        main()
    else:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(Path(__file__).resolve()),
                *sys.argv[1:],
            ],
            check=False,
        )
