import json
import sqlite3
from datetime import date, datetime
from pathlib import Path
from typing import Any

import streamlit as st

from relatorio_textual import (
    coletar_dados_investigacao,
    consolidar_score_final,
    dados_para_json_armazenar,
    montar_relatorio_completo,
    relatorio_para_bytes_pdf,
)


# ---------------------------
# Configuracoes globais
# ---------------------------
APP_TITLE = "DESTROYER - Sistema OSINT de Investigacao de Fraude"
APP_SUBTITLE = "Investigacao pesada de empresas globais"
DB_PATH = "investigacoes.db"
UPLOAD_DIR = Path("uploads")
APP_VERSION = "v1.1.0 - Relatorio textual + historico"


COUNTRIES = [
    "Afeganistao",
    "Africa do Sul",
    "Albania",
    "Alemanha",
    "Brasil",
    "Estados Unidos",
    "Portugal",
    "Reino Unido",
    "Outro / Nao informado",
]

COMPANY_TYPES = ["Trading", "Financeira", "Importadora", "Outra"]


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(r[1]) for r in rows}


def init_dirs_and_db() -> None:
    """Cria estrutura local, tabela base e migra colunas de relatorio."""
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
        migrations = [
            ("report_text", "ALTER TABLE investigations ADD COLUMN report_text TEXT"),
            ("report_json", "ALTER TABLE investigations ADD COLUMN report_json TEXT"),
            ("observacoes_iniciais", "ALTER TABLE investigations ADD COLUMN observacoes_iniciais TEXT"),
            ("investigation_ip", "ALTER TABLE investigations ADD COLUMN investigation_ip TEXT"),
        ]
        for col_name, ddl in migrations:
            cols = _table_columns(conn, "investigations")
            if col_name not in cols:
                conn.execute(ddl)
        conn.commit()


def init_session_state() -> None:
    defaults: dict[str, Any] = {
        "progress": 0,
        "last_saved_id": None,
        "report_view_id": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def save_uploaded_files(files: list[Any]) -> list[str]:
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
    """Persiste investigacao com campos opcionais de relatorio."""
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
                status,
                report_text,
                report_json,
                observacoes_iniciais,
                investigation_ip
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                payload["company_name"],
                payload.get("website") or "",
                payload.get("country") or "Outro / Nao informado",
                payload.get("company_type") or "Outra",
                payload.get("directors") or "",
                payload.get("legal_address") or "",
                payload.get("additional_info") or "",
                json.dumps(payload.get("uploaded_files") or [], ensure_ascii=True),
                payload.get("risk_score", 0),
                payload.get("status") or "Concluida",
                payload.get("report_text"),
                payload.get("report_json"),
                payload.get("observacoes_iniciais"),
                payload.get("investigation_ip") or "",
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def load_investigations() -> list[dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM investigations ORDER BY datetime(created_at) DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def load_investigation_by_id(inv_id: int) -> dict[str, Any] | None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    return dict(row) if row else None


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


def render_tab_nova_investigacao() -> None:
    st.subheader("Nova Investigacao")
    st.caption(
        "Use o campo abixo para o contexto. Em seguida, pelas abas superiores, informe **dominio** "
        "e/ou **IP** quando tiver. O botao Analisar funciona mesmo vazio (gera relatorio com o que houver)."
    )

    observacoes = st.text_area(
        "Observacoes iniciais ou contexto da investigacao",
        height=220,
        key="observacoes_investigacao",
        placeholder="Ex.: cliente relata deposito nao devolvido; site recebido por WhatsApp; suspeita de clone...",
    )

    if st.button("Analisar", type="primary", use_container_width=True):
        dominio_ctx = (st.session_state.get("destroyer_dominio") or "").strip()
        ip_ctx = (st.session_state.get("destroyer_ip") or "").strip()

        with st.spinner("Analisando com dados disponiveis — coletando dominio, infraestrutura e IP..."):
            dados = coletar_dados_investigacao(dominio_ctx or None, ip_ctx or None)
            relatorio = montar_relatorio_completo(observacoes or "", dominio_ctx, ip_ctx, dados)
            score, nivel, _ = consolidar_score_final(dados)

        st.session_state["ultimo_relatorio_ui"] = {
            "relatorio": relatorio,
            "dados": dados,
            "observacoes": observacoes or "",
            "dominio_ctx": dominio_ctx,
            "ip_ctx": ip_ctx,
        }

        titulo = relatorio["titulo"]
        st.markdown(f"## {titulo}")
        st.markdown(f"**Data/Hora:** {relatorio['data_hora']}")
        st.metric("Score final (0-100)", f"{relatorio['score_final']}/100 — nivel {relatorio['nivel_risco']}")

        st.markdown("### SECAO 1 - O QUE FOI ENCONTRADO")
        st.text(relatorio["secao_encontrado"])

        st.markdown("### SECAO 2 - ANALISE E CONCLUSOES")
        st.markdown(relatorio["secao_analise"].replace("\n", "\n\n"))

        for msg in dados.get("feedback", []):
            st.caption(msg)

        try:
            pdf_bytes = relatorio_para_bytes_pdf(relatorio)
            st.download_button(
                label="Exportar PDF",
                data=pdf_bytes,
                file_name=f"destroyer_relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as exc:
            st.warning(f"PDF indisponivel ({exc}). Instale: pip install fpdf2")

        st.download_button(
            "Exportar texto (.txt)",
            data=relatorio["texto_plano_completo"].encode("utf-8"),
            file_name=f"destroyer_relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True,
        )

        display_name = dominio_ctx or ip_ctx or "Investigacao OSINT (somente contexto)"
        payload = {
            "company_name": display_name[:200],
            "website": dominio_ctx or "",
            "country": "Outro / Nao informado",
            "company_type": "Outra",
            "directors": "",
            "legal_address": "",
            "additional_info": "",
            "uploaded_files": [],
            "risk_score": int(round(float(score))),
            "status": "Concluida",
            "report_text": relatorio["texto_plano_completo"],
            "report_json": dados_para_json_armazenar(
                observacoes or "", dominio_ctx, ip_ctx, dados, relatorio
            ),
            "observacoes_iniciais": observacoes or "",
            "investigation_ip": ip_ctx or "",
        }
        new_id = save_investigation(payload)
        st.session_state.last_saved_id = new_id
        st.success(f"Relatorio salvo no historico local (ID #{new_id}).")


def render_tab_captura_dominio() -> None:
    st.subheader("Investigacao de Dominio")
    st.write(
        "Informe aqui o **site ou dominio** alvo. Os dados ficam na sessao ate voce voltar em "
        "**Nova Investigacao** e clicar em **Analisar**."
    )
    st.text_input(
        "Dominio ou URL (ex.: www.xyztrade.com)",
        key="destroyer_dominio",
        placeholder="www.exemplo.com",
    )
    if (st.session_state.get("destroyer_dominio") or "").strip():
        st.success(f"Dominio definido: **{st.session_state.destroyer_dominio.strip()}**")
    else:
        st.info("Nenhum dominio informado ainda — o Bloco 1 e o Bloco 2 (por site) serao ignorados na analise.")


def render_tab_captura_infra() -> None:
    st.subheader("Infraestrutura Tecnica")
    st.write(
        "Informe o **endereco IP** que deseja analisar (geolocalizacao, ASN, portas, reverse DNS). "
        "O **Bloco 2 completo** (servidor, WAF, pagina) usa o dominio definido na aba **Investigacao de Dominio**."
    )
    st.text_input(
        "Endereco IP",
        key="destroyer_ip",
        placeholder="Ex.: 203.0.113.10",
    )
    if (st.session_state.get("destroyer_ip") or "").strip():
        st.success(f"IP definido: **{st.session_state.destroyer_ip.strip()}**")
    else:
        st.info("Nenhum IP informado — a analise direta de IP sera ignorada.")


def render_tab_historico() -> None:
    st.subheader("Historico")
    view_id = st.session_state.get("report_view_id")
    if view_id:
        row = load_investigation_by_id(int(view_id))
        if row and row.get("report_text"):
            st.markdown("### Relatorio completo")
            st.caption(f"ID #{row['id']} — {row.get('created_at', '')}")
            st.text_area(
                "Conteudo do relatorio",
                value=row["report_text"],
                height=480,
                key=f"report_body_{view_id}",
            )
            if st.button("Fechar relatorio", key="close_report"):
                st.session_state.report_view_id = None
                st.rerun()
        else:
            st.warning("Relatorio nao disponivel para este registro (dados antigos ou vazios).")
            if st.button("Fechar", key="close_report_empty"):
                st.session_state.report_view_id = None
                st.rerun()
        st.markdown("---")

    all_data = load_investigations()
    if not all_data:
        st.info("Nenhuma investigacao salva ainda.")
        return

    st.write("### Registros")
    for row in all_data:
        c1, c2, c3, c4, c5 = st.columns([1.2, 2.2, 1, 1, 1.6])
        c1.write(row["created_at"])
        c2.write(row.get("company_name") or "—")
        c3.write(int(row["risk_score"] or 0))
        c4.write(row.get("status") or "—")
        with c5:
            b1, b2 = st.columns(2)
            with b1:
                if st.button("Ver Relatorio", key=f"view_rep_{row['id']}"):
                    st.session_state.report_view_id = int(row["id"])
                    st.rerun()
            with b2:
                if st.button("Deletar", key=f"del_rep_{row['id']}"):
                    delete_investigation(int(row["id"]))
                    st.rerun()


def render_tab_configuracoes() -> None:
    st.subheader("Configuracoes")
    st.write("Dados locais e exportacao.")

    cfg_col_1, cfg_col_2 = st.columns(2)
    with cfg_col_1:
        if st.button("Limpar Historico", type="secondary", use_container_width=True):
            clear_history()
            st.success("Historico apagado.")
            st.rerun()

    with cfg_col_2:
        records = load_investigations()
        st.download_button(
            "Exportar dados (JSON)",
            data=export_history_json(records),
            file_name=f"historico_investigacoes_{date.today().isoformat()}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.markdown("---")
    st.info(f"Versao: **{APP_VERSION}**")


def main() -> None:
    init_dirs_and_db()
    init_session_state()
    render_home()

    tab_new, tab_dom, tab_infra, tab_hist, tab_cfg = st.tabs(
        [
            "Nova Investigacao",
            "Investigacao de Dominio",
            "Infraestrutura Tecnica",
            "Historico",
            "Configuracoes",
        ]
    )

    with tab_new:
        render_tab_nova_investigacao()
    with tab_dom:
        render_tab_captura_dominio()
    with tab_infra:
        render_tab_captura_infra()
    with tab_hist:
        render_tab_historico()
    with tab_cfg:
        render_tab_configuracoes()


if __name__ == "__main__":
    main()
