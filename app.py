import io
import json
import os
import sqlite3
import uuid
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv
from PIL import Image, UnidentifiedImageError

from forensics import analyze_image

load_dotenv()
st.set_page_config(
    page_title="ImagoSec | Image Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      :root { --ink:#e8eef8; --muted:#9aabc1; --panel:#111d2d; --line:#24364d;
              --accent:#45c4db; --green:#41d6a3; }
      .stApp { background: radial-gradient(ellipse at 50% -20%, #19314d 0, #0b1421 55%); }
      [data-testid="stHeader"] { background: transparent; }
      .block-container { max-width: 1280px; padding-top: 2rem; padding-bottom: 3rem; }
      .hero { padding: 1.6rem 1.8rem; border: 1px solid var(--line); border-radius: 20px;
              background: linear-gradient(120deg, rgba(20,39,60,.96), rgba(15,27,42,.92));
              margin-bottom: 1.4rem; }
      .eyebrow { color: var(--accent); font-size:.78rem; font-weight:700; letter-spacing:.14em;
                 text-transform:uppercase; margin-bottom:.45rem; }
      .hero h1 { color:var(--ink); font-size:2.25rem; margin:0; line-height:1.15; }
      .hero p { color:var(--muted); margin:.7rem 0 0; max-width:760px; font-size:1rem; }
      .section-title { color:var(--ink); font-size:1.2rem; font-weight:700; margin:.6rem 0 .25rem; }
      .subtle { color:var(--muted); font-size:.9rem; }
      div[data-testid="stMetric"] { background:rgba(17,29,45,.9); border:1px solid var(--line);
          border-radius:15px; padding:1rem 1.1rem; }
      div[data-testid="stMetricLabel"] { color:var(--muted); }
      div[data-testid="stMetricValue"] { color:var(--ink); }
      div[data-testid="stTabs"] button { color:var(--muted); }
      div[data-testid="stTabs"] button[aria-selected="true"] { color:var(--accent); }
      div[data-testid="stFileUploader"] section { background:rgba(17,29,45,.8);
          border:1px dashed #3b5877; border-radius:15px; }
      [data-testid="stSidebar"] { background:#0b1421; border-right:1px solid var(--line); }
      .note { border-left:3px solid var(--accent); background:rgba(69,196,219,.08);
              border-radius:8px; padding:.75rem 1rem; color:#c8d8e9; }
      .footer { color:#71839b; font-size:.8rem; text-align:center; padding-top:1.5rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


def azure_credential():
    """Use developer sign-in locally and managed identity when hosted on Azure."""
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential()


def get_secret(secret_name):
    """Read an optional Key Vault secret; return None if Key Vault is not configured."""
    vault_url = os.getenv("AZURE_KEY_VAULT_URL")
    if not vault_url:
        return None

    from azure.keyvault.secrets import SecretClient

    client = SecretClient(vault_url=vault_url, credential=azure_credential())
    return client.get_secret(secret_name).value


def get_sql_connection_string():
    secret_name = os.getenv("AZURE_SQL_SECRET_NAME", "imagosec-sql-connection-string")
    return get_secret(secret_name) or os.getenv("AZURE_SQL_CONNECTION_STRING")


def get_blob_service_client():
    """Create a Blob client only when Blob Storage has been configured."""
    secret_name = os.getenv(
        "AZURE_STORAGE_SECRET_NAME", "imagosec-storage-connection-string"
    )
    connection_string = get_secret(secret_name)
    if not connection_string:
        connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

    account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL")
    if not connection_string and not account_url:
        return None

    from azure.storage.blob import BlobServiceClient

    if connection_string:
        return BlobServiceClient.from_connection_string(connection_string)
    return BlobServiceClient(account_url, credential=azure_credential())


def upload_to_blob(file_bytes, filename, file_hash):
    """Upload to a private, pre-created container when Azure Blob is configured."""
    try:
        client = get_blob_service_client()
        if client is None:
            return None

        container_name = os.getenv("AZURE_STORAGE_CONTAINER", "imagosec-ingestion")
        suffix = Path(filename).suffix.lower()
        blob_name = f"{uuid.uuid4().hex}{suffix}"
        blob_client = client.get_blob_client(container=container_name, blob=blob_name)
        blob_client.upload_blob(
            file_bytes, overwrite=False, metadata={"sha256": file_hash}
        )
        return blob_name
    except Exception as exc:
        st.sidebar.warning(f"Blob upload failed; scan remains available: {exc}")
        return None


def save_scan(filename, result, blob_name):
    """Save scan history to SQLite by default, or Azure SQL when selected."""
    metadata = result.get("metadata", {})
    ela = result.get("ela", {})
    values = (
        result["sha256"],
        int(result["risk_score"]),
        filename,
        json.dumps(metadata.get("flags", [])),
        json.dumps(ela),
        blob_name,
        json.dumps(result.get("issues", [])),
    )
    database_mode = os.getenv("IMAGOSEC_DATABASE", "sqlite").lower()

    if database_mode == "azure_sql":
        connection_string = get_sql_connection_string()
        if not connection_string:
            raise RuntimeError(
                "Azure SQL mode is selected, but no SQL connection string was found. "
                "Configure AZURE_SQL_CONNECTION_STRING or Key Vault."
            )
        import pyodbc

        with pyodbc.connect(connection_string) as connection:
            connection.cursor().execute(
                """INSERT INTO dbo.AnalysisLogs
                   (FileHash, ThreatLevel, FileName, MetadataFlags, ELAReport,
                    BlobName, FindingsJson)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                values,
            )
        return "Azure SQL"

    if database_mode != "sqlite":
        raise ValueError("IMAGOSEC_DATABASE must be 'sqlite' or 'azure_sql'.")

    db_path = os.getenv("SQLITE_PATH", "local_evaluation_ledger.db")
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS AnalysisLogs (
                LogID INTEGER PRIMARY KEY AUTOINCREMENT,
                FileHash TEXT NOT NULL,
                ThreatLevel INTEGER NOT NULL,
                FileName TEXT NOT NULL,
                MetadataFlags TEXT,
                ELAReport TEXT,
                BlobName TEXT,
                FindingsJson TEXT,
                ScanDate TEXT DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        connection.execute(
            """INSERT INTO AnalysisLogs
               (FileHash, ThreatLevel, FileName, MetadataFlags, ELAReport,
                BlobName, FindingsJson)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            values,
        )
    return "local SQLite"


with st.sidebar:
    st.markdown("## 🛡️ ImagoSec")
    st.caption("Image forensics workspace")
    st.divider()
    st.markdown("### Runtime configuration")
    database_mode = os.getenv("IMAGOSEC_DATABASE", "sqlite").lower()
    if database_mode == "azure_sql":
        st.success("Database · Azure SQL")
    else:
        st.info("Database · SQLite (local)")
    blob_configured = bool(
        os.getenv("AZURE_STORAGE_CONNECTION_STRING")
        or os.getenv("AZURE_STORAGE_ACCOUNT_URL")
        or os.getenv("AZURE_KEY_VAULT_URL")
    )
    st.write(f"Blob storage · {'Configured' if blob_configured else 'Not configured'}")
    st.caption(
        "SQLite is the zero-cloud-cost demo mode. Set Azure configuration to verify "
        "cloud integration; paused resources are not contacted."
    )
    st.divider()
    st.markdown("### What this scan checks")
    st.markdown("- File readability and validation\n- Metadata and editing traces\n- ELA-style pixel differences")

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">Image integrity • metadata • pixel analysis</div>
      <h1>🛡️ ImagoSec</h1>
      <p>Inspect an image for metadata and pixel-level indicators in one clear report. 
      This prototype's ELA score is heuristic and cannot prove that an image is authentic or altered.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="section-title">Start an image scan</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtle">Choose a JPG, PNG, or BMP image. Invalid or corrupted files are rejected.</div>',
    unsafe_allow_html=True,
)
uploaded = st.file_uploader(
    "Upload an image", type=["jpg", "jpeg", "png", "bmp"], label_visibility="collapsed"
)

if uploaded is None:
    st.info("Upload an image to see its scan summary, metadata, and analysis details here.")
else:
    file_bytes = uploaded.getvalue()
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            image.verify()
    except (UnidentifiedImageError, OSError, ValueError):
        st.error("Invalid or corrupted image. Please choose a readable JPG, PNG, or BMP file.")
        st.stop()

    with st.spinner("Analyzing image…"):
        result = analyze_image(uploaded.name, file_bytes)

    risk = int(result["risk_score"])
    if risk >= 70:
        status, status_type = "Elevated indicators", "error"
    elif risk >= 40:
        status, status_type = "Review recommended", "warning"
    else:
        status, status_type = "No major indicators", "success"

    col_preview, col_summary = st.columns([1, 1.35], gap="large")
    with col_preview:
        st.markdown('<div class="section-title">Image preview</div>', unsafe_allow_html=True)
        with Image.open(io.BytesIO(file_bytes)) as image:
            st.image(image.copy(), caption=uploaded.name, width=420)
        st.caption(f"{len(file_bytes):,} bytes · SHA-256 `{result['sha256'][:16]}…`")

    with col_summary:
        st.markdown('<div class="section-title">Scan summary</div>', unsafe_allow_html=True)
        score_col, status_col = st.columns(2)
        score_col.metric("Prototype risk score", f"{risk}/100")
        status_col.metric("Assessment", status)
        st.progress(max(0, min(risk, 100)) / 100)
        if status_type == "error":
            st.error("Higher-risk indicators were found. Review the details below.")
        elif status_type == "warning":
            st.warning("Some indicators deserve review; the score is not a forensic verdict.")
        else:
            st.success("No major indicators were detected by this prototype.")
        st.markdown(
            '<div class="note">A low score does not guarantee that an image is genuine. '
            'ELA and metadata can produce false positives and false negatives.</div>',
            unsafe_allow_html=True,
        )

    overview_tab, metadata_tab, technical_tab = st.tabs(
        ["🔎 Findings", "🏷️ Metadata", "📊 Pixel analysis"]
    )
    with overview_tab:
        findings = result.get("issues", [])
        if findings:
            for finding in findings:
                st.warning(finding)
        else:
            st.success("No major findings detected by the current checks.")
        st.code(f"SHA-256: {result['sha256']}", language="text")

    with metadata_tab:
        metadata = result.get("metadata", {})
        if "error" in metadata:
            st.info("Metadata could not be read from this image.")
        else:
            meta_a, meta_b, meta_c = st.columns(3)
            meta_a.metric("Format", str(metadata.get("format") or "Unknown"))
            size = metadata.get("size")
            meta_b.metric("Dimensions", f"{size[0]} × {size[1]}" if size else "Unknown")
            meta_c.metric("Color mode", str(metadata.get("mode") or "Unknown"))
            st.write("**Editing software:**", metadata.get("software") or "Not recorded")
            st.write("**Metadata flags:**", ", ".join(metadata.get("flags", [])) or "None found")
            with st.expander("View complete metadata result"):
                st.json(metadata)

    with technical_tab:
        ela = result.get("ela", {})
        st.metric("ELA-style score", f"{ela.get('risk_score', 0)}/100")
        st.write(ela.get("message", "No ELA summary available."))
        st.caption("This implementation compares recompressed pixels; it does not yet generate a visual heatmap.")
        with st.expander("View quality comparison values"):
            st.json({"quality_scores": ela.get("quality_scores", [])})

    report = {
        "filename": uploaded.name,
        "sha256": result["sha256"],
        "risk_score": risk,
        "issues": result.get("issues", []),
        "metadata": result.get("metadata", {}),
        "ela": result.get("ela", {}),
    }
    st.download_button(
        "⬇️ Download scan report (JSON)",
        data=json.dumps(report, indent=2, default=str),
        file_name=f"imagosec-report-{result['sha256'][:12]}.json",
        mime="application/json",
    )

    # Streamlit reruns the script on UI interactions; persist each hash only once
    # per browser session to avoid duplicate database rows and duplicate blob uploads.
    if "saved_scan_hashes" not in st.session_state:
        st.session_state.saved_scan_hashes = set()
    if result["sha256"] not in st.session_state.saved_scan_hashes:
        blob_name = upload_to_blob(file_bytes, uploaded.name, result["sha256"])
        try:
            database_name = save_scan(uploaded.name, result, blob_name)
            st.sidebar.success(f"Scan history saved to {database_name}.")
        except Exception as exc:
            st.sidebar.error(f"Could not save scan history: {exc}")
        st.session_state.saved_scan_hashes.add(result["sha256"])

st.markdown(
    '<div class="footer">ImagoSec prototype · Local SQLite is intended for demos; Azure services are optional and require configuration.</div>',
    unsafe_allow_html=True,
)
