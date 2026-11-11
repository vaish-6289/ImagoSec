import io
import json
import os
import sqlite3
import uuid
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv
from PIL import Image, UnidentifiedImageError

from forensics import analyze_image, detect_suspicious_magic

load_dotenv()
st.set_page_config(page_title="ImagoSec | Fake Image & Scam Scanner", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
      :root { --ink:#e8eef8; --muted:#a9b8cb; --line:#2a3c52; --accent:#4bd1e5; }
      .stApp { background:radial-gradient(ellipse at 50% -20%,#19314d 0,#0b1421 58%); }
      [data-testid="stHeader"] { background:transparent; }
      .block-container { max-width:1280px; padding-top:1.6rem; padding-bottom:3rem; }
      [data-testid="stSidebar"] { background:#0b1421; border-right:1px solid var(--line); }
      .hero { padding:1.7rem 1.8rem; border:1px solid var(--line); border-radius:20px;
        background:linear-gradient(120deg,rgba(20,39,60,.98),rgba(15,27,42,.94)); margin-bottom:1rem; }
      .eyebrow { color:var(--accent); font-size:.78rem; font-weight:700; letter-spacing:.13em; text-transform:uppercase; }
      .hero h1 { color:var(--ink); font-size:2.25rem; margin:.35rem 0; line-height:1.15; }
      .hero p { color:var(--muted); max-width:900px; margin:.55rem 0 0; font-size:1.02rem; }
      .section-title { color:var(--ink); font-size:1.22rem; font-weight:700; margin:1.3rem 0 .45rem; }
      .muted { color:var(--muted); font-size:.92rem; }
      .card { height:100%; min-height:125px; padding:1rem; border:1px solid var(--line);
        border-radius:14px; background:rgba(17,29,45,.9); }
      .card h3 { color:var(--ink); font-size:1rem; margin:0 0 .45rem; }
      .card p { color:var(--muted); font-size:.9rem; margin:0; line-height:1.5; }
      .warning-note { border-left:4px solid #f3b84b; background:rgba(243,184,75,.09); border-radius:8px; padding:.85rem 1rem; color:#f3e5c4; margin:.8rem 0 1rem; }
      .danger-note { border-left:4px solid #f87171; background:rgba(248,113,113,.10); border-radius:8px; padding:.85rem 1rem; color:#fecaca; margin:.8rem 0 1rem; }
      .safe-note { border-left:4px solid #4ade80; background:rgba(74,222,128,.08); border-radius:8px; padding:.85rem 1rem; color:#bbf7d0; margin:.8rem 0 1rem; }
      .alteration-alert { border:2px solid #f3b84b; border-radius:12px; padding:1rem 1.15rem; margin:.8rem 0 1rem; background:rgba(243,184,75,.13); color:#fff1c2; font-size:1.08rem; font-weight:700; }
      .alteration-alert.detected { border-color:#f87171; background:rgba(248,113,113,.14); color:#fecaca; }
      .alteration-alert.clear { border-color:#4ade80; background:rgba(74,222,128,.10); color:#bbf7d0; }
      div[data-testid="stMetric"] { background:rgba(17,29,45,.9); border:1px solid var(--line); border-radius:14px; padding:.85rem; }
      div[data-testid="stMetricLabel"] { color:var(--muted); }
      div[data-testid="stMetricValue"] { color:var(--ink); }
      div[data-testid="stFileUploader"] section { background:rgba(17,29,45,.8); border:1px dashed #496887; border-radius:15px; }
      .footer { color:#8292a8; font-size:.82rem; text-align:center; padding-top:1.6rem; }
      @media(max-width:700px) { .hero h1 {font-size:1.7rem;} .card {min-height:0;margin-bottom:.5rem;} }
    </style>
    """,
    unsafe_allow_html=True,
)


def azure_credential():
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential()


def get_secret(secret_name):
    vault_url = os.getenv("AZURE_KEY_VAULT_URL")
    if not vault_url:
        return None
    from azure.keyvault.secrets import SecretClient
    return SecretClient(vault_url=vault_url, credential=azure_credential()).get_secret(secret_name).value


def get_sql_connection_string():
    secret_name = os.getenv("AZURE_SQL_SECRET_NAME", "imagosec-sql-connection-string")
    return get_secret(secret_name) or os.getenv("AZURE_SQL_CONNECTION_STRING")


def get_blob_service_client():
    secret_name = os.getenv("AZURE_STORAGE_SECRET_NAME", "imagosec-storage-connection-string")
    connection_string = get_secret(secret_name) or os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL")
    if not connection_string and not account_url:
        return None
    from azure.storage.blob import BlobServiceClient
    if connection_string:
        return BlobServiceClient.from_connection_string(connection_string)
    return BlobServiceClient(account_url, credential=azure_credential())


def upload_to_blob(file_bytes, filename, file_hash):
    try:
        client = get_blob_service_client()
        if client is None:
            return None
        container = os.getenv("AZURE_STORAGE_CONTAINER", "imagosec-ingestion")
        blob_name = f"{uuid.uuid4().hex}{Path(filename).suffix.lower()}"
        client.get_blob_client(container=container, blob=blob_name).upload_blob(
            file_bytes, overwrite=False, metadata={"sha256": file_hash}
        )
        return blob_name
    except Exception as exc:
        st.sidebar.warning(f"Private cloud upload failed: {exc}")
        return None


def save_scan(filename, result, blob_name):
    metadata = result.get("metadata", {})
    ela = result.get("ela", {})
    values = (
        result["sha256"], int(result.get("risk_score", 0)), filename,
        json.dumps(metadata.get("flags", [])), json.dumps(ela), blob_name,
        json.dumps(result.get("issues", [])),
    )
    mode = os.getenv("IMAGOSEC_DATABASE", "sqlite").lower()
    if mode == "azure_sql":
        connection_string = get_sql_connection_string()
        if not connection_string:
            raise RuntimeError("Azure SQL selected, but no SQL connection string is configured.")
        import pyodbc
        with pyodbc.connect(connection_string) as connection:
            connection.cursor().execute(
                """INSERT INTO dbo.AnalysisLogs
                   (FileHash, ThreatLevel, FileName, MetadataFlags, ELAReport, BlobName, FindingsJson)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""", values
            )
        return "Azure SQL"
    if mode != "sqlite":
        raise ValueError("IMAGOSEC_DATABASE must be 'sqlite' or 'azure_sql'.")
    with sqlite3.connect(os.getenv("SQLITE_PATH", "local_evaluation_ledger.db")) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS AnalysisLogs (
                LogID INTEGER PRIMARY KEY AUTOINCREMENT, FileHash TEXT NOT NULL,
                ThreatLevel INTEGER NOT NULL, FileName TEXT NOT NULL, MetadataFlags TEXT,
                ELAReport TEXT, BlobName TEXT, FindingsJson TEXT,
                ScanDate TEXT DEFAULT CURRENT_TIMESTAMP)"""
        )
        connection.execute(
            """INSERT INTO AnalysisLogs
               (FileHash, ThreatLevel, FileName, MetadataFlags, ELAReport, BlobName, FindingsJson)
               VALUES (?, ?, ?, ?, ?, ?, ?)""", values
        )
    return "local SQLite"


def status_label(score):
    if score >= 70:
        return "Red: high warning", "danger"
    if score >= 40:
        return "Yellow: review", "warning"
    return "Green: low warning", "safe"


def alteration_result(metadata, ela):
    """Return a cautious plain-language alteration clue summary."""
    software = metadata.get("software") if isinstance(metadata, dict) else None
    flags = metadata.get("flags", []) if isinstance(metadata, dict) else []
    pixel_score = int(ela.get("risk_score", 0)) if isinstance(ela, dict) else 0
    has_pixel_clue = pixel_score > 25
    has_metadata_clue = bool(software or flags)
    if has_pixel_clue or has_metadata_clue:
        return (
            "⚠️ Image changes/alteration clues detected — review this image carefully. "
            "These clues are not proof that it was manipulated.",
            "detected",
        )
    return (
        "No clear image-change clues detected by these checks. This does not prove the image is unchanged.",
        "clear",
    )


with st.sidebar:
    st.markdown("## 🛡️ ImagoSec")
    st.caption("Fake image & scam scanner for everyday users")
    st.divider()
    st.markdown("### What it checks")
    st.markdown("- school fee screenshots\n- payment screenshots\n- message photos\n- suspicious file markers")
    st.divider()
    mode = os.getenv("IMAGOSEC_DATABASE", "sqlite").lower()
    st.markdown("### Storage mode")
    st.write(f"Database: **{'Azure SQL' if mode == 'azure_sql' else 'SQLite (local demo)'}**")
    st.caption("Use Azure only when configured. Demo mode is local SQLite.")

st.markdown(
    """<div class="hero"><div class="eyebrow">Everyday image safety check</div>
    <h1>🛡️ ImagoSec | Fake Image & Scam Scanner</h1>
    <p>Scammers use fake payment screenshots, edited bills, and disguised files to try to fool people. ImagoSec checks for suspicious file markers, hidden editing clues, and unusual pixel patterns so you can pause and verify before trusting an image.</p></div>""",
    unsafe_allow_html=True,
)

st.markdown('<div class="section-title">What can this help you check?</div>', unsafe_allow_html=True)
cols = st.columns(3, gap="small")
items = [
    ("💰 Payment screenshots", "Check if a display image looks changed or fake before transferring money."),
    ("📄 School bills & receipts", "Look for altered totals, false account details, or edited text."),
    ("💬 Message photos", "Spot suspicious or manipulated images sent in chats or social apps."),
]
for col, (title, text) in zip(cols, items):
    with col:
        st.markdown(f"<div class='card'><h3>{title}</h3><p>{text}</p></div>", unsafe_allow_html=True)

st.markdown('<div class="section-title">Check an image</div>', unsafe_allow_html=True)
st.markdown('<div class="muted">Choose a JPG, PNG, or BMP file (maximum 15 MB).</div>', unsafe_allow_html=True)
uploaded = st.file_uploader("Choose an image", type=["jpg", "jpeg", "png", "bmp"], max_upload_size=15, label_visibility="collapsed")

if uploaded is None:
    st.info("Drag and drop an image to get a quick scan for suspicious markers and editing clues.")
else:
    file_bytes = uploaded.getvalue()
    result = analyze_image(uploaded.name, file_bytes)
    suspicious_markers = detect_suspicious_magic(file_bytes)

    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            image.verify()
        image_readable = True
    except (UnidentifiedImageError, OSError, ValueError):
        image_readable = False

    if not image_readable:
        st.error("⛔ This file could not be opened as an image. It may be damaged, mislabeled, or unsupported. Do not open it with another program if you do not trust its source.")
        if suspicious_markers:
            st.markdown("<div class='danger-note'><strong>Suspicious file marker detected:</strong> " + "; ".join(suspicious_markers) + ". This is a warning clue, not a final malware verdict.</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div class='warning-note'><strong>No selected suspicious marker was found.</strong> This does not prove the file is safe; only a small list of signature checks was used.</div>", unsafe_allow_html=True)
        st.markdown("### What to do next")
        st.write("Do not open or forward the file. Verify with the original sender using a trusted method, and scan it with reputable security software if needed.")
        st.stop()

    score = int(result.get("risk_score", 0))
    label, level = status_label(score)
    metadata = result.get("metadata", {})
    ela = result.get("ela", {})
    metadata_flags = metadata.get("flags", []) if isinstance(metadata, dict) else []
    software_found = metadata.get("software") if isinstance(metadata, dict) else None
    pixel_score = int(ela.get("risk_score", 0)) if isinstance(ela, dict) else 0
    alteration_text, alteration_state = alteration_result(metadata, ela)

    preview, summary = st.columns([1, 1.4], gap="large")
    with preview:
        st.markdown('<div class="section-title">Image preview</div>', unsafe_allow_html=True)
        with Image.open(io.BytesIO(file_bytes)) as image:
            st.image(image.copy(), caption=uploaded.name, width=360)
        st.caption(f"SHA-256 fingerprint: `{result['sha256'][:16]}…`")
    with summary:
        st.markdown('<div class="section-title">Your result</div>', unsafe_allow_html=True)
        if level == "danger":
            st.error(f"🚨 {label}")
            st.progress(1.0)
            st.markdown("<div class='danger-note'><strong>Important:</strong> This is a warning result based on selected file and image clues. It is not a full malware verdict.</div>", unsafe_allow_html=True)
        elif level == "warning":
            st.warning(f"⚠️ {label}")
            st.progress(max(0, min(score, 100)) / 100)
            st.markdown("<div class='warning-note'><strong>Potentially suspicious:</strong> Image clues suggest checking carefully before trusting the file.</div>", unsafe_allow_html=True)
        else:
            st.success(f"✅ {label}")
            st.progress(max(0, min(score, 100)) / 100)
            st.markdown("<div class='safe-note'><strong>No selected warning signs found.</strong> This does not prove the image is perfect or malware-free; it only means no selected issues were detected.</div>", unsafe_allow_html=True)
        alteration_class = "detected" if alteration_state == "detected" else "clear"
        st.markdown(f"<div class='alteration-alert {alteration_class}' role='status'>{alteration_text}</div>", unsafe_allow_html=True)

    st.markdown("### Was the image changed or edited?")
    if software_found or metadata_flags:
        trace_text = []
        if software_found:
            trace_text.append(f"Editing software recorded: {software_found}")
        if metadata_flags:
            trace_text.append("Metadata fields present: " + ", ".join(str(x) for x in metadata_flags))
        st.write("**Clues found:** " + "; ".join(trace_text))
    else:
        st.write("**Clues found:** No editing-software metadata or suspicious EXIF fields were found in the file.")

    st.write(f"**Pixel comparison clue:** {ela.get('message', 'No pixel clue available')} The ELA-style score is a warning signal, not a percentage of the image changed.")

    if suspicious_markers:
        st.markdown("### File security check")
        st.error("🚩 Suspicious file marker(s) detected: " + "; ".join(suspicious_markers))
        st.caption("Marker matches are warning indicators. They do not confirm malware by themselves.")
    else:
        st.markdown("### File security check")
        st.success("✅ No selected suspicious executable/archive marker was detected in the file.")
        st.caption("This is a limited check and does not rule out every hidden payload or disguise.")

    ela_heatmap = ela.get("heatmap")
    if ela_heatmap is not None:
        st.markdown("### Pixel-difference map")
        st.image(ela_heatmap, caption="ELA-style map: brighter areas show larger recompression differences, not confirmed edits.")

    if level == "danger":
        st.warning("🛑 Pause and verify before paying, sharing, or trusting the image. Use an official app or trusted contact method instead of relying on the image alone.")
    elif level == "warning":
        st.warning("⚠️ Review the image carefully. Check the sender or source through a trusted method, not just the image itself.")
    else:
        st.info("✅ No major warning signs were detected by this prototype. Still verify important information through an official app or trusted source.")

    with st.expander("Technical details"):
        st.code(
            f"Metadata traces: {software_found or 'none'} | flags={metadata_flags or 'none'} | pixel score={pixel_score}/100 | suspicious markers={suspicious_markers or 'none'}",
            language="text",
        )
        st.json({"metadata": metadata, "ela": ela, "issues": result.get("issues", []), "sha256": result["sha256"]})

    report = {
        "filename": uploaded.name,
        "sha256": result["sha256"],
        "status": label,
        "image_change_clue_result": alteration_text,
        "risk_score": score,
        "suspicious_markers": suspicious_markers,
        "metadata": metadata,
        "ela": {key: value for key, value in ela.items() if key != "heatmap"},
        "issues": result.get("issues", []),
    }
    st.download_button("⬇️ Download scan report", data=json.dumps(report, indent=2, default=str), file_name=f"imagosec-report-{result['sha256'][:12]}.json", mime="application/json")

    if "saved_scan_hashes" not in st.session_state:
        st.session_state.saved_scan_hashes = set()
    if result["sha256"] not in st.session_state.saved_scan_hashes:
        blob_name = upload_to_blob(file_bytes, uploaded.name, result["sha256"])
        try:
            db_name = save_scan(uploaded.name, result, blob_name)
            st.sidebar.success(f"Scan record saved to {db_name}.")
        except Exception as exc:
            st.sidebar.error(f"Scan analyzed, but history could not be saved: {exc}")
        st.session_state.saved_scan_hashes.add(result["sha256"])

st.markdown('<div class="footer">ImagoSec is a prototype warning tool. It does not replace a real antivirus scan or a forensic image-analysis tool.</div>', unsafe_allow_html=True)
