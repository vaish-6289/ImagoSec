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
from dotenv import load_dotenv

load_dotenv()
st.set_page_config(page_title="ImagoSec | Image Safety Check", page_icon="🛡️", layout="wide")

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
      .safety-note { border-left:4px solid #f3b84b; background:rgba(243,184,75,.09); border-radius:8px;
        padding:.85rem 1rem; color:#f3e5c4; margin:.8rem 0 1rem; }
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
        result["sha256"], int(result["risk_score"]), filename,
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


def score_band(score):
    if score >= 70:
        return "🔴 More indicators to review"
    if score >= 40:
        return "🟠 Some indicators to review"
    return "🟢 Few indicators detected"


with st.sidebar:
    st.markdown("## 🛡️ ImagoSec")
    st.caption("Cybersecurity checks for everyday images")
    st.divider()
    mode = os.getenv("IMAGOSEC_DATABASE", "sqlite").lower()
    st.write(f"Database: **{'Azure SQL' if mode == 'azure_sql' else 'SQLite (local demo)'}**")
    st.caption("Azure services are optional and used only when configured.")
    st.divider()
    st.caption("A screenshot cannot prove a payment was made. Check your bank or payment app directly.")

st.markdown(
    """<div class="hero"><div class="eyebrow">Cybersecurity for everyday images</div>
    <h1>🛡️ Check the image. Pause before you trust it.</h1>
    <p>Check a receipt, school notice, online-sale screenshot, or image from a message for selected warning signs. ImagoSec can highlight clues to double-check. It is not antivirus and cannot prove an image is genuine.</p></div>""",
    unsafe_allow_html=True,
)

st.markdown('<div class="section-title">What do we check?</div>', unsafe_allow_html=True)
cols = st.columns(4, gap="small")
items = [
    ("📁 Is it a real, readable image?", "Checks that the file opens and has an allowed image type. <b>(file validation)</b>"),
    ("🏷️ What details are saved?", "Looks for editing-software and other image details. <b>(metadata / EXIF)</b>"),
    ("🧩 Do pixel patterns differ?", "Compares recompressed copies for unusual differences. <b>(ELA-style analysis)</b>"),
    ("⚠️ Is it malicious?", "This prototype is not an antivirus scanner. It cannot confirm whether a file is malware."),
]
for col, (title, text) in zip(cols, items):
    with col:
        st.markdown(f"<div class='card'><h3>{title}</h3><p>{text}</p></div>", unsafe_allow_html=True)

st.markdown('<div class="section-title">Check an image</div>', unsafe_allow_html=True)
st.markdown('<div class="muted">Choose a JPG, PNG, or BMP file (maximum 15 MB).</div>', unsafe_allow_html=True)
uploaded = st.file_uploader("Choose an image", type=["jpg", "jpeg", "png", "bmp"], max_upload_size=15, label_visibility="collapsed")

if uploaded is None:
    st.info("Choose an image to see the checks and practical next steps.")
else:
    file_bytes = uploaded.getvalue()
    suspicious_markers = detect_suspicious_magic(file_bytes)
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            image.verify()
        image_readable = True
    except (UnidentifiedImageError, OSError, ValueError):
        image_readable = False

    if not image_readable:
        st.error("⛔ This file could not be opened as an image. It may be damaged, mislabeled, or unsupported. Do not open it with another program if you do not trust its source.")
        st.markdown("### Security result")
        st.error("**Malicious content: UNKNOWN — NOT SCANNED.** ImagoSec does not include antivirus scanning, so it cannot say this file is malicious or safe.")
        if suspicious_markers:
            st.warning("A limited file-signature rule matched: " + ", ".join(repr(marker) for marker in suspicious_markers) + ". This is a warning clue, not a malware verdict.")
        else:
            st.info("No match in the prototype's small signature-rule list. This does not mean the file is safe; no percentage or clean verdict is available.")
        st.write("**Was the image changed?** Cannot assess because this file was not readable as an image.")
        st.write("**What should I do?** Do not open or forward it. If it matters, confirm with the sender through a trusted channel and scan it with reputable security software.")
        st.stop()

    with st.spinner("Checking image details and pixel patterns…"):
        result = analyze_image(uploaded.name, file_bytes)
    metadata = result.get("metadata", {})
    ela = result.get("ela", {})
    pixel_score = max(0, min(100, int(ela.get("risk_score", 0))))
    software = metadata.get("software") if isinstance(metadata, dict) else None
    metadata_flags = metadata.get("flags", []) if isinstance(metadata, dict) else []
    edit_traces = []
    if software:
        edit_traces.append(f"editing software recorded: {software}")
    if metadata_flags:
        edit_traces.append("metadata fields: " + ", ".join(str(flag) for flag in metadata_flags))
    pixel_flag = pixel_score > 30

    image_col, results_col = st.columns([1, 1.4], gap="large")
    with image_col:
        with Image.open(io.BytesIO(file_bytes)) as image:
            st.image(image.copy(), caption=uploaded.name, width=380)
        st.caption(f"SHA-256 file fingerprint: `{result['sha256'][:16]}…`")
    with results_col:
        st.markdown("### Your results")
        if edit_traces or pixel_flag:
            st.warning("🟠 **Possible editing clues found.** This does not prove the image was changed.")
        else:
            st.success("🟢 **No specific alteration clues found by these checks.** This does not prove the image is unchanged.")
        st.metric("ELA-style pixel indicator score", f"{pixel_score}/100")
        st.progress(pixel_score / 100)
        st.markdown('<div class="safety-note"><b>How to read this:</b> The score measures this prototype’s pixel-difference signal. It is not the percentage of the image changed and is not a probability.</div>', unsafe_allow_html=True)

    st.markdown("### Was your image changed or altered?")
    if edit_traces:
        st.write("**Editing-related metadata traces found:** " + "; ".join(edit_traces) + ". Such traces can be normal and do not prove an edit.")
    else:
        st.write("**Editing-related metadata traces:** None found in the fields checked.")
    if pixel_flag:
        st.write(f"**Pixel differences:** The ELA-style indicator is {pixel_score}/100. It may reflect editing, recompression, or normal image processing; this prototype cannot identify exactly what changed or calculate the percentage of pixels changed.")
    else:
        st.write(f"**Pixel differences:** No strong anomaly under this prototype's threshold (ELA-style indicator: {pixel_score}/100). This is not proof that the image is unchanged.")

    st.markdown("### Does it contain malicious data?")
    st.error("**UNKNOWN — NOT SCANNED.** The app validates and analyzes selected image properties but does not run antivirus or malware analysis. Do not interpret the alteration score as a malware score.")
    if suspicious_markers:
        st.warning("A limited signature rule matched: " + ", ".join(repr(marker) for marker in suspicious_markers) + ". This is only a rule match; it does not confirm malware.")

    st.markdown("### What to do next")
    if edit_traces or pixel_flag:
        st.warning("Pause before trusting the image. Verify payments, identities, or instructions through an official app or a contact method you already trust.")
    else:
        st.info("No specific warning signs were detected by these checks. Still verify important claims independently.")

    with st.expander("Engineer details"):
        st.code(
            f"Metadata traces left by editing tools: {edit_traces or 'none found in checked fields'} | Pixel anomalies using an ELA-style risk score: {pixel_score}/100 | Malware scan: not implemented | Signature-rule matches: {suspicious_markers or 'none'}",
            language="text",
        )
        st.json({"metadata": metadata, "ela_pixel_indicator": ela, "issues": result.get("issues", []), "sha256": result["sha256"]})

    report = {
        "filename": uploaded.name,
        "sha256": result["sha256"],
        "malware_status": "unknown_not_scanned",
        "ela_pixel_indicator_score_not_probability": pixel_score,
        "editing_metadata_traces": edit_traces,
        "signature_rule_matches_not_malware_verdict": [repr(marker) for marker in suspicious_markers],
        "metadata": metadata,
        "ela": ela,
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

st.markdown('<div class="footer">A warning indicator is not proof of manipulation. No malware scan is performed. Verify important claims using trusted sources.</div>', unsafe_allow_html=True)
