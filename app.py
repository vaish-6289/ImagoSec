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


def pixel_difference_label(score):
    if score > 60:
        return "High pixel differences"
    if score > 25:
        return "Some pixel differences"
    return "Low pixel differences"


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
    <p>Check a receipt, school notice, online-sale screenshot, or image from a message for selected warning signs. ImagoSec looks for image-editing clues and suspicious file markers, including some disguised executable or archive signatures.</p></div>""",
    unsafe_allow_html=True,
)

st.markdown('<div class="section-title">What do we check?</div>', unsafe_allow_html=True)
cols = st.columns(4, gap="small")
items = [
    ("📁 Is it a real, readable image?", "Checks that the file opens and has an allowed image type. <b>(file validation)</b>"),
    ("🏷️ What details are saved?", "Looks for editing-software and other image details. <b>(metadata / EXIF)</b>"),
    ("🧩 Do pixel patterns differ?", "Compares recompressed copies for unusual differences. <b>(ELA-style analysis)</b>"),
    ("🚩 Is there a suspicious file marker?", "Checks for selected executable and archive signatures that may be hidden in a file. A match is a warning clue, not proof of malware."),
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
        st.markdown("### File security check")
        if suspicious_markers:
            st.error("🚩 **Suspicious file marker detected.** The file contains a signature associated with an executable or archive: " + ", ".join(repr(marker) for marker in suspicious_markers) + ". Treat it as suspicious; this is not confirmation of malware.")
        else:
            st.warning("**No known marker detected by this check.** This does not rule out hidden or malicious content; only selected signatures are checked.")
        st.write("**Image alteration:** Cannot assess because this file could not be decoded as an image.")
        st.write("**Next step:** Don’t open or forward a suspicious file. Verify it with the sender through a trusted channel and use reputable security software if you need a malware verdict.")
        st.stop()

    with st.spinner("Checking image details, pixel patterns, and suspicious file markers…"):
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
        st.markdown("### Your image check")
        if edit_traces or pixel_flag:
            st.warning("🟠 **Possible image-editing clues found.** Review the details below; clues do not prove what changed.")
        else:
            st.success("🟢 **No specific image-editing clues found by these checks.** This does not prove the image is unchanged.")
        st.markdown(f"**Pixel comparison:** {pixel_difference_label(pixel_score)}")
        st.caption("The ELA value is an internal comparison score—not a percentage of the image changed.")

    st.markdown("### Was your image changed or altered?")
    if edit_traces:
        st.write("**Editing-related details found:** " + "; ".join(edit_traces) + ". These details may be normal and do not prove alteration.")
    else:
        st.write("**Editing-related details:** None found in the metadata fields checked.")
    if pixel_flag:
        st.write(f"**Pixel comparison:** {pixel_difference_label(pixel_score)}. The ELA-style comparison found differences that can come from editing, recompression, or normal image processing; it cannot identify exact edits or calculate how much of the image changed.")
    else:
        st.write(f"**Pixel comparison:** {pixel_difference_label(pixel_score)}. No strong anomaly crossed this prototype's review threshold. This does not prove the image is unchanged.")

    st.markdown("### Suspicious hidden content check")
    if suspicious_markers:
        st.error("🚩 **Suspicious file marker detected:** " + ", ".join(repr(marker) for marker in suspicious_markers) + ". This may indicate executable/archive content or a disguised file. Treat it as suspicious, but a signature match alone does not confirm malware.")
        st.write("**What to do:** Don’t open or forward it. Verify the source and use a trusted security scanner for a malware verdict.")
    else:
        st.success("✅ **No known suspicious marker detected** by ImagoSec’s selected signature checks.")
        st.caption("This is not a clean bill of health: signatures are limited, and no marker match does not rule out hidden or malicious content.")

    if edit_traces or pixel_flag or suspicious_markers:
        st.warning("**Pause and verify.** Don’t rely on this image alone for payments, identity, or important instructions. Check with an official app or a contact method you already trust.")
    else:
        st.info("No specific warning signs were detected by these checks. Verify important claims independently.")

    with st.expander("Engineer details"):
        st.code(
            f"Metadata traces left by editing tools: {edit_traces or 'none found in checked fields'} | Pixel anomalies using an ELA-style risk score: {pixel_score}/100 ({pixel_difference_label(pixel_score)}) | Suspicious executable/archive signature markers: {suspicious_markers or 'none detected'}",
            language="text",
        )
        st.caption("The ELA score is an internal pixel-difference heuristic, not a percent altered or malware probability. Signature checks cover selected markers only.")
        st.json({"metadata": metadata, "ela_pixel_comparison": ela, "suspicious_signature_markers": [repr(marker) for marker in suspicious_markers], "issues": result.get("issues", []), "sha256": result["sha256"]})

    report = {
        "filename": uploaded.name,
        "sha256": result["sha256"],
        "image_editing_clues": edit_traces,
        "pixel_difference_label": pixel_difference_label(pixel_score),
        "ela_internal_score_not_percent_altered": pixel_score,
        "suspicious_signature_markers": [repr(marker) for marker in suspicious_markers],
        "malware_verdict": "not_provided_signature_indicators_only",
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

st.markdown('<div class="footer">ImagoSec checks image-editing clues and selected suspicious file markers. Pixel scores are not percentages of the image changed, and marker matches are indicators—not confirmed malware verdicts.</div>', unsafe_allow_html=True)
