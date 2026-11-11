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
      .use-card,.check-card { height:100%; min-height:130px; padding:1rem; border:1px solid var(--line);
        border-radius:14px; background:rgba(17,29,45,.9); }
      .use-card h3,.check-card h3 { color:var(--ink); font-size:1rem; margin:0 0 .45rem; }
      .use-card p,.check-card p { color:var(--muted); font-size:.9rem; margin:0; line-height:1.5; }
      .tech { color:var(--accent); font-weight:600; }
      .safety-note { border-left:4px solid #f3b84b; background:rgba(243,184,75,.09); border-radius:8px;
        padding:.85rem 1rem; color:#f3e5c4; margin:.8rem 0 1rem; }
      div[data-testid="stMetric"] { background:rgba(17,29,45,.9); border:1px solid var(--line); border-radius:14px; padding:.85rem; }
      div[data-testid="stMetricLabel"] { color:var(--muted); }
      div[data-testid="stMetricValue"] { color:var(--ink); }
      div[data-testid="stFileUploader"] section { background:rgba(17,29,45,.8); border:1px dashed #496887; border-radius:15px; }
      .footer { color:#8292a8; font-size:.82rem; text-align:center; padding-top:1.6rem; }
      @media(max-width:700px) { .hero h1 {font-size:1.7rem;} .use-card,.check-card {min-height:0;margin-bottom:.5rem;} }
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


def risk_band(score):
    if score >= 70:
        return "🔴 Several warning signs", "high"
    if score >= 40:
        return "🟠 Some warning signs", "medium"
    return "🟢 Few warning signs found", "low"


with st.sidebar:
    st.markdown("## 🛡️ ImagoSec")
    st.caption("A friendly image safety check")
    st.divider()
    st.markdown("### How it helps")
    st.markdown("Check a receipt, school notice, marketplace payment screenshot, or image sent in a message for selected warning signs.")
    st.divider()
    mode = os.getenv("IMAGOSEC_DATABASE", "sqlite").lower()
    st.markdown("### Storage mode")
    st.write(f"Database: **{'Azure SQL' if mode == 'azure_sql' else 'SQLite (local demo)'}**")
    st.caption("SQLite lets you demonstrate without active cloud resources. Azure services are used only when configured.")
    st.divider()
    st.markdown("### Remember")
    st.caption("A screenshot is not proof that money was sent. Check your bank or payment app directly.")

st.markdown(
    """<div class="hero"><div class="eyebrow">Cybersecurity for everyday images</div>
    <h1>🛡️ Check the image. Pause before you trust it.</h1>
    <p>Does it contain suspicious file indicators? Was the image possibly changed? Check a receipt, school notice, online-sale screenshot, or photo from a message. ImagoSec shows clues and what to verify next—it cannot prove an image is genuine or detect every kind of malware.</p></div>""",
    unsafe_allow_html=True,
)

st.markdown('<div class="section-title">What can this help you check?</div>', unsafe_allow_html=True)
use_cols = st.columns(3, gap="small")
use_cases = [
    ("🧾 Bills & school payments", "A receipt or fee screenshot looks unusual? Review its file, saved details, and pixel-pattern indicators. Always confirm payments in your bank or school portal."),
    ("🛍️ Buying and selling online", "Someone sends a 'payment complete' screenshot? Check for image warning signs, then confirm the transaction in your own payment account before handing over goods."),
    ("💬 Photos from messages", "A picture or screenshot feels suspicious? ImagoSec can surface selected file and editing clues to help you decide what to verify next."),
]
for column, (title, text) in zip(use_cols, use_cases):
    with column:
        st.markdown(f"<div class='use-card'><h3>{title}</h3><p>{text}</p></div>", unsafe_allow_html=True)

st.markdown('<div class="section-title">What does ImagoSec look for?</div>', unsafe_allow_html=True)
check_cols = st.columns(4, gap="small")
checks = [
    ("1 · Is it a readable image?", "Checks that the file opens as an image and has an allowed type. <span class='tech'>(file validation)</span>"),
    ("2 · What details are saved?", "Looks for format, size, and available editing-software details. <span class='tech'>(metadata / EXIF)</span>"),
    ("3 · Do pixel patterns differ?", "Compares recompressed copies for unusual differences. <span class='tech'>(ELA-style analysis)</span>"),
    ("4 · What does the score mean?", "A score is a clue to review—not proof of editing or safety. <span class='tech'>(heuristic estimate)</span>"),
]
for column, (title, text) in zip(check_cols, checks):
    with column:
        st.markdown(f"<div class='check-card'><h3>{title}</h3><p>{text}</p></div>", unsafe_allow_html=True)

st.markdown('<div class="section-title">Check an image</div>', unsafe_allow_html=True)
st.markdown('<div class="muted">Choose a JPG, PNG, or BMP file (maximum 15 MB).</div>', unsafe_allow_html=True)
uploaded = st.file_uploader("Choose an image", type=["jpg", "jpeg", "png", "bmp"], max_upload_size=15, label_visibility="collapsed")

if uploaded is None:
    st.info("👆 Choose an image to get a simple risk summary and practical next steps.")
else:
    file_bytes = uploaded.getvalue()
    # Analyze first, so suspicious signature markers in an invalid disguised upload
    # can be reported without ever trying to display or execute the file.
    result = analyze_image(uploaded.name, file_bytes)
    signature_matches = detect_suspicious_magic(file_bytes)
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            image.verify()
        image_readable = True
    except (UnidentifiedImageError, OSError, ValueError):
        image_readable = False

    if not image_readable:
        st.error("⛔ This file cannot be opened as an image. It may be damaged, mislabeled, or contain an unsupported format. Do not open it with another program if you do not trust its source.")
        if signature_matches:
            st.error("🚨 A known executable/archive signature marker was found in the initial file bytes: " + ", ".join(repr(x) for x in signature_matches))
            st.metric("Known-signature indicator score", "100%")
            st.caption("This is a match to a small signature list—not a malware probability or a complete antivirus scan.")
        else:
            st.metric("Known-signature indicator score", "0%")
            st.caption("No marker from this prototype's small signature list was found. That does not prove the file is harmless.")
        st.markdown("### Result")
        st.write("**Was the image changed?** Cannot assess: the file could not be decoded as an image.")
        st.write("**Does it contain malicious data?** No malware verdict is available. The prototype only checks a limited set of file-signature markers.")
        st.stop()

    score = int(result.get("risk_score", 0))
    label, band = risk_band(score)
    metadata = result.get("metadata", {})
    ela = result.get("ela", {})
    metadata_flags = metadata.get("flags", []) if isinstance(metadata, dict) else []
    software_found = metadata.get("software") if isinstance(metadata, dict) else None
    pixel_score = int(ela.get("risk_score", 0)) if isinstance(ela, dict) else 0
    has_editing_traces = bool(software_found or metadata_flags)
    alteration_indicator = max(pixel_score, 35 if has_editing_traces else 0)

    preview, summary = st.columns([1, 1.4], gap="large")
    with preview:
        st.markdown('<div class="section-title">Image preview</div>', unsafe_allow_html=True)
        with Image.open(io.BytesIO(file_bytes)) as image:
            st.image(image.copy(), caption=uploaded.name, width=380)
        st.caption(f"{len(file_bytes):,} bytes · File fingerprint (SHA-256): `{result['sha256'][:16]}…`")
    with summary:
        st.markdown('<div class="section-title">Quick safety summary</div>', unsafe_allow_html=True)
        st.metric("Overall warning indicator", f"{score}%")
        st.write(label)
        st.progress(max(0, min(score, 100)) / 100)
        st.markdown('<div class="safety-note"><strong>Important:</strong> Percentages here are prototype indicator scores, not the probability that an image is altered or malware is present.</div>', unsafe_allow_html=True)

    st.markdown("### Results in plain language")
    st.write(f"**Was your image changed or altered?** Alteration indicator score: **{alteration_indicator}%** (based on ELA-style pixel differences and editing-related metadata clues).")
    if has_editing_traces:
        trace_items = []
        if software_found:
            trace_items.append(f"editing software recorded: {software_found}")
        if metadata_flags:
            trace_items.append("metadata fields present: " + ", ".join(str(x) for x in metadata_flags))
        st.write("**What clues were found?** " + "; ".join(trace_items) + f"; ELA-style pixel indicator: {pixel_score}%.")
    elif pixel_score > 30:
        st.write(f"**What clues were found?** Unusual pixel differences were measured (ELA-style indicator: {pixel_score}%). The prototype cannot identify exact altered objects or state what percentage of the image was changed.")
    else:
        st.write(f"**What clues were found?** No specific editing metadata traces or strong ELA-style pixel anomalies were found (pixel indicator: {pixel_score}%). This does not prove the image was unchanged.")

    if signature_matches:
        st.error("**Does this file contain malicious data?** A known suspicious signature marker was detected. This requires caution; it is not a full malware scan.")
        st.metric("Known-signature indicator score", "100%")
        st.write("**Marker(s) found:** " + ", ".join(repr(x) for x in signature_matches))
    else:
        st.success("**Does this file contain malicious data?** No marker from this prototype's limited signature list was found.")
        st.metric("Known-signature indicator score", "0%")
        st.caption("This is not a malware-free verdict; this prototype does not scan all embedded content or execute antivirus checks.")

    if band == "high":
        st.error("🛑 Pause and verify independently. Don't send money, share codes, or hand over goods based only on this image.")
    elif band == "medium":
        st.warning("👀 Take a closer look. Contact the sender using a trusted method, not contact details shown only in the image.")
    else:
        st.info("✅ No major warning signs were detected by these checks. Verify important claims in the official app or with the organization.")

    st.markdown("### Engineer summary")
    st.code(
        f"Metadata traces left by editing tools: {('software=' + str(software_found) if software_found else 'none recorded')}; flags={metadata_flags or 'none'} | Pixel anomalies using an ELA-style risk score: {pixel_score}/100 | Known suspicious signature markers: {signature_matches or 'none detected'}",
        language="text",
    )
    with st.expander("View complete metadata and technical scan details"):
        st.json({"metadata": metadata, "pixel_analysis": ela, "issues": result.get("issues", []), "sha256": result["sha256"]})

    report = {"filename": uploaded.name, "sha256": result["sha256"], "overall_indicator_score": score,
              "alteration_indicator_score_not_probability": alteration_indicator,
              "ela_indicator_score_not_probability": pixel_score,
              "known_signature_matches": [repr(x) for x in signature_matches],
              "issues": result.get("issues", []), "metadata": metadata, "ela": ela}
    st.download_button("⬇️ Download scan report", data=json.dumps(report, indent=2, default=str),
                       file_name=f"imagosec-report-{result['sha256'][:12]}.json", mime="application/json")

    if "saved_scan_hashes" not in st.session_state:
        st.session_state.saved_scan_hashes = set()
    if result["sha256"] not in st.session_state.saved_scan_hashes:
        blob_name = upload_to_blob(file_bytes, uploaded.name, result["sha256"])
        try:
            db_name = save_scan(uploaded.name, result, blob_name)
            st.sidebar.success(f"Scan record saved to {db_name}.")
        except Exception as exc:
            st.sidebar.error(f"Scan was analyzed, but its history could not be saved: {exc}")
        st.session_state.saved_scan_hashes.add(result["sha256"])

st.markdown('<div class="footer">ImagoSec surfaces limited warning indicators to help people pause and verify. Scores are not probabilities, a malware verdict, or proof of image authenticity.</div>', unsafe_allow_html=True)
