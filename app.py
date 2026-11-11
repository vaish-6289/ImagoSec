import io
import json
import os
import sqlite3
import uuid
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv
from PIL import Image, ImageDraw, UnidentifiedImageError

from forensics import analyze_image, detect_suspicious_magic

load_dotenv()
st.set_page_config(page_title="ImagoSec | Image & Scam Scanner", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
      :root { --ink:#e8eef8; --muted:#a9b8cb; --line:#40536a; --accent:#4bd1e5; }
      .stApp { background:#0b1421; color:var(--ink); }
      [data-testid="stHeader"] { background:transparent; }
      .block-container { max-width:1280px; padding-top:1.6rem; padding-bottom:3rem; }
      [data-testid="stSidebar"] { background:#0b1421; border-right:1px solid var(--line); }
      .section-title { color:var(--ink); font-size:1.22rem; font-weight:700; margin:1.3rem 0 .45rem; }
      .muted { color:var(--muted); font-size:.92rem; }
      .card { height:100%; min-height:135px; padding:1rem; border:1px solid var(--line); border-radius:14px; background:rgba(17,29,45,.9); }
      .card h3 { color:var(--ink); font-size:1rem; margin:0 0 .45rem; }
      .card p { color:var(--muted); font-size:.9rem; margin:0; line-height:1.5; }
      div[data-testid="stFileUploader"] section { background:rgba(17,29,45,.8); border:1px dashed #496887; border-radius:15px; }
      .footer { color:#8292a8; font-size:.82rem; text-align:center; padding-top:1.6rem; }
      @media(max-width:700px) { .card {min-height:0;margin-bottom:.5rem;} }
    </style>
    """,
    unsafe_allow_html=True,
)


def make_demo_samples():
    """Create fictional image samples in memory; no repository assets are needed."""
    samples = {}

    image = Image.new("RGB", (900, 520), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 900, 82), fill="#dbeafe")
    draw.text((34, 28), "DEMO SCHOOL - FICTIONAL FEE STATEMENT", fill="#16345c")
    draw.text((45, 130), "Student: Sample Student", fill="#26364a")
    draw.text((45, 195), "Reference: DEMO-2026-001", fill="#26364a")
    draw.text((45, 260), "Tuition fee: $120.00", fill="#26364a")
    draw.text((45, 325), "Status: For demonstration only", fill="#26364a")
    draw.rounded_rectangle((36, 405, 865, 480), radius=12, fill="#fef3c7")
    draw.text((55, 432), "FICTIONAL SAMPLE - NOT A REAL BILL OR PAYMENT REQUEST", fill="#7c5314")
    samples["School bill or receipt"] = image_bytes(image)

    image = Image.new("RGB", (900, 520), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 900, 80), fill="#dbeafe")
    draw.text((35, 25), "DEMO ONLINE MARKETPLACE", fill="#16345c")
    draw.text((55, 130), "Order: SAMPLE-0001", fill="#26364a")
    draw.text((55, 190), "Item: Example product", fill="#26364a")
    draw.text((55, 250), "Amount: $25.00", fill="#26364a")
    draw.text((55, 310), "Payment status: DEMO ONLY", fill="#26364a")
    draw.rounded_rectangle((35, 405, 865, 480), radius=12, fill="#fef3c7")
    draw.text((55, 432), "FICTIONAL PRACTICE IMAGE - NO REAL PAYMENT WAS MADE", fill="#7c5314")
    samples["Online sale payment screen"] = image_bytes(image)

    image = Image.new("RGB", (760, 560), "#e8eef5")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((70, 35, 690, 500), radius=24, fill="white", outline="#cbd5e1", width=3)
    draw.text((105, 75), "DEMO MESSAGE - FICTIONAL", fill="#334155")
    draw.rounded_rectangle((105, 145, 600, 255), radius=18, fill="#e2e8f0")
    draw.text((130, 177), "Please check this sample notice.", fill="#1e293b")
    draw.text((130, 212), "Do not use it as a real instruction.", fill="#1e293b")
    draw.rounded_rectangle((190, 300, 650, 400), radius=18, fill="#bfdbfe")
    draw.text((215, 332), "This is a practice image only.", fill="#1e3a8a")
    draw.text((102, 525), "No real person, payment, or private information is shown.", fill="#475569")
    samples["Text message photo"] = image_bytes(image)
    return samples


def image_bytes(image):
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def save_scan(filename, result, blob_name=None):
    metadata = result.get("metadata", {})
    ela = result.get("ela", {})
    values = (
        result["sha256"], int(result.get("risk_score", 0)), filename,
        json.dumps(metadata.get("flags", [])),
        json.dumps({key: value for key, value in ela.items() if key != "heatmap"}, default=str),
        blob_name,
        json.dumps(result.get("issues", [])),
    )
    mode = os.getenv("IMAGOSEC_DATABASE", "sqlite").lower()
    if mode == "azure_sql":
        connection_string = os.getenv("AZURE_SQL_CONNECTION_STRING")
        if not connection_string:
            raise RuntimeError("Azure SQL is selected, but AZURE_SQL_CONNECTION_STRING is not configured.")
        import pyodbc
        with pyodbc.connect(connection_string) as connection:
            connection.cursor().execute(
                """INSERT INTO dbo.AnalysisLogs
                   (FileHash, ThreatLevel, FileName, MetadataFlags, ELAReport, BlobName, FindingsJson)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""", values,
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
               VALUES (?, ?, ?, ?, ?, ?, ?)""", values,
        )
    return "local SQLite"


def status_label(score):
    if score >= 70:
        return "Danger: suspicious signs found", "danger"
    if score >= 40:
        return "Review: possible warning signs", "warning"
    return "No major warning signs detected", "safe"


with st.sidebar:
    st.title("ImagoSec")
    st.caption("Image & Scam Scanner")
    st.divider()
    st.markdown("### What can I check?")
    st.write("School bills and receipts, online sale screens, and photos shared in text messages.")
    st.caption("A screenshot cannot prove a payment was made. Check your bank or payment app directly.")
    st.divider()
    database_mode = os.getenv("IMAGOSEC_DATABASE", "sqlite").lower()
    st.write(f"Database: **{'Azure SQL' if database_mode == 'azure_sql' else 'SQLite (local demo)'}**")
    st.caption("Azure services are optional and used only when configured.")

st.markdown("# 🛡️ ImagoSec")
st.markdown("### Image safety and scam warning check")

cols = st.columns(4, gap="small")
checks = [
    ("📁 Does it open as a picture?", "Checks that the file is a supported, readable image."),
    ("🏷️ Does it show editing clues?", "Looks for selected software and metadata traces."),
    ("🧩 Do parts look different?", "Compares recompressed pixel patterns. Normal processing can also cause differences."),
    ("🚩 Are there suspicious file signs?", "Looks for selected suspicious file markers. A match is a warning, not proof of a virus."),
]
for col, (title, description) in zip(cols, checks):
    with col:
        st.markdown(f"<div class='card'><h3>{title}</h3><p>{description}</p></div>", unsafe_allow_html=True)

st.markdown('<div class="section-title">Check an image</div>', unsafe_allow_html=True)
st.caption("Choose what to check")
mode = st.radio(
    "Choose what to check",
    ["Upload your own image", "Try a sample image"],
    horizontal=True,
    index=1,
    label_visibility="collapsed",
)

samples = make_demo_samples()
file_bytes = None
filename = None
if mode == "Upload your own image":
    uploaded = st.file_uploader(
        "Upload your own image", type=["jpg", "jpeg", "png", "bmp"],
        max_upload_size=15, label_visibility="collapsed",
    )
    if uploaded is not None:
        file_bytes = uploaded.getvalue()
        filename = uploaded.name
else:
    st.caption("These fictional practice pictures contain no real payment or personal information. Choose one to scan, or download it to try later.")
    download_cols = st.columns(3)
    for col, (sample_name, sample_data) in zip(download_cols, samples.items()):
        with col:
            st.download_button(
                f"⬇️ Download: {sample_name}",
                data=sample_data,
                file_name=sample_name.lower().replace(" ", "-") + ".png",
                mime="image/png",
                use_container_width=True,
            )
    selected_sample = st.selectbox("Choose a sample picture to scan", list(samples.keys()), index=1)
    file_bytes = samples[selected_sample]
    filename = selected_sample.lower().replace(" ", "-") + ".png"

if file_bytes is None:
    st.info("Upload a picture or choose a sample picture to begin.")
else:
    try:
        with Image.open(io.BytesIO(file_bytes)) as check_image:
            check_image.verify()
        readable = True
    except (UnidentifiedImageError, OSError, ValueError):
        readable = False

    if not readable:
        st.error("This file could not be opened as an image. Don’t open it in another program if you do not trust its source.")
        markers = detect_suspicious_magic(file_bytes)
        if markers:
            st.error("Suspicious file marker(s) detected: " + "; ".join(markers) + ". This is an indicator, not a malware verdict.")
        st.stop()

    with st.spinner("Checking image details, pixel patterns, and suspicious file markers…"):
        result = analyze_image(filename, file_bytes)
    metadata = result.get("metadata", {})
    ela = result.get("ela", {})
    markers = detect_suspicious_magic(file_bytes)
    score = int(result.get("risk_score", 0))
    label, level = status_label(score)
    software = metadata.get("software") if isinstance(metadata, dict) else None
    flags = metadata.get("flags", []) if isinstance(metadata, dict) else []
    pixel_score = int(ela.get("risk_score", 0)) if isinstance(ela, dict) else 0
    change_clues = bool(software or flags or pixel_score > 25)

    image_col, result_col = st.columns([1, 1.4], gap="large")
    with image_col:
        st.image(file_bytes, caption=filename, use_container_width=True)
        st.caption(f"SHA-256 file fingerprint: `{result['sha256'][:16]}…`")
    with result_col:
        st.markdown("## Your result")
        if markers:
            st.error("🔴 **Danger: suspicious file signs found.** Don’t open or forward this file. A marker is a warning, not proof of a virus.")
        elif level == "warning" or change_clues:
            st.warning("🟠 **Review: possible warning signs found.** Check the details before trusting this image.")
        else:
            st.success("🟢 **No major warning signs detected by these checks.** This does not prove the image is unchanged or safe.")

        if change_clues:
            st.error("⚠️ **Image changes/alteration clues detected.** These clues can have ordinary causes and are not proof of manipulation.")
        else:
            st.success("✅ **No clear image-change clues detected.** This does not prove the image is unchanged.")
        st.markdown(f"**Pixel comparison:** {('High' if pixel_score > 60 else 'Some' if pixel_score > 25 else 'Low')} pixel differences")
        st.caption("The ELA value is an internal comparison score—not a percentage of the image changed.")

        st.markdown("**Was your image changed or altered?**")
        if software or flags:
            details = ([f"Software recorded: {software}"] if software else [])
            if flags:
                details.append("Metadata fields: " + ", ".join(map(str, flags)))
            st.write("**Editing-related details:** " + "; ".join(details))
        else:
            st.write("**Editing-related details:** None found in the metadata fields checked.")
        st.write("**Pixel comparison:** " + str(ela.get("message", "No pixel comparison available.")))

    if markers:
        st.warning("Suspicious marker matches are limited indicators, not a malware verdict.")
    heatmap = ela.get("heatmap") if isinstance(ela, dict) else None
    if heatmap is not None:
        with st.expander("View pixel-difference map"):
            st.image(heatmap, caption="ELA-style recompression differences; brighter areas are not proof of edits.", use_container_width=True)

    report = {
        "filename": filename,
        "sha256": result["sha256"],
        "risk_score": score,
        "status": label,
        "suspicious_markers": markers,
        "metadata": metadata,
        "ela": {key: value for key, value in ela.items() if key != "heatmap"},
        "issues": result.get("issues", []),
    }
    st.download_button(
        "⬇️ Download scan report",
        data=json.dumps(report, indent=2, default=str),
        file_name=f"imagosec-report-{result['sha256'][:12]}.json",
        mime="application/json",
    )

    scan_key = f"saved_{result['sha256']}"
    if not st.session_state.get(scan_key):
        try:
            saved_to = save_scan(filename, result)
            st.sidebar.success(f"Scan record saved to {saved_to}.")
        except Exception as exc:
            st.sidebar.error(f"Scan analyzed, but history could not be saved: {exc}")
        st.session_state[scan_key] = True

st.markdown('<div class="footer">ImagoSec is a prototype warning tool, not a malware verdict or proof of image authenticity.</div>', unsafe_allow_html=True)
