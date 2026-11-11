import os
from typing import Dict, Any

import streamlit as st
from dotenv import load_dotenv

from forensics import analyze_image
from services.azure_db import save_scan_record

load_dotenv()

st.set_page_config(page_title="ImagoSec", page_icon="🛡️", layout="wide")


def render_sidebar() -> None:
    with st.sidebar:
        st.title("ImagoSec")
        st.caption("Secure image forensics gateway")
        st.markdown(
            """
            - File signature validation
            - Metadata forensics
            - ELA pixel tampering analysis
            - Optional Azure SQL logging
            """
        )

        st.subheader("Project status")
        st.success("MVP completed and ready for local testing")

        st.subheader("Configuration")
        db_ready = bool(
            os.getenv("AZURE_SQL_SERVER")
            and os.getenv("AZURE_SQL_DATABASE")
            and os.getenv("AZURE_SQL_USERNAME")
            and os.getenv("AZURE_SQL_PASSWORD")
        )
        st.info("Azure SQL logging: enabled" if db_ready else "Azure SQL logging: skipped (env not configured)")


render_sidebar()

st.title("🛡️ ImagoSec")
st.subheader("Digital image safety and alteration detection")

st.markdown(
    """
    Upload an image to verify:
    - whether the file is suspicious or disguised as another type
    - whether metadata indicates editorial traces or hidden software artifacts
    - whether the pixel structure matches tampering risk patterns using ELA scoring
    """
)

uploaded = st.file_uploader("Upload an image", type=["jpg", "jpeg", "png", "bmp"], help="Supported formats: JPG, JPEG, PNG, BMP")

if uploaded is None:
    st.info("No file uploaded yet. Please choose an image to begin scanning.")
    st.markdown(
        """
        Example workflow:
        1. Upload a suspicious image
        2. Review metadata and findings
        3. Download a sanitized version without embedded metadata
        4. Save the report to Azure SQL when configured
        """
    )
    st.stop()

file_bytes = uploaded.getvalue()

with st.spinner("Running forensic scan..."):
    result = analyze_image(uploaded.name, file_bytes)

st.image(file_bytes, caption=f"Uploaded: {uploaded.name}", use_container_width=True)

risk = int(result["risk_score"])

col1, col2, col3 = st.columns(3)
col1.metric("Risk score", f"{risk}/100")
col2.metric("Hash", result["sha256"][:12] + "...")
col3.metric("Status", "Valid" if result["valid"] else "Rejected")

if risk >= 70:
    st.error("High risk: suspicious image content or visible manipulation indicators were detected.")
elif risk >= 40:
    st.warning("Moderate risk: inspect metadata and the ELA output before trusting the file.")
else:
    st.success("Low risk: no strong tampering indicators were detected.")

st.progress(min(100, max(0, risk)) / 100)

if result["valid"]:
    st.success("File validation passed.")
else:
    st.error(f"Validation failed: {result['issues'][0] if result['issues'] else 'Invalid image upload'}")

st.subheader("Metadata audit")
metadata = result.get("metadata", {})
if metadata.get("error"):
    st.info("No readable metadata was found in this image.")
else:
    st.json(
        {
            "format": metadata.get("format"),
            "size": metadata.get("size"),
            "mode": metadata.get("mode"),
            "software": metadata.get("software"),
            "flags": metadata.get("flags", []),
            "dpi": metadata.get("dpi"),
            "color_mode": metadata.get("color_mode"),
        }
    )

st.subheader("ELA / pixel manipulation analysis")
ela = result.get("ela", {})
st.json(
    {
        "risk_score": ela.get("risk_score"),
        "quality_scores": ela.get("quality_scores", []),
        "message": ela.get("message"),
        "status": ela.get("status"),
    }
)

st.subheader("Findings")
if result["issues"]:
    for item in result["issues"]:
        st.write(f"- {item}")
else:
    st.write("No major findings detected.")

sanitized_bytes = result.get("sanitized_image")
if sanitized_bytes:
    st.subheader("Sanitized output")
    st.image(sanitized_bytes, caption="Metadata-removed sanitized version", use_container_width=True)
    st.download_button(
        label="Download sanitized image",
        data=sanitized_bytes,
        file_name=f"sanitized_{uploaded.name}",
        mime="image/jpeg",
    )

st.subheader("Optional Azure database logging")
extra = result.get("metadata", {})
metadata_flags = ", ".join(extra.get("flags", [])) if isinstance(extra, dict) else ""
ela_report = ela.get("message", "") if isinstance(ela, dict) else ""

if st.button("Save scan result to Azure SQL"):
    db_response = save_scan_record(
        username="guest_user",
        file_hash=result["sha256"],
        threat_level=risk,
        file_name=uploaded.name,
        metadata_flags=metadata_flags,
        ela_report=ela_report,
    )
    if db_response.get("status") == "success":
        st.success(db_response.get("message", "Scan saved successfully."))
    else:
        st.warning(db_response.get("message", "Azure SQL logging is not configured. Set the environment variables to enable it."))

st.caption("ImagoSec is designed for forensic review and citizen safety awareness, not as a legal or forensic guarantee of authenticity.")


path = os.getenv("AZURE_SQL_SERVER")
if path:
    st.sidebar.caption("Azure-ready configuration detected")
else:
    st.sidebar.caption("Local mode: no Azure secrets configured")


# End of file
