import io

import streamlit as st
from PIL import Image

from forensics import analyze_image

st.set_page_config(page_title="ImagoSec", page_icon="🛡️", layout="wide")

st.title("ImagoSec")
st.subheader("Secure Image Forensics Gateway")

st.markdown(
    """
    This prototype checks:
    - suspicious file signatures
    - hidden metadata and editing traces
    - pixel-level manipulation indicators
    """
)

uploaded = st.file_uploader("Upload an image", type=["jpg", "jpeg", "png", "bmp"])

if uploaded is not None:
    file_bytes = uploaded.getvalue()

    st.image(file_bytes, caption=f"Uploaded: {uploaded.name}", use_container_width=True)

    with st.spinner("Running forensic scan..."):
        result = analyze_image(uploaded.name, file_bytes)

    risk = result["risk_score"]
    st.metric("Threat Risk Score", f"{risk}/100")

    if risk >= 70:
        st.error("High risk: image appears manipulated or suspicious.")
    elif risk >= 40:
        st.warning("Moderate risk: review metadata and pixel differences.")
    else:
        st.success("Low risk: no obvious tampering signals detected.")

    st.progress(risk / 100)
    st.code(f"SHA-256: {result['sha256']}")

    if result["valid"]:
        st.success("File validation passed.")
    else:
        st.error("File validation failed.")

    st.subheader("Metadata Audit")
    metadata = result["metadata"]
    if "error" in metadata:
        st.info("No readable metadata found.")
    else:
        st.json(
            {
                "format": metadata.get("format"),
                "size": metadata.get("size"),
                "mode": metadata.get("mode"),
                "software": metadata.get("software"),
                "flags": metadata.get("flags", []),
            }
        )

    st.subheader("ELA / Pixel Manipulation Analysis")
    ela = result["ela"]
    st.json(
        {
            "risk_score": ela["risk_score"],
            "quality_scores": ela["quality_scores"],
            "message": ela["message"],
        }
    )

    st.subheader("Findings")
    if result["issues"]:
        for item in result["issues"]:
            st.write(f"- {item}")
    else:
        st.write("No major findings detected.")
