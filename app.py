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
st.set_page_config(page_title="ImagoSec", page_icon="🛡️", layout="wide")


def azure_credential():
    """Use developer sign-in locally and managed identity when hosted on Azure."""
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential()


def get_secret(secret_name):
    """Read an optional secret from Key Vault; return None if Key Vault is unused."""
    vault_url = os.getenv("AZURE_KEY_VAULT_URL")
    if not vault_url:
        return None

    from azure.keyvault.secrets import SecretClient

    client = SecretClient(vault_url=vault_url, credential=azure_credential())
    return client.get_secret(secret_name).value


def get_sql_connection_string():
    # Key Vault takes precedence; environment variables support local demos.
    secret_name = os.getenv(
        "AZURE_SQL_SECRET_NAME", "imagosec-sql-connection-string"
    )
    return get_secret(secret_name) or os.getenv("AZURE_SQL_CONNECTION_STRING")


def get_blob_service_client():
    """Return a Blob client using a Key Vault connection string or managed identity."""
    connection_secret = os.getenv(
        "AZURE_STORAGE_SECRET_NAME", "imagosec-storage-connection-string"
    )
    connection_string = get_secret(connection_secret)
    if not connection_string:
        connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

    from azure.storage.blob import BlobServiceClient

    if connection_string:
        return BlobServiceClient.from_connection_string(connection_string)

    account_url = os.getenv("AZURE_STORAGE_ACCOUNT_URL")
    if account_url:
        return BlobServiceClient(account_url, credential=azure_credential())
    return None


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
            file_bytes,
            overwrite=False,
            metadata={"sha256": file_hash},
        )
        return blob_name
    except Exception as exc:
        st.sidebar.warning(f"Blob upload failed; scan can still be saved: {exc}")
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
                "Set AZURE_SQL_CONNECTION_STRING or configure Key Vault."
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


st.title("🛡️ ImagoSec | Secure Image Forensics Gateway")
st.markdown(
    "Upload an image to check its file validity, metadata, and ELA-style pixel indicators. "
    "The ELA score is a heuristic, not proof that an image was manipulated."
)

with st.sidebar:
    st.header("Configuration")
    st.caption(
        "SQLite is the default for local demos. Azure SQL and private Blob Storage "
        "are used only when configured."
    )
    st.write(f"Database: `{os.getenv('IMAGOSEC_DATABASE', 'sqlite')}`")

uploaded = st.file_uploader(
    "Upload an image", type=["jpg", "jpeg", "png", "bmp"]
)

if uploaded is not None:
    file_bytes = uploaded.getvalue()
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            image.verify()
    except (UnidentifiedImageError, OSError, ValueError):
        st.error("Invalid or corrupted image. Please upload a readable JPG, PNG, or BMP file.")
        st.stop()

    with Image.open(io.BytesIO(file_bytes)) as image:
        st.image(
            image.copy(),
            caption=f"Uploaded: {uploaded.name}",
            width=400,
        )

    with st.spinner("Running forensic scan..."):
        result = analyze_image(uploaded.name, file_bytes)

    st.metric("Threat Risk Score", f"{result['risk_score']}/100")
    risk = result["risk_score"]
    if risk >= 70:
        st.error("High risk indicators found. Review the findings carefully.")
    elif risk >= 40:
        st.warning("Moderate risk indicators found. Review the findings carefully.")
    else:
        st.success("Low risk indicators found; this is not a guarantee of authenticity.")

    st.progress(risk / 100)
    st.code(f"SHA-256: {result['sha256']}")
    st.subheader("Metadata Audit")
    st.json(result["metadata"])
    st.subheader("ELA / Pixel Manipulation Analysis")
    st.json(result["ela"])
    st.subheader("Findings")
    if result["issues"]:
        for finding in result["issues"]:
            st.write(f"- {finding}")
    else:
        st.write("No major findings detected by this prototype.")

    # Persist only after the scan is complete. Blob storage is optional.
    blob_name = upload_to_blob(file_bytes, uploaded.name, result["sha256"])
    try:
        database_name = save_scan(uploaded.name, result, blob_name)
        st.sidebar.success(f"Scan history saved to {database_name}.")
    except Exception as exc:
        st.sidebar.error(f"Could not save scan history: {exc}")
PY