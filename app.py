import os
import sqlite3

import streamlit as st
from dotenv import load_dotenv

from forensics import analyze_image

# Load environment variables from a local .env file when present.
load_dotenv()


def init_sqlite_db(conn):
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL,
            Email TEXT NOT NULL UNIQUE,
            CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS AnalysisLogs (
            LogID INTEGER PRIMARY KEY AUTOINCREMENT,
            UserID INTEGER NOT NULL,
            FileHash TEXT NOT NULL,
            ThreatLevel INTEGER NOT NULL,
            FileName TEXT NOT NULL,
            MetadataFlags TEXT,
            ELAReport TEXT,
            ScanDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (UserID) REFERENCES Users(UserID)
        );
        """
    )
    cur.execute("SELECT COUNT(*) FROM Users;")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO Users (Username, Email) VALUES (?, ?);",
            ("EvaluatorUser", "evaluator@university.edu"),
        )
    conn.commit()


def get_db_connection():
    azure_conn = os.getenv("AZURE_SQL_CONNECTION_STRING")

    if azure_conn:
        try:
            import pyodbc

            conn = pyodbc.connect(azure_conn)
            cur = conn.cursor()
            cur.execute(
                """
                IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
                BEGIN
                    CREATE TABLE dbo.Users (
                        UserID INT IDENTITY(1,1) PRIMARY KEY,
                        Username NVARCHAR(100) NOT NULL,
                        Email NVARCHAR(200) NOT NULL UNIQUE,
                        CreatedAt DATETIME2 DEFAULT GETDATE()
                    );
                END
                """
            )
            cur.execute(
                """
                IF OBJECT_ID(N'dbo.AnalysisLogs', N'U') IS NULL
                BEGIN
                    CREATE TABLE dbo.AnalysisLogs (
                        LogID INT IDENTITY(1,1) PRIMARY KEY,
                        UserID INT NOT NULL,
                        FileHash NVARCHAR(128) NOT NULL,
                        ThreatLevel INT NOT NULL,
                        FileName NVARCHAR(255) NOT NULL,
                        MetadataFlags NVARCHAR(500) NULL,
                        ELAReport NVARCHAR(500) NULL,
                        ScanDate DATETIME2 DEFAULT GETDATE(),
                        CONSTRAINT FK_AnalysisLogs_Users FOREIGN KEY (UserID) REFERENCES dbo.Users(UserID)
                    );
                END
                """
            )
            conn.commit()
            return conn, "azure"
        except Exception as exc:
            st.sidebar.warning(f"Azure SQL unavailable: {exc}. Falling back to local SQLite mode.")

    sqlite_path = os.getenv("LOCAL_SQLITE_PATH", "local_evaluation_ledger.db")
    conn = sqlite3.connect(sqlite_path)
    init_sqlite_db(conn)
    return conn, "local"


def ensure_user_id(conn, mode):
    if mode == "azure":
        cur = conn.cursor()
        cur.execute("SELECT TOP 1 UserID FROM dbo.Users ORDER BY UserID;")
        row = cur.fetchone()
        if row is None:
            cur.execute(
                "INSERT INTO dbo.Users (Username, Email) VALUES (?, ?);",
                ("EvaluatorUser", "evaluator@university.edu"),
            )
            conn.commit()
            cur.execute("SELECT TOP 1 UserID FROM dbo.Users ORDER BY UserID DESC;")
            row = cur.fetchone()
        return int(row[0])

    cur = conn.cursor()
    cur.execute("SELECT UserID FROM Users ORDER BY UserID LIMIT 1;")
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO Users (Username, Email) VALUES (?, ?);",
            ("EvaluatorUser", "evaluator@university.edu"),
        )
        conn.commit()
        cur.execute("SELECT UserID FROM Users ORDER BY UserID DESC LIMIT 1;")
        row = cur.fetchone()
    return int(row[0])


def log_scan(conn, mode, result, filename):
    user_id = ensure_user_id(conn, mode)
    if mode == "azure":
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO dbo.AnalysisLogs (UserID, FileHash, ThreatLevel, FileName, MetadataFlags, ELAReport)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                user_id,
                result["sha256"],
                int(result["risk_score"]),
                filename,
                str(result.get("issues", [])),
                str(result.get("ela", {})),
            ),
        )
        conn.commit()
        return

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO AnalysisLogs (UserID, FileHash, ThreatLevel, FileName, MetadataFlags, ELAReport)
        VALUES (?, ?, ?, ?, ?, ?);
        """,
        (
            user_id,
            result["sha256"],
            int(result["risk_score"]),
            filename,
            str(result.get("issues", [])),
            str(result.get("ela", {})),
        ),
    )
    conn.commit()


def upload_blob_if_configured(filename, file_bytes):
    blob_conn = os.getenv("AZURE_BLOB_CONNECTION_STRING")
    if not blob_conn:
        return
    try:
        from azure.storage.blob import BlobServiceClient

        client = BlobServiceClient.from_connection_string(blob_conn)
        container_name = os.getenv("AZURE_BLOB_CONTAINER", "imagosec-ingestion")
        container = client.get_container_client(container_name)
        container.upload_blob(name=filename, data=file_bytes, overwrite=True)
        st.sidebar.success("Azure Blob upload complete.")
    except Exception as exc:
        st.sidebar.warning(f"Blob upload skipped: {exc}")


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

conn, db_mode = get_db_connection()
if db_mode == "local":
    st.sidebar.info("Mode: Local SQLite fallback")
else:
    st.sidebar.success("Mode: Azure SQL connected")

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

    try:
        log_scan(conn, db_mode, result, uploaded.name)
        st.sidebar.success("Scan metadata saved to the active configuration layer.")
        upload_blob_if_configured(uploaded.name, file_bytes)
    except Exception as log_err:
        st.sidebar.error(f"Data logging failed: {log_err}")

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
