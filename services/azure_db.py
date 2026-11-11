from __future__ import annotations

import os
from typing import Any, Dict, Optional

import pyodbc
from dotenv import load_dotenv

load_dotenv()


def get_sql_connection():
    server = os.getenv("AZURE_SQL_SERVER")
    database = os.getenv("AZURE_SQL_DATABASE")
    username = os.getenv("AZURE_SQL_USERNAME")
    password = os.getenv("AZURE_SQL_PASSWORD")

    if not all([server, database, username, password]):
        return None

    connection_string = (
        "DRIVER={ODBC Driver 18 for SQL Server};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        "Encrypt=yes;"
        "TrustServerCertificate=no;"
        "Connection Timeout=30;"
    )

    try:
        return pyodbc.connect(connection_string)
    except Exception:
        return None


def save_scan_record(
    username: str,
    file_hash: str,
    threat_level: int,
    file_name: str,
    metadata_flags: str = "",
    ela_report: str = "",
) -> Dict[str, Any]:
    connection = get_sql_connection()
    if connection is None:
        return {
            "status": "skipped",
            "message": "Azure SQL not configured. Set AZURE_SQL_SERVER, AZURE_SQL_DATABASE, AZURE_SQL_USERNAME, and AZURE_SQL_PASSWORD to enable database logging.",
        }

    try:
        with connection:
            cursor = connection.cursor()

            cursor.execute(
                "SELECT UserID FROM Users WHERE Username = ?",
                (username,),
            )
            row = cursor.fetchone()

            if row is None:
                cursor.execute(
                    "INSERT INTO Users (Username, Email) VALUES (?, ?)",
                    (username, f"{username}@imagosec.local"),
                )
                connection.commit()
                cursor.execute(
                    "SELECT UserID FROM Users WHERE Username = ?",
                    (username,),
                )
                row = cursor.fetchone()

            user_id = row[0]
            cursor.execute(
                "INSERT INTO AnalysisLogs (UserID, FileHash, ThreatLevel, FileName, MetadataFlags, ELAReport) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, file_hash, threat_level, file_name, metadata_flags, ela_report),
            )
            connection.commit()

        return {
            "status": "success",
            "message": "Scan record saved to Azure SQL successfully.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to save scan record: {str(exc)}",
        }
    finally:
        connection.close()


# End of file
