# ImagoSec

ImagoSec is a Streamlit image-forensics prototype. It checks uploaded image files, extracts metadata, calculates an ELA-style heuristic score, and stores scan history. The ELA score is an indicator only—not proof that an image is authentic or manipulated.

## Current implementation

- Streamlit upload and result UI
- Plain-language results with green, orange, and red safety alerts
- Fictional downloadable practice images that can be scanned in the app
- Easy-read printable HTML scan reports, alongside the technical JSON report
- Python/Pillow/NumPy forensic analysis (`forensics.py`)
- Optional local ClamAV scan for known malware signatures
- Local SQLite scan-history mode by default
- Optional Azure SQL scan-history mode
- Optional private Azure Blob upload
- Optional Azure Key Vault secrets via `DefaultAzureCredential`
- Azure SQL schema and upgrade script: `db/schema.sql`

Authentication/user accounts, Power BI dashboards, and AI-based manipulation detection are not implemented yet.

## Run locally (no Azure resources needed)

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

The default database is SQLite and creates `local_evaluation_ledger.db` in the project directory. To change the path, set `SQLITE_PATH`. To keep the database file out of Git, it is included in `.gitignore`.

## Enable ClamAV malware scanning

ClamAV is optional. When `clamscan` is installed and its signature database is current, ImagoSec scans each selected image's bytes locally via standard input, without writing the upload to disk. On Ubuntu/Debian, install and update ClamAV in the same environment that runs Streamlit:

```bash
sudo apt-get update
sudo apt-get install -y clamav
sudo freshclam
```

Restart Streamlit after installation. The app reports a detected signature, no known signature found, or a scan error/unavailable state; it never treats a missing scanner or failed scan as clean. A clean signature scan is not proof that a file is safe. ClamAV is not included in the Python requirements because it is an operating-system program, and the hosting environment must install it separately.

The sample selector also includes a harmless EICAR antivirus test pattern to verify that ClamAV can detect a known test signature. It is not malware and is not an image; the test sample is not offered as a download.

## Configure Azure for an integration demo

1. Create an Azure SQL Database, a Storage Account with a **private** container, and (optionally) a Key Vault.
2. Apply `db/schema.sql` to the Azure SQL database. The application does not create or alter Azure tables at runtime.
3. Set `IMAGOSEC_DATABASE=azure_sql` and configure the Azure SQL connection string using either `AZURE_SQL_CONNECTION_STRING` or the Key Vault secret named by `AZURE_SQL_SECRET_NAME` (default: `imagosec-sql-connection-string`).
4. Configure Blob Storage using one of these approaches:
   - Preferred on Azure: set `AZURE_STORAGE_ACCOUNT_URL` and grant the app identity **Storage Blob Data Contributor** on the storage account/container.
   - For local integration testing: store a storage connection string in Key Vault under `AZURE_STORAGE_SECRET_NAME` (default: `imagosec-storage-connection-string`), or temporarily use `AZURE_STORAGE_CONNECTION_STRING` in an untracked local `.env`.
5. Set `AZURE_STORAGE_CONTAINER` to the private container name (default: `imagosec-ingestion`). The container must exist before running the app.
6. Run the app and upload a harmless test image. Verify its blob in the private container and the corresponding row in `dbo.AnalysisLogs`.

Copy `.env.example` to `.env` for local configuration. `.env` is ignored by Git; **never commit passwords, access keys, connection strings, uploaded images, or real secrets**. `DefaultAzureCredential` uses a developer identity when signed in locally and a managed identity when deployed on a supported Azure host. A GitHub Codespace does not automatically have an Azure managed identity: sign in with an authorized developer identity and grant it the minimum required Azure roles.

For SQL, the connection string must include a working SQL Server ODBC driver in the environment. The `pyodbc` Python package alone does not install Microsoft's operating-system ODBC driver. For a production deployment, prefer Microsoft Entra authentication/managed identity rather than a SQL username and password. Grant the identity only the required database permissions.

## Pausing resources for evaluation

After verifying Azure mode, you can switch back to `IMAGOSEC_DATABASE=sqlite` for local demos and pause/delete cloud resources if your evaluation policy allows. Keep the code, `.env.example`, schema, and setup instructions in the repository. Before a final review that asks for live Azure verification, reactivate the resources, confirm networking/roles/secrets, apply the schema if needed, and repeat the upload-and-query check. Azure resource deletion can remove data and may require recreating resources; retain only non-sensitive setup notes and backups you are permitted to keep.
