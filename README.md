# ImagoSec

ImagoSec is a secure web gateway that instantly exposes photo alterations and neutralizes hidden malicious code through pixel and metadata analysis.

## Project overview

ImagoSec is a digital image forensic prototype designed to detect:
- altered or manipulated image content
- suspicious hidden payload markers and disguised executable files
- metadata traces left by editing tools
- pixel anomalies using an ELA-style risk score

This version adds the features that were still missing from the initial prototype: a cleaner Streamlit workflow, sanitized output generation, Azure SQL logging support, easy environment configuration, and complete local/production deployment guidance.

## Current implementation status

The repository now includes:
- secure image upload interface
- file validation and header scan
- metadata forensic audit
- ELA-style manipulation analysis
- sanitized image export without embedded metadata
- optional Azure SQL logging for scan records
- environment-based configuration for Azure deployment

## Tech stack

- Frontend: Streamlit
- Backend: Python 3.x
- Imaging: Pillow, NumPy
- Azure SQL: pyodbc + Azure SQL Database
- Azure integration: Azure Key Vault, Azure Blob Storage, Azure App Service

## Local setup

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

2. Start the app:

```bash
streamlit run app.py
```

3. Open the local URL shown by Streamlit, usually:

```text
http://localhost:8501
```

## Environment configuration

Create a `.env` file in the project root using the example values below:

```env
AZURE_SQL_SERVER=your-server.database.windows.net
AZURE_SQL_DATABASE=imagosecdb
AZURE_SQL_USERNAME=sqladminuser
AZURE_SQL_PASSWORD=your-strong-password
```

The project will work in local mode without Azure SQL variables. If those values are present, the app can log scan records automatically to Azure SQL.

## Project structure

```text
ImagoSec/
├── app.py
├── forensics.py
├── requirements.txt
├── .env.example
├── .gitignore
├── db/
│   └── schema.sql
├── services/
│   ├── __init__.py
│   └── azure_db.py
└── README.md
```

## Features in the completed MVP

### 1. Payload sanitization checks
- validates the image extension
- checks suspicious file signatures such as PE and ELF headers
- rejects disguised executable payloads masquerading as image files
- verifies the file can actually be opened by Pillow

### 2. Metadata forensic auditing
- extracts image metadata and EXIF information
- highlights software traces like Photoshop or other editing tools
- surfaces suspicious metadata context such as software names, dates, or device-related flags

### 3. Error Level Analysis (ELA)
- recompresses the image at multiple quality levels
- compares pixel differences to estimate manipulation risk
- returns a risk score, diagnostic message, and quality comparison values

### 4. Sanitized output generation
- removes embedded metadata from the image before download
- creates a cleaned JPEG version for safer sharing or archival use

### 5. Azure SQL logging
- logs uploaded image hash, file name, threat score, metadata flags, and ELA result
- uses SQL transactions for clean record creation
- gracefully skips logging if Azure settings are not configured

## Azure design notes

### RDBMS usage
The application is designed around an Azure SQL database with a `Users` table and an `AnalysisLogs` table connected by a one-to-many foreign key relationship.

### Cloud security
Secrets should be stored in Azure Key Vault or environment variables configured by the deployment platform. Do not hard-code credentials in the repository.

### DP-900 alignment
The upload workflow can be extended to Azure Blob Storage for ingestion, and Azure SQL stores the transactional scan history used in dashboards and BI reporting tools such as Power BI.

## Deployment flow: frontend to backend and hosting

### Option 1: Streamlit Community Cloud
1. Push the repository to GitHub
2. Open Streamlit Community Cloud
3. Connect the repo and choose the main branch
4. Add environment variables in the deployment settings
5. Deploy the app

This is the simplest frontend deployment for a Streamlit UI.

### Option 2: Azure App Service
1. Create an Azure App Service for a Python app
2. Configure the app to run `streamlit run app.py`
3. Add environment variables for Azure SQL and any supporting services
4. Enable managed identity or Key Vault integration for credentials
5. Configure startup/health checks and firewall restrictions

This is the better production option if you want the app to be hosted like a real service.

### Backend responsibilities
The backend logic in this project includes:
- validation and scanning of uploaded images
- ELA and metadata risk analysis
- optional database storage using Azure SQL
- handling of sanitized output generation and audit logging

### Production guidance
- Store secrets in Azure Key Vault, not in `.env` files in public repos
- Restrict database access to trusted networks or private endpoints
- Validate upload size to prevent resource exhaustion
- Add user authentication before exposing the project publicly
- Add audit logs and monitoring for production use

## SQL schema

The database schema is available in `db/schema.sql` and supports the required `Users` and `AnalysisLogs` tables.

## Future enhancements
- AI-driven tampering detection and stronger ELA visualization
- user authentication and role-based access control
- dashboarding using Power BI or Azure Data Explorer
- Azure Blob Storage upload pipeline and secure retention policies

## License
This project is for academic and demonstration purposes.
