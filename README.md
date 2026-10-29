# ImagoSec

ImagoSec is a secure web gateway that instantly exposes photo alterations and neutralizes hidden malicious code through pixel and metadata analysis.

## Project overview

ImagoSec is a digital image forensic prototype designed to detect:
- altered or manipulated image content
- suspicious hidden payload markers and disguised executable files
- metadata traces left by editing tools
- pixel anomalies using an ELA-style risk score

The system is built as an MVP using Streamlit and Python, with a modular design that can later integrate with Azure Blob Storage, Azure SQL Database, and Azure Key Vault.

## Current status

This repository currently contains a working local prototype for:
- secure image upload interface
- file validation and header scan
- metadata forensic audit
- ELA-style manipulation analysis
- database schema planning for Azure SQL

## Tech stack

- Frontend: Streamlit
- Backend: Python 3.x
- Imaging: Pillow, NumPy
- Database: Azure SQL Database (planned)
- Cloud services: Azure Blob Storage, Azure Key Vault, Power BI (planned)

## Local setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Project structure

```text
ImagoSec/
├── app.py
├── forensics.py
├── requirements.txt
├── .gitignore
├── db/
│   └── schema.sql
└── README.md
```

## Features in this prototype

### 1. Payload sanitization checks
- validates image extension
- checks suspicious file signatures such as PE or ELF headers
- blocks disguised executable payloads masquerading as image files

### 2. Metadata forensic auditing
- extracts image metadata
- highlights software traces such as Photoshop or other editing tools
- flags suspicious metadata signatures

### 3. Error Level Analysis (ELA) style detection
- recompresses the uploaded image at different qualities
- compares pixel differences to estimate manipulation risk
- provides a risk score and summary message

## Azure design notes

### RDBMS usage
The app is designed to store user and scan history data in Azure SQL Database using a Users table and an AnalysisLogs table with a one-to-many relationship.

### Cloud security
Sensitive settings and secrets can be stored in Azure Key Vault and accessed at runtime.

### DP-900 alignment
The upload workflow can be extended to Azure Blob Storage for ingestion, while Azure SQL maintains transactional scan history used by reporting tools like Power BI.

## Future enhancements
- AI-based image tampering detection
- stronger ELA heatmap visualization
- user authentication and dashboard
- cloud deployment using Azure services

## License
This project is for academic and demonstration purposes.
