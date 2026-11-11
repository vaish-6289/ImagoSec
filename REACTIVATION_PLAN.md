### 🔑 Verified Microsoft Entra Passwordless Connection Profile
For evaluation tracking, the application uses the following integrated token-based parameters to authenticate against Azure SQL without hardcoded passwords:

```text
Server=tcp:sr-imagosec.database.windows.net,1433;Initial Catalog=db-imagosec;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Authentication="Active Directory Default";
```
*Note: The system extracts this configuration dynamically at runtime via system environment variables (`os.getenv`), ensuring full separation of credentials from source code repositories.*
