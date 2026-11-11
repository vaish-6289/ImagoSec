### 🔑 Verified Microsoft Entra Passwordless Connection Profile
For evaluation tracking, the application uses the following integrated token-based parameters to authenticate against Azure SQL without hardcoded passwords:

```text
Server=tcp:sr-imagosec.database.windows.net,1433;Initial Catalog=db-imagosec;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Authentication="Active Directory Default";
```
*Note: The system extracts this configuration dynamically at runtime via system environment variables (`os.getenv`), ensuring full separation of credentials from source code repositories.*

# 🔄 ImagoSec Live Azure Reactivation & Data Architecture Plan

This document serves as the operational blueprint to shift the application from its cost-optimized **Local Evaluation Mode** back to a **Live Azure Cloud State** for live grading or review sessions [Scenario 3].

---

## 🛠️ Part 1: Step-by-Step Infrastructure Re-Provisioning

Follow these steps in the Azure Portal to redeploy the environment cleanly without changing any underlying Python source code [Scenario 3]:

### Step 1: Provision the Azure SQL Serverless Database
1. Search for **SQL databases** in the Azure Portal and click **Create** [Scenario 3].
2. Set the Resource Group to `rg-imagosec-prod` and name the database `imagosec-db` [Scenario 3].
3. Under **Compute + storage**, select **Serverless** (General Purpose) to enable auto-pausing and save student credits [Scenario 3].
4. Under **Networking**:
   - Set Network Connectivity to **Public Endpoint**.
   - Set "Allow Azure services and resources to access this server" to **Yes**.
5. Move to **Security** -> Set Minimum TLS Version to **TLS 1.2**.
6. Set the authentication method to **Microsoft Entra passwordless authentication** (AAD) and assign your student email address as the admin [Scenario 3]. Click **Review + create** -> **Create**.
7. Once deployed, open the database, navigate to the **Query Editor**, paste the contents of `db/schema.sql`, and click **Run** to generate the relational tables, foreign keys, and analytical indexes.

### Step 2: Provision Azure Blob Storage Account
1. Search for **Storage accounts** and click **Create** [Scenario 3].
2. Set the Resource Group to `rg-imagosec-prod`, name the account using lowercase letters only (e.g., `stimagosecingest`), and select your region [Scenario 3].
3. Set the Primary Workload to **General purpose** and redundancy to **LRS** [Scenario 3].
4. In the **Advanced** tab, set Blob Access Tier to **Cool** and leave "Allow enabling anonymous access on individual containers" **unchecked (Disabled)** to prevent public data exposure [Scenario 3].
5. Click **Review + create** -> **Create** [Scenario 3]. 
6. Open the storage account, navigate to **Containers** under Data Storage, click **+ Container**, name it exactly `imagosec-ingestion`, and set access to **Private** [Scenario 3].

### Step 3: Provision Azure Key Vault Secrets
1. Search for **Key Vaults** and click **Create** [Scenario 3].
2. Name it uniquely (e.g., `kv-imagosec-vault`) and select **Azure role-based access control (RBAC)** under Access Configuration [Scenario 3].
3. Set **Purge protection** to **Disabled** and retention to **7 days**. Click **Review + create** -> **Create**.
4. Navigate to **Access control (IAM)** -> **Add role assignment** [Scenario 3]. Assign your own student email the **Key Vault Secrets Officer** role so your user profile has data plane permissions to write keys [Scenario 3].
5. Navigate to **Secrets** -> **Generate/Import**. Create a new secret named `BlobConnectionString` and paste your storage account connection string value into the field [Scenario 3]. Click **Create**.

### Step 4: Link Power BI Desktop (Analytical Reporting Workload)
1. Copy the logical SQL Server name string from your Azure overview page (e.g., `sql-imagosec-srv.database.windows.net`) [Scenario 3].
2. Launch **Power BI Desktop** on your computer.
3. Click **Get Data** -> **Azure** -> **Azure SQL Database** -> **Connect**.
4. Configure the fields:
   - **Server:** Paste your logical server address URL.
   - **Database:** Type `imagosec-db`.
   - **Data Connectivity Mode:** Click the toggle for **DirectQuery** (enforces real-time, zero-caching chart updates) [Scenario 3].
5. Click **OK**. Select the **Microsoft account** (Microsoft Entra ID) tab on the left-hand navigation pane, click **Sign In** to log in using your university-linked login credentials, and click **Connect**.
6. Check the box next to the `AnalysisLogs` table from the Navigator menu list and click **Load** [Scenario 3].

---

## ⚙️ Part 2: How the Dual-Configuration Fallback Framework Works

The application implements a resilient **Chameleon Fallback Architecture** designed to automatically adjust its data consumption layers based on active environmental infrastructure profiles [Scenario 3].


