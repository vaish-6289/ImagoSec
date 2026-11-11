-- Create the Users table for a future authenticated version of ImagoSec.
IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Users (
        UserID INT IDENTITY(1,1) PRIMARY KEY,
        Username NVARCHAR(100) NOT NULL,
        Email NVARCHAR(200) NOT NULL UNIQUE,
        CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
    );
END;
GO

-- UserID is nullable until authentication is implemented. Scan history is still
-- persisted for the current anonymous/demo workflow.
IF OBJECT_ID(N'dbo.AnalysisLogs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.AnalysisLogs (
        LogID BIGINT IDENTITY(1,1) PRIMARY KEY,
        UserID INT NULL,
        FileHash NVARCHAR(64) NOT NULL,
        ThreatLevel INT NOT NULL,
        FileName NVARCHAR(255) NOT NULL,
        MetadataFlags NVARCHAR(MAX) NULL,
        ELAReport NVARCHAR(MAX) NULL,
        BlobName NVARCHAR(512) NULL,
        FindingsJson NVARCHAR(MAX) NULL,
        ScanDate DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        CONSTRAINT FK_AnalysisLogs_Users
            FOREIGN KEY (UserID) REFERENCES dbo.Users(UserID)
    );
END;
GO

-- Upgrade the earlier prototype schema when it already exists.
IF COL_LENGTH('dbo.AnalysisLogs', 'BlobName') IS NULL
    ALTER TABLE dbo.AnalysisLogs ADD BlobName NVARCHAR(512) NULL;
GO
IF COL_LENGTH('dbo.AnalysisLogs', 'FindingsJson') IS NULL
    ALTER TABLE dbo.AnalysisLogs ADD FindingsJson NVARCHAR(MAX) NULL;
GO
IF COL_LENGTH('dbo.AnalysisLogs', 'UserID') IS NOT NULL
    ALTER TABLE dbo.AnalysisLogs ALTER COLUMN UserID INT NULL;
GO
IF COL_LENGTH('dbo.AnalysisLogs', 'MetadataFlags') IS NOT NULL
    ALTER TABLE dbo.AnalysisLogs ALTER COLUMN MetadataFlags NVARCHAR(MAX) NULL;
GO
IF COL_LENGTH('dbo.AnalysisLogs', 'ELAReport') IS NOT NULL
    ALTER TABLE dbo.AnalysisLogs ALTER COLUMN ELAReport NVARCHAR(MAX) NULL;
GO
