CREATE TABLE Licensing_Dev.License_Statuses (
    ID INT IDENTITY PRIMARY KEY,
    Name VARCHAR(50) NOT NULL UNIQUE -- e.g., Pending-Training, On-Hold, Completed
);

CREATE TABLE Licensing_Dev.License_Types (
    ID INT IDENTITY PRIMARY KEY,
    Name VARCHAR(50) NOT NULL UNIQUE -- e.g., Microsoft365, MicrosoftCopilot
);

CREATE TABLE Licensing_Dev.License_RequestSources (
    ID INT IDENTITY PRIMARY KEY,
    Name VARCHAR(50) NOT NULL UNIQUE -- e.g., MyIT, VirtualDesktop
);

CREATE TABLE Licensing_Dev.License_RequestActions (
    ID INT IDENTITY PRIMARY KEY,
    Name VARCHAR(50) NOT NULL UNIQUE -- e.g., Upgrade, Downgrade
);

CREATE TABLE Licensing_Dev.License_Requests (
    ID INT IDENTITY PRIMARY KEY,
    -- Foreign Key References (mandatory)
    StatusID INT FOREIGN KEY REFERENCES Licensing_Dev.License_Statuses(ID) NOT NULL,
    -- Required Fields
    UserUPN INT FOREIGN KEY REFERENCES Licensing_Dev.Users(ID) NOT NULL,
    RequestedBy INT FOREIGN KEY REFERENCES Licensing_Dev.Users(ID) NOT NULL,
    LicenseType INT FOREIGN KEY REFERENCES Licensing_Dev.License_Types(ID) NOT NULL,
    Action INT FOREIGN KEY REFERENCES Licensing_Dev.License_RequestActions(ID) NOT NULL,
    RequestSource INT FOREIGN KEY REFERENCES Licensing_Dev.License_RequestSources(ID) NOT NULL,
    RITMNumber VARCHAR(50) NOT NULL,
    TaskNumber VARCHAR(50) NOT NULL,
    -- Optional/Nullable Fields
    RequestedDate DATETIME,
    ProcessedDate DATETIME,
    SaviyntTrackID VARCHAR(100),
    SaviyntTransactionID VARCHAR(100),
    SaviyntExitCode VARCHAR(100),
    SnowTicketNumber VARCHAR(50),
    EmailSentCount INT,
    EmailSentDate DATETIME,
    LAppCase VARCHAR(50),
    LAppCaseCreatedDate DATETIME,
    SOUAgreedDate DATETIME,
    LastUpdatedDate DATETIME DEFAULT GETDATE(),
    UpdatedBy VARCHAR(100),
    CompletionDate DATETIME
);

CREATE OR ALTER VIEW Licensing_Dev.LicenseRequestView AS
SELECT
    lr.ID,
    
    -- Join lookup table values
    ls.Name AS Status,
    u1.UPN AS UserUPN,
    u2.UPN AS RequestedBy,
    lt.Name AS LicenseType,
    la.Name AS Action,
    lrs.Name AS RequestSource,

    -- Direct fields
    lr.RITMNumber,
    lr.TaskNumber,
    lr.RequestedDate,
    lr.ProcessedDate,
    lr.SaviyntTrackID,
    lr.SaviyntTransactionID,
    lr.SaviyntExitCode,
    lr.SnowTicketNumber,
    lr.EmailSentCount,
    lr.EmailSentDate,
    lr.LAppCase,
    lr.LAppCaseCreatedDate,
    lr.SOUAgreedDate,
    lr.LastUpdatedDate,
    lr.UpdatedBy,
    lr.CompletionDate,
    lr.Comments

FROM Licensing_Dev.License_Requests lr
INNER JOIN Licensing_Dev.License_Statuses ls ON lr.StatusID = ls.ID
INNER JOIN Licensing_Dev.License_Types lt ON lr.LicenseType = lt.ID
INNER JOIN Licensing_Dev.License_RequestSources lrs ON lr.RequestSource = lrs.ID
INNER JOIN Licensing_Dev.License_RequestActions la ON lr.Action = la.ID
INNER JOIN Licensing_Dev.Users u1 ON lr.UserUPN = u1.ID
INNER JOIN Licensing_Dev.Users u2 ON lr.RequestedBy = u2.ID;



INSERT INTO Licensing_Dev.License_Statuses (Name)
VALUES ('New'), ('In-Progress'), ('Pending Training'), ('On-Hold'),('Canceled'), ('Expired'), ('Completed');

INSERT INTO Licensing_Dev.License_Types (Name)
VALUES ('Microsoft365'), ('MicrosoftCopilot');

INSERT INTO Licensing_Dev.License_RequestSources (Name)
VALUES ('MyIT'), ('VirtualDesktop');

INSERT INTO Licensing_Dev.License_RequestActions (Name)
VALUES ('Upgrade'), ('Downgrade');
