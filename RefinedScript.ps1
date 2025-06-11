<#
.SYNOPSIS
    License-Queue-Process
.DESCRIPTION
    Picks message from the database and processes it.
    It can process assignment of Copilot licenses and upgrade/downgrade of E1/E5 licenses.
.NOTES
.COMPONENT
    Requires Modules Az,Graph
.NOTES
    Name                : Vinay Gupta
    Email               : vinay.gupta1@bp.com
    CreatedDate         : 2024/05/03
    Version             : 2.0 (Merged)
    Enhancement Date    : 2025/10/02 (YYYY/MM/DD)
    Enhancements        : Merged Copilot.ps1 and E1-E5.ps1 functionality.
                          Included ST&S entity copilot license allocation.
.WEBHOOKS
    # Need to provide WEBHOOKS
#>

$PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
Write-Output "Using Hybrid Worker: $($env:computername)"

#Start-Transcript -Path 'D:\Temp\CombinedLicenseManagement_logs.txt'

# Define the license pool threshold limit - These might need adjustment or separate handling per license type
$threshold = 30 # General threshold, Copilot.ps1 was 30, E1-E5.ps1 was 30
$ProcessCutoff = 100 # General cutoff, Copilot.ps1 was 1000, E1-E5.ps1 was 100. This will be license type specific in main loop.

$TestMode = $false # Default, will be overridden by AutomationAccountName switch
if ($TestMode) { Write-Output 'TESTMODE ENABLED' }

### START FUNCTION DEFINITIONS ###
Function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG', 'VERBOSE')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [switch]$VerboseLog
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "$timestamp [$Level] : $Message"

    if ($ErrorRecord) {
        $logEntry += " | Exception: $($ErrorRecord.Exception.Message)"
        if ($ErrorRecord.ScriptStackTrace) {
            $logEntry += " | Stack: $($ErrorRecord.ScriptStackTrace)"
        }
    }

    switch ($Level) {
        'ERROR'   { Write-Error $logEntry }
        'WARN'    { Write-Warning $logEntry }
        'DEBUG'   { if ($VerboseLog) { Write-Host $logEntry -ForegroundColor Cyan } }
        'VERBOSE' { if ($VerboseLog) { Write-Verbose $logEntry } }
        Default   { Write-Host $logEntry }
    }
}

Function ScriptError {
    param(
        [Parameter(Mandatory = $true)]
        [string]$msg,
        [Parameter(Mandatory = $false)]
        [string]$UserUPNForError = $userUPN, # Allow overriding UserUPN if needed
        [Parameter(Mandatory = $false)]
        [string]$LicenseTypeForError = $LicenseType,
        [Parameter(Mandatory = $false)]
        [string]$RITMNumberForError = $RITMNumber,
        [Parameter(Mandatory = $false)]
        [string]$RequestedByForError = $RequestedBy,
        [Parameter(Mandatory = $false)]
        [string]$licenseCategorizationIDForError = $licenseCategorizationID,
        [Parameter(Mandatory = $false)]
        [string]$actionForError = $action,
        [Parameter(Mandatory = $false)]
        [string]$RequestedTimeForError = $RequestedTime,
        [Parameter(Mandatory = $false)]
        [string]$ProcessedTimeForError = $ProcessedTime,
        [Parameter(Mandatory = $false)]
        [string]$LAppCaseForError = $LAppCase,
        [Parameter(Mandatory = $false)]
        [hashtable]$saviyntRequestReferenceIDsForError = $saviyntRequestReferenceIDs,
        [Parameter(Mandatory = $false)]
        [string]$SnowTaskTicketNumber # To store SNOW task if created
    )

    $respObj = @{
        UPN   = $UserUPNForError
        Error = $msg
    }
    $response = $respObj | ConvertTo-Json

    Write-Log $msg -Level 'ERROR'
    Write-Log $response -Level 'ERROR'
    Write-Log 'One or more errors occurred, Refer the output screen for details' -Level 'ERROR'

    if($LicenseTypeForError -eq 'MicrosoftCopilot'){
        try{
            Update-TicketStatus -TicketNumber $RITMNumberForError -Stage 'Validation' -State '-5' -WorkNotes "Failed for : $UserUPNForError, Error : $msg"
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log "Failed to update RITM status for Copilot error: $ex" -Level 'ERROR'
        }
    }

    $ShortDesc = 'Failure; Automatic Fulfilment Not Possible - M365 License'
    try{
        # Determine CMDB_CI based on LicenseTypeForError
        $cmdbCiForTask = if ($LicenseTypeForError -eq 'MicrosoftCopilot') { 'M365 Copilot' } else { 'Digital Collaboration Tools' }
        
        $ticket = New-SnowTask -shortDescription $ShortDesc -Description $response -UserUPN $UserUPNForError -cmdb_ci $cmdbCiForTask
        Write-Log "SNOW ticket logged: $ticket" -Level 'ERROR'
        $SnowTaskTicketNumber = $ticket # Store for Dataverse logging
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to create SNOW Task: $ex" -Level 'ERROR'
    }

    # Add Error message to Dataverse
    try {
        $completionTimeError = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
        $bodyContent = @{
            new_requestedby                          = $RequestedByForError
            new_requestedfor                         = $UserUPNForError
            'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationIDForError)"
            new_action                               = $actionForError
            new_requestsource                        = 'DWP-Automation'
            new_requesttime                          = $RequestedTimeForError
            new_processedtime                        = $ProcessedTimeForError
            new_completiontime                       = $completionTimeError
            new_lappcasenumber                       = $LAppCaseForError
            new_saviynttrackingid                    = $saviyntRequestReferenceIDsForError.trackingID
            new_status                               = "Error" 
            new_saviynttransactionid                 = $saviyntRequestReferenceIDsForError.APITransactionID
            new_errorcode                            = $msg
            new_snowtasknumber                       = $SnowTaskTicketNumber # Added this field
        } | ConvertTo-Json

        $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent
        Write-Log 'Error message added to Dataverse successfully' -Level 'INFO'
    }
    catch {
        Write-Log "Dataverse body content for error: $bodyContent" -Level 'ERROR'
        $ex = $_.Exception.Message
        Write-Log "Failed to POST error record to Dataverse: $ex" -Level 'VERBOSE'
        Write-Log 'Failed to POST record in the dataverse table License_queue_request during scriptError.' -Level 'ERROR'
    }
    return # Copilot.ps1 had return, E1-E5.ps1 had continue. Standardizing to return from function, caller decides flow.
}

Function New-SnowTask {
    param(
        [Parameter(Mandatory = $true)]
        [string]$shortDescription,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [string]$UserUPN,
        [Parameter(Mandatory = $false)]
        [string]$TicketType, # Used by E1-E5.ps1 to influence assignment_group
        [Parameter(Mandatory = $false)]
        [string]$cmdb_ci = 'Digital Collaboration Tools' # Default from E1-E5, Copilot used 'M365 Copilot'
    )

    $header = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $SNOW_Oauth_Token"
    }

    # Copilot assignment group: '5373ac80db20a59017dbcf8315961995'
    # E1-E5 default assignment group: 'cf4ddcb5db8f1f00953fa103ca961925'
    # E1-E5 ReplicationTask assignment group: '5373ac80db20a59017dbcf8315961995'

    $assignmentGroup = 'cf4ddcb5db8f1f00953fa103ca961925' # Default E1-E5
    if ($cmdb_ci -eq 'M365 Copilot') {
        $assignmentGroup = '5373ac80db20a59017dbcf8315961995' # Copilot's group
    } elseif ($TicketType -eq 'ReplicationTask') {
        $assignmentGroup = '5373ac80db20a59017dbcf8315961995' # E1-E5 Replication Task group
    }


    $body = @{
        short_description = $shortDescription
        description       = $Description
        cmdb_ci           = $cmdb_ci
        assignment_group  = $assignmentGroup
        priority          = if ($cmdb_ci -eq 'M365 Copilot') { 4 } else { 3 } # Copilot prio 4, E1/E5 prio 3
        contact_type      = 'Via API'
        u_requested_for   = $UserUPN
        u_source          = if ($cmdb_ci -eq 'M365 Copilot') { 'DWP-Automation' } else { 'Portal' } # Copilot source 'DWP-Automation', E1/E5 'Portal'
    }

    $params = @{
        method = 'POST'
        uri    = "$SnowURL/api/snc/v1/bp_rest_api/createRecord/c12586b6db9818d0389f3951f396197c/createServiceTask"
        body   = $body | ConvertTo-Json
        header = $header
    }

    try {
        (Invoke-RestMethod @params -ErrorAction Stop).result.number
    }
    catch {
        $exMsg = $_.Exception.Message
        Write-Log "Error creating SNOW task (first attempt): $exMsg" -Level 'VERBOSE'
        # Error logging SNOW ticket. Trying again with 'RequestedBy' value (Copilot.ps1 logic, might not be always available)
        # For E1-E5, RequestedBy might not be defined in the same way. Let's assume UserUPN is the primary identifier.
        # $body.u_requested_for = $UserUPN # Already set
        # $params.body = $body | ConvertTo-Json # No change needed to body for retry if u_requested_for is already $UserUPN

        # Copilot.ps1 had a retry mechanism that seemed to re-use $UserUPN, not $RequestedBy for u_requested_for.
        # The original E1-E5.ps1 also had a retry with $UserUPN.
        # The primary difference was the error message and the "Continue" in E1-E5.ps1.
        # Let's keep the retry but ensure it's robust.
        try {
            Write-Log "Retrying SNOW task creation for $UserUPN" -Level 'INFO'
            $taskResult = (Invoke-RestMethod @params -ErrorAction Stop).result.number # Retry with the same params
            Write-Log "New-SnowTask: Successfully created SNOW task '$taskResult' on retry for User: $UserUPN." -Level 'INFO'
            return $taskResult
        }
        catch {
            $exMsgRetry = $_.Exception.Message
            Write-Log "Failed to log SNOW ticket on retry for $UserUPN. Body: $($body | ConvertTo-Json). Params: $($params | ConvertTo-Json). Error: $exMsgRetry" -Level 'ERROR'
            throw "Failed to create SNOW task after retry: $exMsgRetry" # Throw to allow ScriptError to handle
        }
    }
}

function Convert-ToDateTime {
    param (
        [string]$dateString
    )
    $dateFormats = @(
        'dd/MM/yyyy'
        # Add other common formats if necessary
    )
    foreach ($format in $dateFormats) {
        try {
            $dateTime = [datetime]::ParseExact($dateString, $format, $null)
            return $dateTime
        }
        catch { continue }
    }
    try {
        $dateTime = [datetime]::Parse($dateString)
        return $dateTime
    }
    catch {
        throw "Unable to determine the date format of '$dateString'. Please provide a date in a recognized format."
    }
}

function Get-MSFormToken {
    # $KeyvaultName is global or passed as param. Assuming global for now.
    $scope = 'https://forms.cloud.microsoft/.default'
    $refreshTokenName = 'api-dwp-graph-refreshToken'
    $clientIdName = 'DWP-DevHub-Dataverse-AppID'
    $tenantid = 'ea80952e-a476-42d4-aaf4-5457852b0f7e'
    $refreshtoken = $null
    $clientId = $null

    try {
        $refreshtoken = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $refreshTokenName -AsPlainText
        $clientId = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $clientIdName -AsPlainText
    }
    catch {
        $failedSecretName = if (-not $refreshtoken) { $refreshTokenName } else { $clientIdName }
        Write-Log "Failed to retrieve KeyVault secret '$failedSecretName' from vault '$KeyvaultName'. Error: $($_.Exception.Message)" -Level 'ERROR'
        throw "Failed to retrieve KeyVault secret for MS Form Token generation."
    }

    $body = @{
        client_id     = $clientId
        scope         = $scope
        grant_type    = 'refresh_token'
        refresh_token = $refreshtoken # Corrected variable name
    }
    $tokenUri = "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token"
    try {
        $response = Invoke-WebRequest $tokenUri -ContentType 'application/x-www-form-urlencoded' -Method POST -Body $body
        $tokenobj = ConvertFrom-Json $response.Content
        return $tokenobj.access_token
    }
    catch {
        # Sanitize body for logging by removing refresh_token
        $sanitizedBody = $body | Select-Object * -ExcludeProperty refresh_token | ConvertTo-Json -Compress
        Write-Log "Failed to retrieve MS Form token from identity provider. URI: $tokenUri. Body (sanitized): $sanitizedBody. Error: $($_.Exception.Message)" -Level 'ERROR'
        throw "Failed to retrieve MS Form token from identity provider."
    }
}

function Get-MSFormResponse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN
    )
    $TenantId = 'ea80952e-a476-42d4-aaf4-5457852b0f7e'
    $formId = 'LpWA6nak1EKq9FRXhSsPfk-JoVaKVU9JmxKWm6PhSkVUQTQ1NzYyTUZOTlUxWFNFVlZOUlNFRkdWUC4u'
    $UserID = '56a1894f-558a-494f-9b12-969ba3e14a45' # This seems to be a static UserID, investigate if it should be dynamic

    try {
        $MSFormToken = Get-MSFormToken
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'Verbose'
        ScriptError('Failed to get MS Form token.') # This will call the new ScriptError
        return # Stop further execution in this function
    }

    $Headers = @{
        'Authorization' = "Bearer $MSFormToken"
    }
    $formResponsesUrl = "https://forms.office.com/formapi/api/$TenantId/users/$UserID/forms('$formId')/responses"
    $response = $null
    try {
        $response = Invoke-RestMethod -Uri $formResponsesUrl -Headers $Headers -Method Get -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to retrieve MS Form responses for user '$UserUPN' from URL '$formResponsesUrl'. Error: $($_.Exception.Message)" -Level 'ERROR'
        ScriptError -msg "Failed to retrieve MS Form responses for user $UserUPN." -UserUPNForError $UserUPN
        return "Error_Fetching_Responses"
    }

    $ResponseObject = $response.value | Where-Object { $_.responder -eq $userUPN }

    if ($null -eq $ResponseObject) {
        return "Pending"
    }
    else {
        # $Responder = $responseObject.responder # Not used
        # $ResponseDate = $responseObject.submitDate # Not used
        try {
            $Answer = ($ResponseObject.answers | ConvertFrom-Json).answer1
            return $Answer
        }
        catch {
            Write-Log "Failed to parse MS Form answer for user '$UserUPN' from response. Error: $($_.Exception.Message)" -Level 'ERROR'
            ScriptError -msg "Failed to parse MS Form answer for user $UserUPN." -UserUPNForError $UserUPN
            return "Error_Parsing_Answer"
        }
    }
}

function Get-SOUCornerstoneReport{
    try {
        $azcontext = Set-AzContext -Subscription $StorageAccountSubscription
        $storageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountNameRSG -Name $storageAccountName -DefaultProfile $azcontext
        $storageAccountContext = $storageAccount.Context
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError('Failed to get storage account details.')
        return
    }

    $gpgExecutablePath = 'C:\Program Files (x86)\GnuPGin\gpg.exe' # Consider making this configurable
    $destinationFilePath = 'D:\Temp' # Consider making this configurable or using $env:TEMP
    $secretFileName = 'passphrase.txt'
    $containerNameSouReport = 'copilot-sou-report-cornerstone' # Specific container for SOU reports
    $PrivateKeyFile = 'copilot_prod_SECRET.asc'

    try {
        if (!(Test-Path $destinationFilePath)) {
            New-Item -ItemType Directory -Force -Path $destinationFilePath
        }
    }
    catch {
        Write-Log "$_.Exception.Message" -Level 'ERROR'
        ScriptError -msg "Failed to create destination directory '$destinationFilePath'."
        return
    }

    # $passphraseFilePath = $destinationFilePath + '' + $secretFileName # Original, fixed below
    $passphraseFilePath = Join-Path $destinationFilePath $secretFileName
    $PrivateKeyFilePath = Join-Path $destinationFilePath $PrivateKeyFile

    try {
        $blobs = Get-AzStorageBlob -Container $containerNameSouReport -Context $storageAccountContext | Where-Object { $_.Name -like 'Copilot_SOUReport_CSOD*' }
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError('Failed to get CSV file from container matching with name Copilot_SOUReport_CSOD.')
        return
    }

    if ($blobs) {
        $latestBlob = $blobs | Sort-Object -Property LastModified -Descending | Select-Object -First 1
        $blobName = $latestBlob.Name
        $decryptedFilePath = Join-Path $destinationFilePath ($blobName -replace '\.pgp$', '')


        try {
            Get-AzStorageBlobContent -Blob $blobName -Container $containerNameSouReport -Destination $destinationFilePath -Context $storageAccountContext -Force
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to download latest CSV file from storage container.')
            return
        }
        try {
            Get-AzStorageBlobContent -Blob $secretFileName -Container $containerNameSouReport -Destination $destinationFilePath -Context $storageAccountContext -Force
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to download passphrase file from storage container.')
            return
        }
        $encryptedFilePath = Join-Path $destinationFilePath $blobName
        # $passphraseFilePath already defined

        try {
            Get-AzStorageBlobContent -Blob $PrivateKeyFile -Container $containerNameSouReport -Destination $destinationFilePath -Context $storageAccountContext -Force
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to download private key file from storage container.')
            return
        }
        try {
            & $gpgExecutablePath --batch --yes --import $PrivateKeyFilePath | Out-Null
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to run GPG command to import the secret keys on hybrid worker.')
            return
        }
        Invoke-Command -ScriptBlock {
            # Variables from parent scope need to be passed or redefined if Invoke-Command creates new session context
            $gpgExecutablePath_ic = 'C:\Program Files (x86)\GnuPGin\gpg.exe' # Redefine or pass using $using:
            try {
                & $gpgExecutablePath_ic --batch --yes --pinentry-mode loopback --passphrase-file "$using:passphraseFilePath" --output "$using:decryptedFilePath" --decrypt "$using:encryptedFilePath" | Out-Null
            }
            catch {
                $ex_ic = $_.Exception.Message
                Write-Log $ex_ic -Level 'ERROR' # This Write-Log might not work as expected if function not defined in this scope
                # Propagate error out or use a more robust error handling for Invoke-Command
                throw "GPG decryption failed: $ex_ic" 
            }
        }
        # The if ($LASTEXITCODE -ne 0) check for gpg.exe is kept as it's a direct check of an external command's success.
        if ($LASTEXITCODE -ne 0) {
             ScriptError "GPG Decryption failed. Exit code: $LASTEXITCODE. Check logs for details."
             return
        }
        return $decryptedFilePath
    }
    else {
        Write-Log "No blobs found matching the pattern 'Copilot_SOUReport_CSOD*' in storage container '$containerNameSouReport'." -Level VERBOSE
        ScriptError("No blobs found matching the pattern Copilot_SOUReport_CSOD* in storage container '$containerNameSouReport'.")
        return
    }
}

function Get-SOUStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN,
        [Parameter(Mandatory = $true)]
        [string]$UserEntity,
        [Parameter(Mandatory = $true)]
        [string]$CornerstoneFilePath,
        # Parameters below are from the main loop context, passed for actions within this function
        [Parameter(Mandatory = $true)]
        [string]$DBMessageID,
        [Parameter(Mandatory = $true)]
        [string]$CurrentTaskNumber,
        [Parameter(Mandatory = $true)]
        [string]$CurrentRITMNumber,
        [Parameter(Mandatory = $false)]
        [datetime]$LAppCaseAssignedDateFromDB,
        [Parameter(Mandatory = $true)]
        [string]$UserExtensionAttribute1FromContext
    )

    try {
        $FormResponseValue = Get-MSFormResponse -UserUPN $UserUPN
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError("Failed to get MS Form response for the user $UserUPN.")
        return "Error" # Indicate error state
    }

    try {
        $csvContent = Get-Content -Path $CornerstoneFilePath -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError("Failed to get SOU CSV report content from path: $CornerstoneFilePath.")
        return "Error" # Indicate error state
    }
    
    $csvData = $csvContent | Select-Object -Skip 7
    $csvParsed = $null
    try {
        $csvParsed = $csvData | ConvertFrom-Csv
    }
    catch {
        Write-Log "Failed to parse SOU CSV data. User: $UserUPN. Error: $($_.Exception.Message)" -Level 'ERROR'
        ScriptError -msg "Failed to parse SOU CSV data for user $UserUPN." -UserUPNForError $UserUPN
        return "Error"
    }

    $selectedData = $null
    try {
        $selectedData = $csvParsed | Select-Object 'Training title', 'User full name', 'User e-mail', 'Quiz attempt date', 'Quiz SUCCESS Status', 'Training record status', 'Training record completed date'
    }
    catch {
        Write-Log "SOU CSV missing expected columns or error during column selection. User: $UserUPN. Error: $($_.Exception.Message)" -Level 'ERROR'
        ScriptError -msg "SOU CSV missing expected columns for user $UserUPN." -UserUPNForError $UserUPN
        return "Error"
    }
    $today = (Get-Date)
    $TwentyEightDaysAgo = (Get-Date).AddDays(-28)
    $365DaysAgo = (Get-Date).AddDays(-365)

    $filteredData = $selectedData | Where-Object {
        ($null -ne $_.'Training record completed date') `
        -and (!([string]::IsNullOrWhiteSpace($_.'Training record completed date'))) `
        -and (!([string]::IsnullOrEmpty($_.'Training record completed date')))
    } | Where-Object {
        $TrainingCompletedString = $_.'Training record completed date'
        $trainingCompletedDate = $TrainingCompletedString -split ' ' | Select-Object -First 1
        $parsedDate = $null
        try { $parsedDate = Convert-ToDateTime($trainingCompletedDate) } catch { Write-Log "Could not parse date: $trainingCompletedDate for user $_.'User e-mail'" -Level WARN }
        $parsedDate -ne $null -and $parsedDate -ge $365DaysAgo -and $parsedDate -le $today
    }

    $UserSOUData = $filteredData | Where-Object { ($_.'User e-mail' -eq $UserUPN) -and ($_.'Training title' -like '*Copilot for Microsoft 365*') } | Select-Object -Unique
    $UserPTWData = $selectedData | Where-Object { ($_.'User e-mail' -eq $UserUPN) -and ($_.'Training title' -like '*PTW - Microsoft 365 Copilot Generative AI*') }

    if($null -ne $LAppCaseAssignedDateFromDB){
        # $LAppCaseAssignedDate = Get-Date $LAppCaseAssignedDateFromDB # Already a datetime object if from DB correctly
        if ($LAppCaseAssignedDateFromDB -lt $TwentyEightDaysAgo) {
            Write-Log "Training assignment date ($LAppCaseAssignedDateFromDB) for user $UserUPN is older than 28 days. Training has expired." -Level WARN

            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Training expired' WHERE ID = $DBMessageID;"
            Write-Log "DB record $DBMessageID for UPN $userUPN - $LicenseType $Action marked as Training Expired."

            try {
                Update-TaskStatus -TicketNumber $CurrentTaskNumber -State '3' -WorkNotes 'Training assignment date is older than 28 days. Training has expired. Closing the task.'
            } catch { Write-Log "Failed to update Task $CurrentTaskNumber for user $UserUPN (Context: Training Expired). Error: $($_.Exception.Message)" -Level 'WARN' }
            try {
                Update-TicketStatus -TicketNumber $CurrentRITMNumber -State '3' -Stage 'Training Expired' -WorkNotes 'Training assignment date is older than 28 days. Training has expired. Closing the ticket.'
            } catch { Write-Log "Failed to update RITM $CurrentRITMNumber for user $UserUPN (Context: Training Expired). Error: $($_.Exception.Message)" -Level 'WARN' }
            try {
                Update-EntityQuota -UserEntity $UserExtensionAttribute1FromContext -TicketStage 'Training Expired'
            } catch { Write-Log "Failed to update entity quota for user $UserUPN (Entity: $UserExtensionAttribute1FromContext, Context: Training Expired). Error: $($_.Exception.Message)" -Level 'WARN' }

            $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
            $dataverseBody = @{
                new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $ProcessedTime; new_completiontime = $completionTime
                new_lappcasenumber = $LAppCase; new_saviynttrackingid = $saviyntRequestReferenceIDs.trackingID; new_status = 'Complete'; new_saviynttransactionid = $saviyntRequestReferenceIDs.APITransactionID
                new_errorcode = 'Training Expired'
            } | ConvertTo-Json
            Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dataverseBody
            Write-Log "Dataverse record updated for $userUPN due to training expiry."
            return "Expired" # Special status to indicate processing should stop for this user
        } else {
             # Check PTW for T&S only if LAppCaseAssignedDate is NOT older than 28 days
            if($UserEntity -eq 'Supply, Trading & Shipping'){ # PTW check is specific to T&S
                if($null -ne $UserPTWData){
                    if(($UserPTWData.'Training record status' -notcontains 'Completed') -and ($UserSOUData.'Training record status' -eq 'Completed')){
                        Write-Log "User $UserUPN (T&S) has completed SOU but PTW training is not completed. Rejecting." -Level WARN
                        try {
                            Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Copilot license request rejected' -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName 'Microsft_365_copilot_ST&S_PTW_Pending.html' -Replacements @{}
                        } catch { Write-Log "Failed to send Copilot email (Template: Microsft_365_copilot_ST&S_PTW_Pending.html) to user $UserUPN. Error: $($_.Exception.Message)" -Level 'WARN' }
                        
                        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Rejected due to PTW non-completion' WHERE ID = $DBMessageID;"
                        try {
                            Update-TaskStatus -TicketNumber $CurrentTaskNumber -State '3' -WorkNotes "User's Passport To Work training record shows as incomplete. Microsoft 365 Copilot license request rejected."
                        } catch { Write-Log "Failed to update Task $CurrentTaskNumber for user $UserUPN (Context: PTW Non-Completion). Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Update-TicketStatus -TicketNumber $CurrentRITMNumber -State '3' -Stage 'Training Expired' -WorkNotes "User's Passport To Work training record shows as incomplete. Microsoft 365 Copilot license request rejected." # Stage should be 'Rejected' or similar
                        } catch { Write-Log "Failed to update RITM $CurrentRITMNumber for user $UserUPN (Context: PTW Non-Completion). Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Update-EntityQuota -UserEntity $UserExtensionAttribute1FromContext -TicketStage 'Rejected' # Use 'Rejected' stage
                        } catch { Write-Log "Failed to update entity quota for user $UserUPN (Entity: $UserExtensionAttribute1FromContext, Context: PTW Non-Completion). Error: $($_.Exception.Message)" -Level 'WARN' }

                        $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                        $dataverseBody = @{
                            new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                            new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $ProcessedTime; new_completiontime = $completionTime
                            new_lappcasenumber = $LAppCase; new_saviynttrackingid = $saviyntRequestReferenceIDs.trackingID; new_status = 'Complete'; new_saviynttransactionid = $saviyntRequestReferenceIDs.APITransactionID
                            new_errorcode = 'PTW Training incomplete'
                        } | ConvertTo-Json
                        Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dataverseBody
                        Write-Log "Dataverse record updated for $userUPN due to PTW incomplete."
                        return "PTW_Failed" # Special status
                    }
                } else { # No PTW data found for T&S user
                     if ($UserSOUData.'Training record status' -eq 'Completed') { # SOU is completed but PTW is missing
                        Write-Log "User $UserUPN (T&S) has completed SOU but no PTW training data found. Assuming PTW incomplete and rejecting." -Level WARN
                        # Similar rejection logic as above for PTW not completed
                        try {
                            Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Copilot license request rejected' -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName 'Microsft_365_copilot_ST&S_PTW_Pending.html' -Replacements @{}
                        } catch { Write-Log "Failed to send Copilot email (Template: Microsft_365_copilot_ST&S_PTW_Pending.html) to user $UserUPN. Error: $($_.Exception.Message)" -Level 'WARN' }
                        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Rejected due to missing PTW data' WHERE ID = $DBMessageID;"
                        try {
                            Update-TaskStatus -TicketNumber $CurrentTaskNumber -State '3' -WorkNotes "User's Passport To Work training data not found. Microsoft 365 Copilot license request rejected."
                        } catch { Write-Log "Failed to update Task $CurrentTaskNumber for user $UserUPN (Context: PTW Missing Data). Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Update-TicketStatus -TicketNumber $CurrentRITMNumber -State '3' -Stage 'Training Expired' -WorkNotes "User's Passport To Work training data not found. Microsoft 365 Copilot license request rejected." # Stage should be 'Rejected'
                        } catch { Write-Log "Failed to update RITM $CurrentRITMNumber for user $UserUPN (Context: PTW Missing Data). Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Update-EntityQuota -UserEntity $UserExtensionAttribute1FromContext -TicketStage 'Rejected'
                        } catch { Write-Log "Failed to update entity quota for user $UserUPN (Entity: $UserExtensionAttribute1FromContext, Context: PTW Missing Data). Error: $($_.Exception.Message)" -Level 'WARN' }

                        $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                        $dataverseBody = @{
                            new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                            new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $ProcessedTime; new_completiontime = $completionTime
                            new_lappcasenumber = $LAppCase; new_saviynttrackingid = $saviyntRequestReferenceIDs.trackingID; new_status = 'Complete'; new_saviynttransactionid = $saviyntRequestReferenceIDs.APITransactionID
                            new_errorcode = 'PTW Training data missing'
                        } | ConvertTo-Json
                        Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dataverseBody
                        Write-Log "Dataverse record updated for $userUPN due to missing PTW data."
                        return "PTW_Missing"
                     }
                }
            }
        }
    }

    # Main SOU/TOU status determination logic
    $SOUStatus = 'Pending' # Default
    if($UserEntity -eq 'Supply, Trading & Shipping'){
        if ($null -ne $UserSOUData -and $UserSOUData.'Training record status' -eq 'Completed' `
            -and $null -ne $UserPTWData -and $UserPTWData.'Training record status' -contains 'Completed') {
            switch ($FormResponseValue) {
                'Accept'  { $SOUStatus = 'Passed'; break }
                'Decline' { $SOUStatus = 'Failed'; break }
                'Pending' { $SOUStatus = 'Pending'; break }
                default   { Write-Log "Unknown MS Form response '$FormResponseValue' for T&S user $UserUPN." -Level WARN; $SOUStatus = 'Pending'; break } # Default to Pending for unknown
            }
        } elseif ($null -ne $UserSOUData -and $UserSOUData.'Training record status' -eq 'Completed' `
                   -and ($null -eq $UserPTWData -or $UserPTWData.'Training record status' -notcontains 'Completed')) {
            $SOUStatus = 'Pending' # SOU done, PTW not done or missing, already handled by PTW_Failed/PTW_Missing logic if applicable, otherwise pending LApp case.
            Write-Log "T&S User $UserUPN SOU completed, but PTW is pending or failed. Status: $SOUStatus" -Level INFO
        } else { # SOU not completed or SOU data missing
            $SOUStatus = if ($FormResponseValue -eq 'Decline') {'Failed'} else {'Pending'}
        }
    } else { # Non-T&S users
        if ($null -ne $UserSOUData -and $UserSOUData.'Training record status' -eq 'Completed') { # Check CSOD SOU for non-T&S too
             switch ($FormResponseValue) { # MS Form response is effectively TOU for non-T&S
                'Accept'  { $SOUStatus = 'Passed'; break }
                'Decline' { $SOUStatus = 'Failed'; break }
                'Pending' { $SOUStatus = 'Pending'; break }
                default   { Write-Log "Unknown MS Form response '$FormResponseValue' for non-T&S user $UserUPN." -Level WARN; $SOUStatus = 'Pending'; break }
            }
        } else { # SOU (CSOD) not completed or data missing for non-T&S
            $SOUStatus = if ($FormResponseValue -eq 'Decline') {'Failed'} else {'Pending'}
            Write-Log "Non-T&S User $UserUPN SOU (CSOD) not completed or data missing. MS Form was $FormResponseValue. Status: $SOUStatus" -Level INFO
        }
    }
    return $SOUStatus
}

function Get-TOUStatus { # This function is specific to Copilot.ps1 logic for non-T&S users
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN
    )
    try {
        $FormResponseValue = Get-MSFormResponse -UserUPN $UserUPN
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError("Failed to get MS Form response for TOU status for user $UserUPN.")
        return "Error"
    }

    if ($FormResponseValue -eq "Error" -or $FormResponseValue -eq "Error_Fetching_Responses" -or $FormResponseValue -eq "Error_Parsing_Answer") {
        # ScriptError would have been called by Get-MSFormResponse or this function's catch block already.
        # Just ensure we propagate an error status.
        return "Error"
    }

    switch ($FormResponseValue) {
        'Accept'  { return 'Passed' }
        'Decline' { return 'Failed' }
        'Pending' { return 'Pending' }
        default   { 
            Write-Log "Unknown MS Form response '$FormResponseValue' for user $UserUPN during TOU check." -Level WARN
            return 'Pending' # Default to Pending for unknown MS Form responses
        }
    }
}

function Invoke-UpgradeToCopilot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN,
        [Parameter(Mandatory = $true)]
        [string]$SOUTrainingStatusToUse, # Renamed to avoid conflict with $SOUTrainingStatus from main scope
        [Parameter(Mandatory = $true)]
        [string]$UserEntraGUID,
        [Parameter(Mandatory = $true)]
        [string]$TaskNumberToUpdate, # Renamed
        [Parameter(Mandatory = $true)]
        [string]$RITMNumberToUpdate, # Renamed
        [Parameter(Mandatory = $true)]
        [string]$LAppCaseFromContext, # Renamed
        [Parameter(Mandatory = $true)]
        [string]$UserExtensionAttribute1ForQuota, # Renamed
        # DBRecordID for SQL update on SOU/TOU failure
        [Parameter(Mandatory = $true)]
        [string]$DBRecordIDForFailureUpdate,
        # Following are for Dataverse logging on SOU/TOU failure
        [Parameter(Mandatory = $true)] $RequestedByForDV,
        [Parameter(Mandatory = $true)] $licenseCategorizationIDForDV,
        [Parameter(Mandatory = $true)] $actionForDV,
        [Parameter(Mandatory = $true)] $RequestedTimeForDV,
        [Parameter(Mandatory = $true)] $ProcessedTimeForDV
    )

    $LicenseAssignmentStatus = "ErrorInFunction" # Default status

    if ($SOUTrainingStatusToUse -eq 'Passed') {
        try {
            New-MgGroupMember -GroupId $CopilotCompletedGroupID -DirectoryObjectId $UserEntraGUID
            Write-Log "User $UserUPN has been successfully added to the copilot licensing Entra group $CopilotCompletedGroupID." -Level 'INFO'
            $LicenseAssignmentStatus = 'Assigned'
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log "Failed to add user $UserUPN to Copilot Completed Group $CopilotCompletedGroupID: $ex" -Level 'ERROR'
            # ScriptError('Failed to add user to Copilot Completed Group.') # Let caller handle flow
            $LicenseAssignmentStatus = "ErrorAddingToGroup"
        }
    }
    elseif ($SOUTrainingStatusToUse -eq 'Pending') {
        Write-Log "User $UserUPN SOU/TOU training is still pending (LApp case $LAppCaseFromContext). Awaiting completion." -Level 'INFO'
        Update-TaskStatus -TicketNumber $TaskNumberToUpdate -State '6' -WorkNotes "Learning App case $LAppCaseFromContext has already been raised. Awaiting SOU/TOU training completion check."
        Update-TicketStatus -TicketNumber $RITMNumberToUpdate -State '-5' -Stage 'Pending Training' -WorkNotes "Learning App case $LAppCaseFromContext has already been raised. Awaiting SOU/TOU training completion check."
        $LicenseAssignmentStatus = 'Pending' # This will make the main loop continue for this message
    }
    elseif ($SOUTrainingStatusToUse -eq 'Failed') {
        Write-Log "User $UserUPN has failed or declined SOU/TOU training." -Level 'WARN'
        Update-TaskStatus -TicketNumber $TaskNumberToUpdate -State '3' -WorkNotes 'User has failed the SOU/TOU training or declined. Closing the task.'
        Update-TicketStatus -TicketNumber $RITMNumberToUpdate -State '3' -Stage 'Completed' -WorkNotes 'User has failed the SOU/TOU training or declined. Closing the RITM.' # Stage should be more like 'Rejected' or 'Closed Incomplete'

        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'SOU/TOU Failed' WHERE ID = $DBRecordIDForFailureUpdate;"
        Write-Log "DB record $DBRecordIDForFailureUpdate for $userUPN marked as SOU/TOU Failed."

        Update-EntityQuota -UserEntity $UserExtensionAttribute1ForQuota -TicketStage 'Rejected' # Or 'Training Failed'

        $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
        $dvBody = @{
            new_requestedby = $RequestedByForDV; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationIDForDV)"; new_action = $actionForDV
            new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTimeForDV; new_processedtime = $ProcessedTimeForDV; new_completiontime = $completionTime
            new_lappcasenumber = $LAppCaseFromContext; new_saviynttrackingid = $null; new_status = 'Complete'; new_saviynttransactionid = $null # Assuming no Saviynt for Copilot
            new_errorcode = 'SOU/TOU Failed'
        } | ConvertTo-Json
        Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dvBody
        Write-Log "Dataverse record updated for $userUPN due to SOU/TOU failure."
        $LicenseAssignmentStatus = 'Failed' # This will make the main loop continue for this message after cleanup
    } else {
        Write-Log "Invoke-UpgradeToCopilot called with unexpected SOU/TOU status: '$SOUTrainingStatusToUse' for user $UserUPN." -Level ERROR
        $LicenseAssignmentStatus = "ErrorInvalidSOUStatus"
    }
    return $LicenseAssignmentStatus
}

function Get-SaviyntLicenseReplicationStatus { # Combined from E1-E5.ps1 (more comprehensive)
    param(
        [Parameter(Mandatory = $true)]
        [string]$emailID,
        [Parameter(Mandatory = $true)]
        [string]$action, # 'upgrade' or 'downgrade'
        [Parameter(Mandatory = $true)]
        [string]$LicenseType # 'Microsoft365' or 'MicrosoftCopilot'
    )
    try {
        $licenses = Get-MgUserLicenseDetail -UserId $emailID
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Error getting license details for $emailID: $ex" -Level 'ERROR'
        # ScriptError("Failed to get allocated license details for the user $emailID.") # Let caller handle
        return $false # Assume not replicated on error
    }

    $lic_allocation = $false
    if ($action -eq 'downgrade') { # Specific to E1 downgrade
        if (($LicenseType -eq 'Microsoft365') -and ($licenses.skupartnumber -contains 'STANDARDPACK')) { # STANDARDPACK is E1
            Write-Log "User $emailID has an E1 license (STANDARDPACK)." -Level 'DEBUG'
            $lic_allocation = $true
        }
    }
    elseif ($action -eq 'upgrade') {
        if (($LicenseType -eq 'Microsoft365') -and ($licenses.skupartnumber -contains 'SPE_E5')) {
            Write-Log "User $emailID has an E5 license (SPE_E5)." -Level 'DEBUG'
            $lic_allocation = $true
        }
        elseif (($LicenseType -eq 'MicrosoftCopilot') -and ($licenses.skupartnumber -like '*_Copilot*')) { # Match common Copilot SKU patterns
            Write-Log "User $emailID has a Copilot license (SkuPartNumber like '*_Copilot*')." -Level 'DEBUG'
            $lic_allocation = $true
        }
    }
    
    if (-not $lic_allocation) {
        Write-Log "License replication check for $emailID (Action: $action, Type: $LicenseType) shows license NOT currently allocated. Current licenses: $($licenses.skupartnumber -join ', ')" -Level 'DEBUG'
    }
    return $lic_allocation
}

function Get-EntityQuota {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserEntity
    )
    $header = @{
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $SNOW_Oauth_Token"
    }
    $SkuPartNumber = 'Microsoft_365_Copilot' # This function is Copilot-specific for quota check
    $params = @{
        method = 'GET'
        uri    = "$SnowURL/api/snc/v2/bp_rest_api/c12586b6db9818d0389f3951f396197c/GetProductLicense?searchVal=skupartnumberIN$SkuPartNumber"
        header = $header
    }
    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to get entity license details from SNOW for entity '$UserEntity', Sku '$SkuPartNumber': $ex" -Level 'ERROR'
        # ScriptError 'Failed to get entity license details from SNOW table.' # Let caller handle
        return $null # Indicate error or no data
    }
    $AllEntityDetails = $response.result
    $EntityAvailableLicenses = 0 # Default if not found

    foreach ($entity in $AllEntityDetails) {
        if ($entity.entity -like $UserEntity) {
            # $EntityQuota = $entity.quota # Not used in original Copilot logic return
            $EntityAvailableLicenses = $entity.available_licenses
            break
        }
    }
    Write-Log "Available quota for entity '$UserEntity' (Copilot): $EntityAvailableLicenses" -Level DEBUG
    return $EntityAvailableLicenses
}

function Update-EntityQuota {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserEntity,
        [Parameter(Mandatory = $true)]
        [string]$TicketStage # e.g., 'Pending Training', 'Training Expired', 'Rejected'
    )

    $CurrentEntityAvailableLicenses = Get-EntityQuota -UserEntity $UserEntity
    if ($null -eq $CurrentEntityAvailableLicenses) {
         Write-Log "Could not retrieve current quota for $UserEntity. Aborting Update-EntityQuota." -Level ERROR
         ScriptError "Failed to retrieve current quota for $UserEntity during Update-EntityQuota."
         return 'failed'
    }


    $SysIDs = @{ # Copilot.ps1 specific SysIDs
        'BP Board'                            = '0c636876c31e5e14012a76df0501317f'
        'BP Corporate Exec Office'            = 'f1d3a83ac31e5e14012a76df050131a3'
        'Technology'                          = '5f4597aec3a78294186959aeb0013122'
        'Supply, Trading & Shipping'          = '707ab31cc30c16105f28d2477d0131f2'
        'Finance'                             = 'a3ca7b5cc30c16105f28d2477d01310e'
        'Legal'                               = 'e03b3f9cc30c16105f28d2477d013121'
        'Customers & products'                = 'ea15b758c3c816105f28d2477d013195'
        'People, Culture & Communications'    = 'ecceffd4c34c16105f28d2477d01317d'
        'Strategy, sustainability & ventures' = 'f7373350c30c16105f28d2477d0131b4'
        'Production & operations'             = 'f8463f5cc3c816105f28d2477d013133'
        'Gas & low carbon energy'             = 'fcb5ff98c3c816105f28d2477d013112'
    }
    $sysID = $SysIDs[$UserEntity]
    if (-not $sysID) {
        Write-Log "SysID not found for entity '$UserEntity' in Update-EntityQuota." -Level ERROR
        ScriptError "SysID not found for entity '$UserEntity' in Update-EntityQuota."
        return 'failed'
    }

    $header = @{
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $SNOW_Oauth_Token"
        'Accept'       = 'application/json'
    }

    $NewEntityAvailableLicenses = [int]$CurrentEntityAvailableLicenses
    if ($TicketStage -eq 'Pending Training') {
        $NewEntityAvailableLicenses -= 1
    }
    elseif ($TicketStage -eq 'Training Expired' -or $TicketStage -eq 'Rejected') {
        $NewEntityAvailableLicenses += 1
    }
    # No change for other stages explicitly mentioned in Copilot.ps1

    $body = @{ available_licenses = $NewEntityAvailableLicenses } | ConvertTo-Json
    $params = @{
        method = 'PUT'
        uri    = "$SnowURL/api/snc/v2/bp_rest_api/c12586b6db9818d0389f3951f396197c/UpdateProductLicense/$sysid"
        body   = $body
        header = $header
    }
    try {
        Invoke-RestMethod @params -ErrorAction Stop
        Write-Log "Successfully updated entity quota for '$UserEntity' to $NewEntityAvailableLicenses (Stage: $TicketStage)." -Level INFO
        return 'success'
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to update entity license details in SNOW for entity '$UserEntity': $ex" -Level 'ERROR'
        # ScriptError 'Failed to update entity license details in SNOW table.' # Let caller handle
        return 'failed'
    }
}

function Send-CopilotEmail { # Specific to Copilot.ps1
    param (
        [Parameter(Mandatory = $true)]
        [string]$SendTo,
        [Parameter(Mandatory = $true)]
        [string]$CC,
        [Parameter(Mandatory = $true)]
        [string]$EmailSubject,
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountNameForEmail, # Renamed to avoid conflict
        [Parameter(Mandatory = $true)]
        [string]$ContainerNameForEmail, # Renamed
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,
        [Parameter(Mandatory = $false)]
        [array]$Replacements
    )
    $bodyEmailAuth = @{ # Renamed variable
        client_id     = $Email_AppID
        client_secret = $Email_Secret
        grant_type    = 'client_credentials'
        scope         = "api://$EmailUtilScope/.default" # Use EmailUtilScope variable
    }
    $uriEmailAuth = "https://login.microsoftonline.com:443/$tenantId/oauth2/v2.0/token" # Use global $tenantId
    $bearerEmail = Invoke-RestMethod -Method POST -Uri $uriEmailAuth -Body $bodyEmailAuth

    $headerEmail = @{ # Renamed variable
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $($bearerEmail.access_token)"
    }
    $bodyEmailSend = @{ # Renamed variable
        SendTo             = $SendTo
        Cc                 = $CC
        EmailSubject       = $EmailSubject
        StorageAccountName = $StorageAccountNameForEmail
        ContainerName      = $ContainerNameForEmail
        TemplateName       = $TemplateName
        Replacements       = $Replacements
    }
    $jsonBodyEmail = $bodyEmailSend | ConvertTo-Json
    $paramsEmail = @{ # Renamed variable
        method  = 'POST'
        uri     = $Email_URI
        headers = $headerEmail
        body    = $jsonBodyEmail
    }
    try {
        Invoke-RestMethod @paramsEmail
        Write-Log "Email '$EmailSubject' sent to $SendTo successfully." -Level INFO
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to send email '$EmailSubject' to $SendTo. Error: $ex" -Level 'ERROR'
    }
}

function Get-TicketStatus { # Shared, seemingly identical
    param (
        [Parameter(Mandatory = $true)]
        [string]$TicketNumber
    )
    $header = @{
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $SNOW_Oauth_Token"
    }
    $params = @{
        method = 'GET'
        uri    = "$SnowURL/api/snc/v2/bp_rest_api/c12586b6db9818d0389f3951f396197c/getRITM?searchVal=numberIN$TicketNumber"
        header = $header
    }
    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        # $script:ritmStatuses = [PSCustomObject]@{ stage = $response.result.stage; state = $response.result.state } # Avoid script scope modification from function
        return [PSCustomObject]@{ stage = $response.result.stage; state = $response.result.state }
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to get RITM $TicketNumber status from ServiceNow: $ex" -Level 'ERROR'
        return $null
    }
}

function Update-TicketStatus { # Shared, seemingly identical
    param (
        [Parameter(Mandatory = $true)]
        [string]$TicketNumber,
        [Parameter(Mandatory = $false)]
        [string]$WorkNotes,
        [Parameter(Mandatory = $false)]
        [string]$Stage,
        [Parameter(Mandatory = $false)]
        [string]$State
    )
    $header = @{
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $SNOW_Oauth_Token"
    }
    $body = @{}
    if ($null -ne $State) { $body.state = $State }
    if ($null -ne $Stage) { $body.stage = $Stage }
    if ($null -ne $WorkNotes) { $body.work_notes = $WorkNotes }

    $jsonBody = $body | ConvertTo-Json
    $params = @{
        method = 'PUT'
        uri    = "$SnowURL/api/snc/v2/bp_rest_api/c12586b6db9818d0389f3951f396197c/updateRITM/$TicketNumber"
        header = $header
        body   = $jsonBody
    }
    try {
        Invoke-RestMethod @params
        Write-Log "RITM $TicketNumber status updated: State=$State, Stage=$Stage." -Level INFO
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to update RITM $TicketNumber status in ServiceNow: $ex. Body: $jsonBody" -Level 'ERROR'
    }
}

function Update-TaskStatus { # Shared, seemingly identical
    param (
        [Parameter(Mandatory = $true)]
        [string]$TicketNumber,
        [Parameter(Mandatory = $false)]
        [string]$WorkNotes,
        [Parameter(Mandatory = $false)]
        [string]$State
    )
    $header = @{
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $SNOW_Oauth_Token"
    }
    $body = @{}
    if ($null -ne $State) { $body.state = $State }
    if ($null -ne $WorkNotes) { $body.work_notes = $WorkNotes }

    $jsonBody = $body | ConvertTo-Json
    $params = @{
        method = 'PUT'
        uri    = "$SnowURL/api/snc/v1/bp_rest_api/updateRecord/c12586b6db9818d0389f3951f396197c/updateServiceTask?searchVal=numberIN$TicketNumber"
        header = $header
        body   = $jsonBody
    }
    try {
        Invoke-RestMethod @params
        Write-Log "Task $TicketNumber status updated: State=$State." -Level INFO
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to update Service Task $TicketNumber status in ServiceNow: $ex. Body: $jsonBody" -Level 'ERROR'
    }
}

function Get-SalesforceJWTToken { # Specific to Copilot.ps1
    # $StorageAccountSubscription, $StorageAccountNameRSG, $storageAccountName are global
    # $SalesforceCertContainer, $SalesforceCertBlobName, $SalesforceCertKeyVaultName, $SalesforceCertPasswordSecretName are from config
    # $SalesforceClientId, $SalesforceUsername, $SalesforceAudienceUrl, $SalesforceTokenUrl are from config
    
    $certificateDir = 'D:\Temp\SF_Cert' # Consider $env:TEMP or configurable path
    if (!(Test-Path $certificateDir)) { New-Item -ItemType Directory -Force -Path $certificateDir }

    try {
        $azSfContext = Set-AzContext -Subscription $StorageAccountSubscription -ErrorAction Stop # Use specific context for this op
        $storageAccountSf = Get-AzStorageAccount -ResourceGroupName $StorageAccountNameRSG -Name $storageAccountName -DefaultProfile $azSfContext -ErrorAction Stop
        $storageAccountContextSf = $storageAccountSf.Context
        Get-AzStorageBlobContent -Container $SalesforceCertContainer -Blob $SalesforceCertBlobName -Destination $certificateDir -Context $storageAccountContextSf -Force -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to download Salesforce certificate '$SalesforceCertBlobName' from '$SalesforceCertContainer': $($_.Exception.Message)" -Level 'ERROR'
        ScriptError "Failed to download Salesforce certificate."
        return $null
    }

    $certificatePath = Join-Path $certificateDir $SalesforceCertBlobName
    try {
        $certificatePassword = Get-AzKeyVaultSecret -VaultName $SalesforceCertKeyVaultName -Name $SalesforceCertPasswordSecretName -AsPlainText -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to retrieve Salesforce certificate password from Key Vault '$SalesforceCertKeyVaultName': $($_.Exception.Message)" -Level 'ERROR'
        ScriptError "Failed to retrieve Salesforce certificate password."
        return $null
    }

    try {
        $securePassword = ConvertTo-SecureString -String $certificatePassword -AsPlainText -Force
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    }
    catch {
        Write-Log "Failed to load Salesforce certificate from '$certificatePath': $($_.Exception.Message)" -Level 'ERROR'
        ScriptError "Failed to load Salesforce certificate."
        return $null
    }

    $header = @{ alg = 'RS256' }
    $expiryDate = [math]::Round((Get-Date).AddMinutes(5).Subtract((Get-Date '1970-01-01')).TotalSeconds) # Shorten expiry to 5 mins
    $claimset = @{ iss = $SalesforceClientId; prn = $SalesforceUsername; aud = $SalesforceAudienceUrl; exp = $expiryDate }

    try {
        $headerJson = $header | ConvertTo-Json -Compress
        $claimsetJson = $claimset | ConvertTo-Json -Compress
        $headerEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $claimsetEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($claimsetJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $inputToken = "$headerEncoded.$claimsetEncoded"
        $signatureBytes = $certificate.PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($inputToken), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $signatureEncoded = [System.Convert]::ToBase64String($signatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $jwt = "$headerEncoded.$claimsetEncoded.$signatureEncoded"
    }
    catch {
        Write-Log "Failed to create or sign JWT for Salesforce: $($_.Exception.Message)" -Level 'ERROR'
        ScriptError "JWT creation/signing failed for Salesforce."
        return $null
    }

    $bodySFAuth = @{ 'assertion' = $jwt; 'grant_type' = 'urn:ietf:params:oauth:grant-type:jwt-bearer' }
    try {
        $responseString = Invoke-RestMethod -Uri $SalesforceTokenUrl -Method Post -Body $bodySFAuth -ContentType 'application/x-www-form-urlencoded'
        $token = ($responseString | ConvertFrom-Json).access_token
        return $token
    }
    catch {
        Write-Log "Failed to get Salesforce token from '$SalesforceTokenUrl': $($_.Exception.Response.GetResponseStream() | ForEach-Object {(New-Object System.IO.StreamReader($_)).ReadToEnd()})" -Level 'ERROR'
        ScriptError "Salesforce token request failed."
        return $null
    }
}

function Invoke-SalesforceCase { # Specific to Copilot.ps1
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserName,
        [Parameter(Mandatory = $false)]
        [string]$UserNTID
    )
    # $SalesforceApiUrl, $SalesforceMTLID are global from config
    $token = Get-SalesforceJWTToken
    if (-not $token) {
        ScriptError "Cannot create Salesforce case for $UserName, failed to get JWT token."
        return $null
    }
    $headers = @{ 'Sforce-Auto-Assign' = 'false'; 'Content-Type' = 'application/json'; 'Authorization' = "Bearer $token" }
    $sanitizedName = $UserName.Normalize([Text.NormalizationForm]::FormD) -replace '\p{Mn}', '' -replace ',', '' -replace '\s{2,}', ' '
    $body = @{ WheredoyousitinBP = '1'; ActionRequired = 'Add Learners'; MTLID = $SalesforceMTLID; User1 = $sanitizedName; NTIDUser1 = $UserNTID } | ConvertTo-Json

    try {
        $LappTicketNumber = Invoke-RestMethod -Uri $SalesforceApiUrl -Headers $headers -Method Post -Body $body -ErrorAction Stop
        Write-Log "Salesforce LApp case created for $UserName ($UserNTID): $LappTicketNumber" -Level INFO
        return $LappTicketNumber
    }
    catch {
        $errorDetails = $_.Exception.Response.GetResponseStream() | ForEach-Object {(New-Object System.IO.StreamReader($_)).ReadToEnd()}
        Write-Log "Error creating Salesforce case for $UserName ($UserNTID). Body: $body. Error: $errorDetails" -Level 'ERROR'
        ScriptError "Error while raising LApp case: $errorDetails"
        return $null
    }
}

Function Invoke-sqlquery { # Shared, seemingly identical
    param(
        $qry
    )
    try{
        Invoke-Sqlcmd -ServerInstance "$sqlsvr" -Database "$sqldb" -Username "$sqluser" -Password "$sqlpass" -Query "$qry" -ErrorAction Stop -QueryTimeout 60
    }catch{
        $ErrorMessage = $_.Exception.Message
        Write-Log "SQL Query failed: $qry. Error: $ErrorMessage" -Level 'ERROR'
        # ScriptError("Error while running SQL query: $ErrorMessage") # Let caller handle if it's critical
        throw "SQL Query failed: $ErrorMessage" # Throw to allow critical path to stop
    }
}

# Functions from E1-E5.ps1
function Invoke-UpgradeToE5 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPNForE5 = $UserUPN # Default to global $UserUPN if not specified
    )

    $script:saviyntRequestReferenceIDs = $null # Reset for this operation

    $bodyToken = @{ client_id = $Saviynt_Oauth_ClientID; client_secret = $Saviynt_Oauth_Secret; grant_type = 'client_credentials'; scope = "$SaviyntApiScope/.default" }
    $uriToken = "https://login.microsoftonline.com:443/$tenantId/oauth2/v2.0/token"
    try { $bearer = Invoke-RestMethod -Method POST -Uri $uriToken -Body $bodyToken }
    catch { Write-Log "Saviynt OAuth token failed: $($_.Exception.Message)" -Level ERROR; ScriptError "Saviynt OAuth token failed."; return }

    $bodyUserLookup = @{ customproperty16 = $UserUPNForE5; max = 100; offset = 0 }
    $headerUserLookup = @{ 'Content-Type' = 'application/x-www-form-urlencoded'; Authorization = "Bearer $($bearer.access_token)" }
    $paramsUserLookup = @{ method = 'GET'; uri = "$SaviyntApiBaseUrl/identity-api/v1/users"; headers = $headerUserLookup; body = $bodyUserLookup }
    try { $result = Invoke-RestMethod @paramsUserLookup -ErrorAction Stop }
    catch { Write-Log "Saviynt user lookup for $UserUPNForE5 failed: $($_.Exception.Message)" -Level ERROR; ScriptError "Saviynt user lookup failed."; return }

    Write-Log "Saviynt user lookup attributes for $UserUPNForE5: $($result.attributes | ConvertTo-Json -Depth 3)" -Level DEBUG
    $BPIdentityAPITransactionID = (New-Guid).Guid -replace '-[a-f|0-9]{12}$'
    $ExceptionErrorCode = "GenericError" # Default

    if (!([string]::IsnullOrEmpty($result.attributes))) {
        Write-Log "Saviynt record found for user $UserUPNForE5." -Level INFO
        $saviyntUserSystemName = $result.attributes.systemUserName.value

        # Check current Saviynt attributes against target E5 attributes (from Dataverse config)
        if ((($result.attributes.customproperty65.value).ToLower() -eq $E1_attributes65.ToLower()) -or (($result.attributes.customproperty65.value).ToLower() -eq $E1_customproperty65.ToLower())) {
            if ((($result.attributes.customproperty53.value).ToLower() -eq $E5_customproperty53_false.ToLower()) -or (!$result.attributes.customproperty53.value) -or (($result.attributes.customproperty63.value).ToLower() -ne $E5_customproperty63.ToLower())) {
                Write-Log "User $UserUPNForE5 does not have E5 attributes in Saviynt. Requesting E5 uplift." -Level INFO
                $headerUpdate = @{ 'Content-Type' = 'application/json'; Authorization = "Bearer $($bearer.access_token)"; client_id = $Saviynt_ClientID; client_secret = $Saviynt_Secret; 'BP-IdentityAPI-TransactionID' = "DWP-$BPIdentityAPITransactionID" }
                $bodyUpdate = @{ attributes = @{ customproperty53 = @{ value = $E5_customproperty53_true }; customproperty63 = @{ value = $E5_customproperty63 } } }
                $paramsUpdate = @{ method = 'PUT'; uri = "$SaviyntApiBaseUrl/identity-api/v1/async/users/$saviyntUserSystemName"; headers = $headerUpdate; body = ($bodyUpdate | ConvertTo-Json) }
                
                try { $TransactionResponse = Invoke-RestMethod @paramsUpdate -ErrorAction Stop }
                catch { Write-Log "Saviynt E5 uplift request for $UserUPNForE5 failed: $($_.Exception.Message)" -Level ERROR; ScriptError "Saviynt E5 uplift request failed."; return }
                
                $TransactionID = $TransactionResponse.TRACKING_ID
                Write-Log "Saviynt E5 uplift request for $UserUPNForE5 logged. Tracking ID: $TransactionID" -Level INFO
                
                # Optionally check status, E1-E5 script did this, but it might be async and not reflect immediately
                # For now, assume request is submitted. Replication check later is key.
                $ExceptionErrorCode = 'Success' # Indicates Saviynt request submitted
            } else {
                Write-Log "Saviynt record for $UserUPNForE5 shows E5 attributes already set, but M365 license not reflected." -Level WARN
                $ShortDesc = "Failure; M365 E5 Upgrade - Saviynt/M365 Mismatch for $UserUPNForE5"
                $Description = "Saviynt shows E5 attributes for $UserUPNForE5, but M365 license is not E5. Investigate. Transaction ID: $BPIdentityAPITransactionID"
                $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE5 -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
                Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "Saviynt/M365 E5 mismatch for $UserUPNForE5. SNOW Task $ticket created."
                $ExceptionErrorCode = "SaviyntE5TrueM365False-$ticket"
            }
        } else {
            Write-Log "Saviynt customproperty65 for $UserUPNForE5 not set correctly for E5 upgrade. Current: $($result.attributes.customproperty65.value)" -Level WARN
            $ShortDesc = "Failure; M365 E5 Upgrade - Incorrect Saviynt Mailbox Info for $UserUPNForE5"
            $Description = "Saviynt customproperty65 for $UserUPNForE5 (Mailbox Type) is not suitable for E5 upgrade. Current: $($result.attributes.customproperty65.value). Investigate. Transaction ID: $BPIdentityAPITransactionID"
            $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE5 -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
            Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "Incorrect Saviynt mailbox info for $UserUPNForE5 for E5 upgrade. SNOW Task $ticket created."
            $ExceptionErrorCode = "EmptyCustomproperty65-$ticket"
        }
    } else {
        Write-Log "Saviynt user record not found for $UserUPNForE5 during E5 upgrade." -Level WARN
        $ShortDesc = "Failure; M365 E5 Upgrade - User Not Found in Saviynt for $UserUPNForE5"
        $Description = "Saviynt user record not found for $UserUPNForE5. Cannot process E5 upgrade. Investigate. Transaction ID: $BPIdentityAPITransactionID"
        $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE5 -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
        Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "User $UserUPNForE5 not found in Saviynt for E5 upgrade. SNOW Task $ticket created."
        $ExceptionErrorCode = "SaviyntNoUserRecord-$ticket"
    }

    $script:saviyntRequestReferenceIDs = [PSCustomObject]@{
        trackingID       = if($TransactionID){$TransactionID}else{$null}
        APITransactionID = $BPIdentityAPITransactionID
        ExitCode         = $ExceptionErrorCode
        SnowTaskNumber   = if($ticket){$ticket}else{$null}
    }
}

function Invoke-DowngradeToE1 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPNForE1 = $UserUPN # Default to global $UserUPN
    )
    $script:saviyntRequestReferenceIDs = $null # Reset

    $bodyToken = @{ client_id = $Saviynt_Oauth_ClientID; client_secret = $Saviynt_Oauth_Secret; grant_type = 'client_credentials'; scope = "$SaviyntApiScope/.default" }
    $uriToken = "https://login.microsoftonline.com:443/$tenantId/oauth2/v2.0/token"
    try { $bearer = Invoke-RestMethod -Method POST -Uri $uriToken -Body $bodyToken }
    catch { Write-Log "Saviynt OAuth token failed for E1 downgrade: $($_.Exception.Message)" -Level ERROR; ScriptError "Saviynt OAuth token failed (E1 downgrade)."; return }
    
    $bodyUserLookup = @{ customproperty16 = $UserUPNForE1; max = 100; offset = 0 }
    $headerUserLookup = @{ 'Content-Type' = 'application/x-www-form-urlencoded'; Authorization = "Bearer $($bearer.access_token)" }
    $paramsUserLookup = @{ method = 'GET'; uri = "$SaviyntApiBaseUrl/identity-api/v1/users"; headers = $headerUserLookup; body = $bodyUserLookup }
    try { $result = Invoke-RestMethod @paramsUserLookup -ErrorAction Stop }
    catch { Write-Log "Saviynt user lookup for $UserUPNForE1 (E1 downgrade) failed: $($_.Exception.Message)" -Level ERROR; ScriptError "Saviynt user lookup failed (E1 downgrade)."; return }

    Write-Log "Saviynt user lookup attributes for $UserUPNForE1 (E1 downgrade): $($result.attributes | ConvertTo-Json -Depth 3)" -Level DEBUG
    $BPIdentityAPITransactionID = (New-Guid).Guid -replace '-[a-f|0-9]{12}$'
    $ExceptionErrorCode = "GenericError"

    if (!([string]::IsnullOrEmpty($result.attributes))) {
        Write-Log "Saviynt record found for user $UserUPNForE1 (E1 downgrade)." -Level INFO
        $saviyntUserSystemName = $result.attributes.systemUserName.value

        # Check if user has E5 attributes to downgrade from
        if ((($result.attributes.customproperty53.value).ToLower() -eq $E5_customproperty53_true.ToLower()) -or (($result.attributes.customproperty63.value).ToLower() -eq $E5_customproperty63.ToLower())) {
            Write-Log "User $UserUPNForE1 has E5 attributes in Saviynt. Requesting E1 downgrade." -Level INFO
            $headerUpdate = @{ 'Content-Type' = 'application/json'; Authorization = "Bearer $($bearer.access_token)"; client_id = $Saviynt_ClientID; client_secret = $Saviynt_Secret; 'BP-IdentityAPI-TransactionID' = "DWP-devhub-$BPIdentityAPITransactionID" } # Original E1-E5 used DW-devhub prefix
            $bodyUpdate = @{ attributes = @{ customproperty53 = @{ value = $E1_customproperty53 }; customproperty63 = @{ value = $E1_customproperty63 } } }
            $paramsUpdate = @{ method = 'PUT'; uri = "$SaviyntApiBaseUrl/identity-api/v1/async/users/$saviyntUserSystemName"; headers = $headerUpdate; body = ($bodyUpdate | ConvertTo-Json) }

            try { $TransactionResponse = Invoke-RestMethod @paramsUpdate -ErrorAction Stop }
            catch { Write-Log "Saviynt E1 downgrade request for $UserUPNForE1 failed: $($_.Exception.Message)" -Level ERROR; ScriptError "Saviynt E1 downgrade request failed."; return }
            
            $TransactionID = $TransactionResponse.TRACKING_ID
            Write-Log "Saviynt E1 downgrade request for $UserUPNForE1 logged. Tracking ID: $TransactionID" -Level INFO
            $ExceptionErrorCode = 'Success'
        } else {
            Write-Log "Saviynt record for $UserUPNForE1 does not show E5 attributes; cannot downgrade or already E1/other. Current customproperty53: $($result.attributes.customproperty53.value), customproperty63: $($result.attributes.customproperty63.value)." -Level WARN
            # This might be a valid state if user is already E1 or never was E5. Consider if a SNOW task is always needed.
            # E1-E5 script created a task here assuming it was an error state ("Saviynt record shows user should have E5, but this is not reflected in M365" - this message seems for upgrade context)
            # For downgrade, if not E5, it might be okay. For now, log and treat as "no action needed from Saviynt"
            $ExceptionErrorCode = "NotE5InSaviyntNoDowngradeNeeded" 
            # $ShortDesc = "Info; M365 E1 Downgrade - User Not E5 in Saviynt for $UserUPNForE1"
            # $Description = "Saviynt record for $UserUPNForE1 does not show E5 attributes. Downgrade to E1 cannot proceed via Saviynt or may not be needed. Transaction ID: $BPIdentityAPITransactionID"
            # $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE1 -TicketType "ReplicationTask" # Or a different type
            # Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "User $UserUPNForE1 not E5 in Saviynt. SNOW Task $ticket created for review."
            # $ExceptionErrorCode = "SaviyntNotE5-$ticket"
        }
    } else {
        Write-Log "Saviynt user record not found for $UserUPNForE1 during E1 downgrade." -Level WARN
        $ShortDesc = "Failure; M365 E1 Downgrade - User Not Found in Saviynt for $UserUPNForE1"
        $Description = "Saviynt user record not found for $UserUPNForE1. Cannot process E1 downgrade. Investigate. Transaction ID: $BPIdentityAPITransactionID"
        $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE1 -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
        Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "User $UserUPNForE1 not found in Saviynt for E1 downgrade. SNOW Task $ticket created."
        $ExceptionErrorCode = "SaviyntNoUserRecord-$ticket"
    }
    $script:saviyntRequestReferenceIDs = [PSCustomObject]@{
        trackingID       = if($TransactionID){$TransactionID}else{$null}
        APITransactionID = $BPIdentityAPITransactionID
        ExitCode         = $ExceptionErrorCode
        SnowTaskNumber   = if($ticket){$ticket}else{$null}
    }
}

function Get-LicenseAllocationStatus { # From E1-E5.ps1 - Pre-check if user *already* has the target license
    param(
        [Parameter(Mandatory = $true)]
        [string]$emailID,
        [Parameter(Mandatory = $true)]
        [string]$action, # 'upgrade' (to E5) or 'downgrade' (to E1)
        [Parameter(Mandatory = $true)]
        [string]$LicenseType # Should be 'Microsoft365' for this function's original intent
    )
    # This function specifically checks if the TARGET state is ALREADY true.
    # e.g. if action is 'upgrade' (to E5), it checks if user already has E5.
    # if action is 'downgrade' (to E1), it checks if user already has E1.
    try {
        $licenses = Get-MgUserLicenseDetail -UserId $emailID
    } catch {
        Write-Log "Get-LicenseAllocationStatus: Error getting licenses for $emailID: $($_.Exception.Message)" -Level WARN
        return $false # Cannot confirm, assume not allocated
    }

    if ($action -eq 'downgrade') { # Target is E1
        if ($licenses.skupartnumber -contains 'STANDARDPACK') {
            Write-Log "User $emailID already has an E1 license (STANDARDPACK)." -Level INFO
            return $true # Already in target state for downgrade
        }
    } elseif ($action -eq 'upgrade') { # Target is E5
        if ($licenses.skupartnumber -contains 'SPE_E5') {
            Write-Log "User $emailID already has an E5 license (SPE_E5)." -Level INFO
            return $true # Already in target state for upgrade
        }
    } else {
        Write-Log "Invalid action '$action' specified in Get-LicenseAllocationStatus for $emailID." -Level WARN
        return $false
    }
    return $false # Not in target state
}

function Get-SnowAccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SnowURLForToken, # Not directly used in token endpoint but good for context/logging
        [Parameter(Mandatory = $true)]
        [string]$SnowApiScopeForToken, 
        [Parameter(Mandatory = $true)]
        [string]$SnowClientIdForToken,
        [Parameter(Mandatory = $true)]
        [string]$SnowClientSecretForToken
    )
    # $tenantId is a global variable, defined before this function is called.
    $tokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "$SnowApiScopeForToken/.default" # Append /.default to the scope as per OAuth2 client credentials flow
        Client_Id     = $SnowClientIdForToken
        Client_Secret = $SnowClientSecretForToken
    }
    $tokenUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    try {
        Write-Log "Attempting to get SNOW Access Token from $tokenUri for scope $SnowApiScopeForToken (Client ID: $SnowClientIdForToken)" -Level DEBUG
        $SnowTokenResponse = Invoke-RestMethod -Uri $tokenUri -Method POST -Body $tokenBody -ErrorAction Stop
        if ($SnowTokenResponse -and $SnowTokenResponse.access_token) {
            return $SnowTokenResponse.access_token
        } else {
            Write-Log "SNOW Access Token response did not contain an access_token. Response: $($SnowTokenResponse | ConvertTo-Json -Depth 3)" -Level ERROR
            throw "SNOW Access Token response did not contain an access_token."
        }
    } catch {
        $ex = $_.Exception.Message
        $errorDetails = "URI: $tokenUri. Body (secrets redacted for log): $(@{$tokenBody | Select-Object * -ExcludeProperty Client_Secret} | ConvertTo-Json -Compress)"
        Write-Log "Failed to get SNOW Access Token: $ex. $errorDetails" -Level ERROR
        throw "SNOW Access Token generation failed: $ex" # Re-throw to allow caller to handle critical failure
    }
}

##############################################
Write-Log 'COMBINED SCRIPT STARTED' -Level 'INFO'
##############################################

# Connect to Azure & MS Graph (common to both scripts)
Disable-AzContextAutosave -Scope Process | Out-Null
try {
    Connect-AzAccount -Identity -WarningAction Ignore | Out-Null
    Write-Log 'Azure Authentication Successful' -Level 'INFO'
}
catch {
    $ex = $_.Exception.Message; Write-Log "Azure Authentication failed: $ex" -Level 'ERROR'; exit
}
try {
    Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
    Write-Log 'MS Graph Authentication Successful' -Level 'INFO'
}
catch {
    $ex = $_.Exception.Message; Write-Log "MS Graph Authentication Failed: $ex" -Level 'ERROR'; exit
}

# SQL Server and DB details (common)
$sqlsvr = "ze1e2p3d301-dbserver-gu4ne.database.windows.net"
$sqldb = "ZE1E2P3D301-DB-7VI9S"
$tenantId = 'ea80952e-a476-42d4-aaf4-5457852b0f7e' # Common Tenant ID

# Automation Account based configuration
$AutomationAccountName = Get-AutomationVariable -Name 'AutomationAccountName'
# $AutomationAccountName = 'AA-DWP-NonProd' # For local testing override

switch ($AutomationAccountName) {
    'AA-DWP-NonProd' {
        $TestMode = $true
        # Azure Storage (Copilot templates, SOU reports, Salesforce cert)
        $StorageAccountSubscription = 'zne-evcs-n-dwp-sbc'
        $StorageAccountNameRSG = 'ZNE-EVCS-N-17-DWP-RSG'
        $StorageAccountName = 'zneevcsn17dwpappstg' # Used by Copilot Send-Email, Get-SOUCornerstoneReport, Get-SalesforceJWTToken
        $CopilotEmailTemplateContainer = 'copilot-license-allocation-email-templates' # Copilot Send-Email
        $SouReportContainer = 'copilot-sou-report-cornerstone' # Get-SOUCornerstoneReport
        
        # Dataverse
        $DataverseEnvironmentURL = 'https://orga8dae9a2.crm4.dynamics.com'
        $KeyvaultName = 'zne-dwp-n-kvl' # Primary KeyVault for this env
        $Copilot_GUID = '58586b15-2e27-ef11-840a-000d3ab44827' # Dataverse License_Category GUID
        $E1_GUID = '135f4d11-300d-ef11-9f8a-6045bd8865c3'      # Dataverse License_Category GUID
        $E5_GUID = 'db56a5c3-250d-ef11-9f89-000d3a222c58'      # Dataverse License_Category GUID

        # SNOW
        $SnowURL = 'https://bpdev.service-now.com' # E1-E5 was bptest, Copilot was bpdev. Standardizing to bpdev for NonProd.
        # $SNOW_Oauth_Token_KV_Name = 'SNOW-Oauth-Token-Test' # Copilot used ZSCEVCSP05MGMKVT vault, E1-E5 used Get-SnowAccessToken
        # For NonProd, let's try Get-SnowAccessToken if possible, requires App ID/Secret
        $snowclient_id_KV_Name = if($SnowURL -like "*bptest*") {'SNOW-Test-AppID'} else {'SNOW-Dev-AppID'} # From E1-E5 logic
        $snowclient_secret_KV_Name = if($SnowURL -like "*bptest*") {'SNOW-Test-Secret'} else {'SNOW-Dev-Secret'}
        $SnowApiScopeKV_Name = 'SNOW-Api-Scope-Test' # Assuming a KV entry for this, e.g. https://bpdev.service-now.com/api/snc/bp_rest_api

        # Email Utility (Copilot)
        $Email_AppID_KV_Name = 'DWP-DevHub-Email-AppID'
        $Email_Secret_KV_Name = 'DWP-DevHub-Email-Secret'
        $EmailUtilScope = 'c390e4a4-f797-4ef8-8d82-8ad8c5438743' # Copilot NonProd Scope
        $Email_URI = 'https://dwp-functions-dev.bpglobal.com/api/Email-Common-Utility'

        # Entra Group IDs (Copilot)
        $CopilotCompletedGroupID = '2dcedb7c-77ad-452b-9c64-6724aea37c76' # G O365 Copilot PoC users
        $CopilotPendingGroupID = '735c9f9c-b778-4020-94c8-e6a07d73bed7' # G AAD CoPilot M365 Pending License Users

        # SQL Credentials
        $sqluser_KV_Name = 'SQL-UserName-Licensingwrite'
        $sqlpass_KV_Name = 'SQL-Password-Licensingwrite'

        # Salesforce (Copilot)
        $SalesforceCertContainer = 'bau-license-allocation-process' # NonProd cert container
        $SalesforceCertBlobName = 'bpcolleagues.my.salesforce.com.pfx' # Assuming same PFX name, content differs by env
        $SalesforceCertKeyVaultName = 'zne-dwp-n-kvl' # Or specific SF KV if different
        $SalesforceCertPasswordSecretName = 'Salesforce-API-Cert-Key-Test' # Or appropriate secret name for NonProd cert
        $SalesforceClientId = '3MVG91LYYD8O4krRFZk502yUZjm5Gonr_Z_Mj8pL0DuEtyWnZSw_O_Ob2PxDzxiCH9tKQ1AFX6FiBoK3Cw5co' # Test
        $SalesforceUsername = 'pcsalesforce1@bp.com.colleagues.hrmtest'
        $SalesforceAudienceUrl = 'test.salesforce.com'
        $SalesforceTokenUrl = 'https://test.salesforce.com/services/oauth2/token'
        $SalesforceApiUrl = 'https://bpcolleagues--hrmtest.sandbox.my.salesforce.com/services/apexrest/createCaseRMS/'
        $SalesforceMTLID = '1000198'

        # Saviynt (E1-E5)
        $SaviyntApiBaseUrl = 'https://apis-001-nonprod.bpweb.bp.com/test' # $SavURL in E1-E5
        $SaviyntApiScope = 'https://api-001-nonprod.bpglobal.com/tst/ieeo-grpitsidentity/proxy/v1/' # Simplified scope base, append /.default later
        $Saviynt_Oauth_ClientID_KV_Name = 'SaviyntApi-TEST-Oauth-ClientID'
        $Saviynt_Oauth_Secret_KV_Name = 'SaviyntApi-TEST-Oauth-Secret'
        $Saviynt_ClientID_KV_Name = 'SaviyntApi-TEST-ClientID' # For direct client_id/secret usage in headers
        $Saviynt_Secret_KV_Name = 'SaviyntApi-TEST-Secret'
    }
    'AA-DWP-Prod' {
        $TestMode = $false
        $StorageAccountSubscription = 'zne-evcs-p-dwp-sbc'
        $StorageAccountNameRSG = 'ZNE-EVCS-P-27-DWP-RSG'
        $StorageAccountName = 'zneevcspdwpstg'
        $CopilotEmailTemplateContainer = 'copilot-license-allocation-email-templates'
        $SouReportContainer = 'copilot-sou-report-cornerstone' # Prod SOU report container

        $DataverseEnvironmentURL = 'https://orgee396095.crm4.dynamics.com'
        $KeyvaultName = 'zne-dwp-p-kvl'
        $Copilot_GUID = '58586b15-2e27-ef11-840a-000d3ab44827' # Prod GUID
        $E1_GUID = '52bf2013-2e27-ef11-840a-000d3a660d83'      # Prod GUID
        $E5_GUID = '54586b15-2e27-ef11-840a-000d3ab44827'      # Prod GUID

        $SnowURL = 'https://bp.service-now.com'
        $SNOW_Oauth_Token_KV_Name = 'SNOW-Oauth-Token' # Direct Token for Prod from ZSCEVCSP05MGMKVT
        # $snowclient_id_KV_Name, $snowclient_secret_KV_Name not typically used for Prod if direct token is available
        $SnowApiScopeKV_Name = 'SNOW-Api-Scope-Prod' # e.g. https://bp.service-now.com/api/snc/bp_rest_api

        $Email_AppID_KV_Name = 'DWP-DevHub-Email-AppID' # Ensure these are Prod values in KV
        $Email_Secret_KV_Name = 'DWP-DevHub-Email-Secret'
        $EmailUtilScope = '00c59037-c0c7-4637-9ba7-2b6b98cff3b5' # Copilot Prod Scope
        $Email_URI = 'https://dwp-functions.bpglobal.com/api/Send-GraphEmailApi'

        $CopilotCompletedGroupID = 'ffe25b27-0c4a-418e-b2f4-52562b038b89' # G O365 Copilot EAP Pilot users
        $CopilotPendingGroupID = '735c9f9c-b778-4020-94c8-e6a07d73bed7'

        $sqluser_KV_Name = 'SQL-LicensingWrite-UserName' # Prod SQL creds
        $sqlpass_KV_Name = 'SQL-LicensingWrite-Password'

        $SalesforceCertContainer = 'bau-license-allocation-process' # Prod cert container
        $SalesforceCertBlobName = 'bpcolleagues.my.salesforce.com.pfx' # Prod PFX
        $SalesforceCertKeyVaultName = 'zne-dwp-p-kvl' 
        $SalesforceCertPasswordSecretName = 'Salesforce-API-Cert-Key' # Prod cert password
        $SalesforceClientId = '3MVG95NPsF2gwOiMXVE8sXplWeRSDv9Y5kUjPN13fh69vyD2H__M0uLCe1s4J.KVNUVC3wapNcAOcC1BPO009' # Prod
        $SalesforceUsername = 'pcsalesforcecopilot1@bp.com.colleagues'
        $SalesforceAudienceUrl = 'login.salesforce.com'
        $SalesforceTokenUrl = 'https://login.salesforce.com/services/oauth2/token'
        $SalesforceApiUrl = 'https://bpcolleagues.my.salesforce.com/services/apexrest/createCaseRMS/'
        $SalesforceMTLID = '908547'

        $SaviyntApiBaseUrl = 'https://apis.bpglobal.com' # $SavURL Prod
        $SaviyntApiScope = 'https://api-001.bpglobal.com/ieeo-grpitsidentity/proxy/v1/' # Prod scope base
        $Saviynt_Oauth_ClientID_KV_Name = 'SaviyntApi-Oauth-ClientID'
        $Saviynt_Oauth_Secret_KV_Name = 'SaviyntApi-Oauth-Secret'
        $Saviynt_ClientID_KV_Name = 'SaviyntApi-ClientID'
        $Saviynt_Secret_KV_Name = 'SaviyntApi-Secret'
    }
    Default {
        ScriptError "AutomationAccountName '$AutomationAccountName' is not recognized. Exiting."
        exit
    }
}
if ($TestMode) { Write-Output "TESTMODE ENABLED via AutomationAccountName: $AutomationAccountName" }

# Fetch secrets from KeyVault based on environment
try {
    Set-AzContext -Subscription $StorageAccountSubscription -ErrorAction Stop # Set context for KV access if needed, or rely on Connect-AzAccount's default
    $Dataverse_AppID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Dataverse-AppID' -AsPlainText
    $Dataverse_ClientSecret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Dataverse-ClientSecret' -AsPlainText
    $sqluser = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $sqluser_KV_Name -AsPlainText
    $sqlpass = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $sqlpass_KV_Name -AsPlainText

    $Email_AppID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $Email_AppID_KV_Name -AsPlainText
    $Email_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $Email_Secret_KV_Name -AsPlainText
    
    # SNOW Authentication: Prioritize Get-SnowAccessToken for NonProd, direct token for Prod
    if ($AutomationAccountName -eq 'AA-DWP-Prod') {
        $SNOW_Oauth_Token = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name $SNOW_Oauth_Token_KV_Name -AsPlainText
        Write-Log "Successfully fetched SNOW_Oauth_Token directly from KeyVault for Prod." -Level INFO
    } else { # NonProd - use AppID/Secret for token via Get-SnowAccessToken
        Write-Log "Attempting to fetch SNOW client ID, secret, and scope from KeyVault for NonProd." -Level DEBUG
        $kvSnowClientId = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name $snowclient_id_KV_Name -AsPlainText 
        $kvSnowClientSecret = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name $snowclient_secret_KV_Name -AsPlainText
        $kvSnowApiScope = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name $SnowApiScopeKV_Name -AsPlainText # Example: "https://bpdev.service-now.com/api/snc/bp_rest_api"
        
        if ($kvSnowClientId -and $kvSnowClientSecret -and $kvSnowApiScope) {
            Write-Log "Successfully fetched SNOW client credentials and scope from KeyVault for NonProd. Now calling Get-SnowAccessToken for $SnowURL with scope $kvSnowApiScope." -Level INFO
            try {
                $SNOW_Oauth_Token = Get-SnowAccessToken -SnowURLForToken $SnowURL -SnowApiScopeForToken $kvSnowApiScope -SnowClientIdForToken $kvSnowClientId -SnowClientSecretForToken $kvSnowClientSecret
                 if ($SNOW_Oauth_Token) {
                    Write-Log "Successfully obtained SNOW_Oauth_Token via Get-SnowAccessToken for NonProd." -Level INFO
                } else {
                    # This case should ideally not be reached if Get-SnowAccessToken throws on failure and is caught.
                    ScriptError -msg "Get-SnowAccessToken returned null/empty token for NonProd, and did not throw an exception that was caught."
                }
            } catch {
                 $DetailedErrorMessage = "Failed to obtain SNOW_Oauth_Token via Get-SnowAccessToken for NonProd. Error: $($_.Exception.Message). Check KeyVault values for $snowclient_id_KV_Name, $snowclient_secret_KV_Name, $SnowApiScopeKV_Name in ZSCEVCSP05MGMKVT and ensure the Entra App Registration is correct."
                 ScriptError -msg $DetailedErrorMessage
                 # SNOW_Oauth_Token will remain null, subsequent SNOW operations will likely fail.
            }
        } else {
            $missingSnowCreds = "Missing one or more SNOW credentials from KeyVault ZSCEVCSP05MGMKVT for NonProd. Cannot generate SNOW token. "
            if(-not $kvSnowClientId) {$missingSnowCreds += "Missing: $snowclient_id_KV_Name. "}
            if(-not $kvSnowClientSecret) {$missingSnowCreds += "Missing: $snowclient_secret_KV_Name. "}
            if(-not $kvSnowApiScope) {$missingSnowCreds += "Missing: $SnowApiScopeKV_Name. "}
            ScriptError -msg $missingSnowCreds
        }
    }
    # Critical check for SNOW token after attempting to fetch/generate it.
    if(-not $SNOW_Oauth_Token) {
        ScriptError -msg "SNOW_Oauth_Token is NOT available after configuration attempts. SNOW-dependent operations will fail. This is a critical failure. Please check previous logs for specific errors in token retrieval or generation."
        # Consider adding 'exit' here if script cannot function without SNOW token.
        # For now, ScriptError logs it, and script would continue, but SNOW calls would fail.
        # Adding an explicit exit for such a critical dependency:
        Write-Log "CRITICAL FAILURE: SNOW_Oauth_Token could not be obtained. Exiting script." -Level ERROR
        exit 1
    }

    # Saviynt Credentials
    $Saviynt_Oauth_ClientID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $Saviynt_Oauth_ClientID_KV_Name -AsPlainText
    $Saviynt_Oauth_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $Saviynt_Oauth_Secret_KV_Name -AsPlainText
    $Saviynt_ClientID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $Saviynt_ClientID_KV_Name -AsPlainText
    $Saviynt_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $Saviynt_Secret_KV_Name -AsPlainText
}
catch {
    $ex = $_.Exception.Message
    ScriptError -msg "Failed to get critical secrets from KeyVault '$KeyvaultName': $ex"
    exit
}

# Dataverse Authentication
$tokenBodyDV = @{ grant_type = 'client_credentials'; client_id = $Dataverse_AppID; client_secret = $Dataverse_ClientSecret; resource = $DataverseEnvironmentURL }
try {
    $tokenResponseDV = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -Method Post -Body $tokenBodyDV -ContentType 'application/x-www-form-urlencoded'
    $accessTokenDV = $tokenResponseDV.access_token
}
catch { $ex = $_.Exception.Message; ScriptError -msg "Failed to get Dataverse access token: $ex"; exit }

$Dataverseheaders = @{ Authorization = "Bearer $accessTokenDV"; 'Content-Type' = 'application/json'; 'OData-MaxVersion' = '4.0'; 'OData-Version' = '4.0'; Accept = 'application/json' }
$lic_category_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/crd15_license_categories"
$lic_attr_map_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/new_license_attribute_mappings"
$lic_queue_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/new_license_queue_requests"

try {
    $lic_category_response_details = (Invoke-RestMethod -Uri $lic_category_apiUrl -Headers $Dataverseheaders -Method Get).value
    
    # E1-E5 specific Dataverse attribute mappings
    $lic_attr_map_response_details_all = (Invoke-RestMethod -Uri $lic_attr_map_apiUrl -Headers $Dataverseheaders -Method Get).value
    $E1_customproperty53 = ($lic_attr_map_response_details_all | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E1_GUID) -and ($_.new_name -eq 'customproperty53') }).new_Value
    $E1_customproperty65 = ($lic_attr_map_response_details_all | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E1_GUID) -and ($_.new_name -eq 'customproperty65') }).new_Value
    $E1_customproperty63 = ($lic_attr_map_response_details_all | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E1_GUID) -and ($_.new_name -eq 'customproperty63') }).new_Value
    $E1_attributes65 = ($lic_attr_map_response_details_all | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E1_GUID) -and ($_.new_name -eq 'attributes65') }).new_Value
    $E5_customproperty63 = ($lic_attr_map_response_details_all | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E5_GUID) -and ($_.new_name -eq 'customproperty63') }).new_Value
    $E5_customproperty53_true = ($lic_attr_map_response_details_all | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E5_GUID) -and ($_.new_name -eq 'customproperty53_true') }).new_Value
    $E5_customproperty53_false = ($lic_attr_map_response_details_all | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E5_GUID) -and ($_.new_name -eq 'customproperty53_false') }).new_Value
}
catch { $ex = $_.Exception.Message; ScriptError -msg "Failed to get Dataverse config (categories/attributes): $ex"; exit }


# Fetch all messages from DB
try {
    $dbmessagesAll = Invoke-Sqlquery -qry "Select * from Licensing_Dev.LicenseRequestView where status in ('New', 'In-Progress','Pending Training','On-Hold')"
} catch { ScriptError('Failed to fetch messages from DB.'); exit }

$numberOfMessagesTotal = $dbmessagesAll.count
Write-Log "Total messages fetched from DB: $numberOfMessagesTotal" -Level 'INFO'

# Initialize Cornerstone SOU Report Path (Copilot specific)
$CSODReportPath = $null
if ($AutomationAccountName -ne $null) { # Check if we need to run Copilot logic which requires this
    Write-Log "Attempting to download SOU Cornerstone Report..." -Level INFO
    $CSODReportPath = Get-SOUCornerstoneReport # This function now uses $SouReportContainer
    if (-not $CSODReportPath) {
        Write-Log "SOU Cornerstone Report could not be obtained. Copilot SOU checks will likely fail." -Level WARN
        # ScriptError might be too severe here if only E1/E5 licenses are processed in a run.
        # Functions using it should handle $null path.
    } else {
        Write-Log "SOU Cornerstone Report obtained at: $CSODReportPath" -Level INFO
    }
}


$ThisRunProcessedCopilot = 0
$ThisRunProcessedE1E5 = 0
$ProcessCutoffCopilot = if($TestMode) {10} else {1000} # Example: Higher limit for Copilot Prod
$ProcessCutoffE1E5 = if($TestMode) {5} else {100}    # Example: Lower limit for E1/E5 Prod

$i = 0
foreach ($messageString in $dbmessagesAll) {
    $i++
    Write-Log "########################## PROCESSING MESSAGE $i OF $numberOfMessagesTotal ##########################" -Level 'INFO'
    Start-Sleep -Seconds 1 # Small delay between messages

    # Reset message-specific variables
    $saviyntRequestReferenceIDs = $null # Crucial for E1/E5 logic
    $LAppCase = $null # Reset LAppCase from previous iteration

    # Extract common message properties
    $ID = $messageString.ID; $Status = $messageString.Status; $userUPN = $messageString.UserUPN; $RequestedBy = $messageString.RequestedBy
    $LicenseType = $messageString.LicenseType; $action = $messageString.Action; $RequestedSource = $messageString.RequestSource
    $RITMNumber = $messageString.RITMNumber; $TaskNumber = $messageString.TaskNumber; $RequestedDate = $messageString.RequestedDate
    $ProcessedDate = $messageString.ProcessedDate; $EmailSentCount = [int]$messageString.EmailSentCount; $EmailSentDate = $messageString.EmailSentDate
    $LAppCase = $messageString.LAppCase; $LAppCaseCreatedDate = $messageString.LAppCaseCreatedDate
    $SOUAgreedDate = $messageString.SOUAgreedDate # Copilot specific
    # E1-E5 specific fields from DB (if they exist in view)
    $SaviyntTrackIDFromDB = $messageString.SaviyntTrackID
    $SaviyntTransactionIDFromDB = $messageString.saviyntTransactionID
    $SaviyntExitCodeFromDB = $messageString.saviyntExitCode
    $SnowTicketNumberFromDB = $messageString.snowTicketNumber
    
    # Convert date strings from DB to DateTime objects if necessary for comparisons
    if ($LAppCaseCreatedDate -is [string] -and -not([string]::IsNullOrWhiteSpace($LAppCaseCreatedDate))) { $LAppCaseCreatedDate = Convert-ToDateTime $LAppCaseCreatedDate }
    if ($ProcessedDate -is [string] -and -not([string]::IsNullOrWhiteSpace($ProcessedDate))) { $ProcessedDate = Convert-ToDateTime $ProcessedDate }


    Write-Log "Processing UPN: $userUPN, LicenseType: $LicenseType, Action: $action, RITM: $RITMNumber, Task: $TaskNumber, DB_ID: $ID" -Level 'INFO'

    # Determine License Categorization ID for Dataverse logging
    $licenseCategorizationID = $null
    if ($action -eq 'downgrade') { # E1
        $licenseCategorizationID = ($lic_category_response_details | Where-Object { $_.new_sub_category -eq 'E1' -and $_._new_parentcategoryid_value -ne $null }).crd15_License_CategoryId # Assuming E1 is a sub-category
        if(-not $licenseCategorizationID) { $licenseCategorizationID = $E1_GUID } # Fallback to direct GUID
    } elseif ($action -eq 'upgrade') {
        if ($LicenseType -eq 'Microsoft365') { # E5
            $licenseCategorizationID = ($lic_category_response_details | Where-Object { $_.new_sub_category -eq 'E5' -and $_._new_parentcategoryid_value -ne $null }).crd15_License_CategoryId
            if(-not $licenseCategorizationID) { $licenseCategorizationID = $E5_GUID }
        } elseif ($LicenseType -eq 'MicrosoftCopilot') {
            $licenseCategorizationID = ($lic_category_response_details | Where-Object { $_.new_sub_category -eq 'Copilot' -and $_._new_parentcategoryid_value -ne $null }).crd15_License_CategoryId
            if(-not $licenseCategorizationID) { $licenseCategorizationID = $Copilot_GUID }
        }
    }
    if (-not $licenseCategorizationID) {
        Write-Log "Could not determine License Categorization ID for $LicenseType ($action). Using a placeholder if available or logging might fail." -Level WARN
        # Attempt to find a generic one or use a known default if critical
        if ($LicenseType -eq 'MicrosoftCopilot') {$licenseCategorizationID = $Copilot_GUID}
        elseif ($LicenseType -eq 'Microsoft365' -and $action -eq 'upgrade') {$licenseCategorizationID = $E5_GUID}
        elseif ($LicenseType -eq 'Microsoft365' -and $action -eq 'downgrade') {$licenseCategorizationID = $E1_GUID}
        else { Write-Log "FATAL: Unknown license categorization for $LicenseType and $action." -Level ERROR; continue}
    }


    # Basic User Validation (common pre-check)
    $UserExists = $null; $UserEnabled = $false
    try {
        $MgUser = Get-MgUser -UserId $userUPN -Property "AccountEnabled, Id, UserPrincipalName, DisplayName, OnPremisesExtensionAttributes, onPremisesSamAccountName" -ErrorAction Stop
        $UserExists = $true; $UserEnabled = $MgUser.AccountEnabled
        Write-Log "User $userUPN exists in Entra. Enabled: $UserEnabled." -Level INFO
    } catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -like '*Request_ResourceNotFound*') {
            Write-Log "User $userUPN not found in Entra." -Level WARN
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 5, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Invalid user in Entra (Not Found)' WHERE ID = $ID;"
            # Dataverse Log for not found user (simplified ScriptError call)
            ScriptError -msg "User $userUPN not found in Entra." -UserUPNForError $userUPN -LicenseTypeForError $LicenseType -RITMNumberForError $RITMNumber # etc.
            Update-TaskStatus -TicketNumber $TaskNumber -State '9' -WorkNotes "User $userUPN not found in Entra. Request cancelled." # E1E5 logic
            continue
        } else {
            ScriptError -msg "Error validating user $userUPN in Entra: $errMsg"
            continue
        }
    }

    if (-not $UserEnabled) {
        Write-Log "User $userUPN account is disabled in Entra." -Level WARN
        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 5, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'User account disabled in Entra' WHERE ID = $ID;"
        ScriptError -msg "User $userUPN account disabled in Entra."
        Update-TaskStatus -TicketNumber $TaskNumber -State '9' -WorkNotes "User $userUPN account disabled in Entra. Request cancelled." # E1E5 logic
        continue
    }
    
    # RITM Status Check (common for active changes)
    if ($action -eq 'upgrade') { # Typically upgrades are tied to RITMs that need to be open
        $RITMInfo = Get-TicketStatus -TicketNumber $RITMNumber
        if ($RITMInfo) {
            $closedStateCodes = @('3', '4', '7', '9') # 3=Closed Complete, 4=Closed Incomplete, 7=Closed Skipped, 9=Cancelled (example states)
            if ($closedStateCodes -contains $RITMInfo.state) {
                Write-Log "RITM $RITMNumber for $userUPN is already closed (State: $($RITMInfo.state), Stage: $($RITMInfo.stage)). Skipping request." -Level INFO
                Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'RITM already closed' WHERE ID = $ID;"
                # Dataverse log for RITM closed
                $completionTimeClosedRitm = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                $dvBodyClosedRitm = @{
                    new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                    new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $ProcessedDate; new_completiontime = $completionTimeClosedRitm
                    new_lappcasenumber = $LAppCase; new_status = 'Aborted'; new_errorcode = 'RITM already closed'
                } | ConvertTo-Json
                Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dvBodyClosedRitm
                continue
            }
        } else {
            Write-Log "Could not retrieve RITM $RITMNumber status for $userUPN. Proceeding with caution." -Level WARN
        }
    }


    # LicenseType specific processing
    if ($LicenseType -eq 'MicrosoftCopilot') {
        Write-Log "Processing MicrosoftCopilot license for $userUPN" -Level INFO
        if ($ThisRunProcessedCopilot -ge $ProcessCutoffCopilot) {
            Write-Log "Copilot processing cutoff ($ProcessCutoffCopilot) reached for this run. Skipping $userUPN." -Level INFO
            continue
        }
        $ThisRunProcessedCopilot++

        if ($action -ne "upgrade") {
            Write-Log "Action '$action' is not 'upgrade' for Copilot. Skipping $userUPN." -Level WARN
            # Potentially mark as error/clarification needed in DB?
            continue
        }

        # Copilot specific pre-checks (already has license?)
        $hasCopilotLicense = Get-SaviyntLicenseReplicationStatus -emailID $userUPN -action 'upgrade' -LicenseType 'MicrosoftCopilot'
        if ($hasCopilotLicense) {
            Write-Log "User $userUPN already has a Copilot license. Closing RITM/Task and DB record." -Level INFO
            Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes 'User already has Copilot license. Request completed.'
            Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes 'User already has Copilot license. Task closed.'
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'User already has Copilot license' WHERE ID = $ID;"
            # Dataverse log for already licensed
            $completionTimeAlreadyLicensed = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
            $dvBodyAlreadyLicensed = @{
                new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $ProcessedDate; new_completiontime = $completionTimeAlreadyLicensed
                new_status = 'Completed'; new_errorcode = 'Already licensed (Copilot)'
            } | ConvertTo-Json
            Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dvBodyAlreadyLicensed
            continue
        }
        
        # Quota Check for Copilot
        $UserExtensionAttribute1 = $MgUser.onPremisesExtensionAttributes.extensionAttribute1
        if (-not $UserExtensionAttribute1) { ScriptError -msg "User $userUPN onPremisesExtensionAttributes.extensionAttribute1 (Entity) is missing."; continue }
        
        $AvailableEntityLicenses = Get-EntityQuota -UserEntity $UserExtensionAttribute1
        $TnSEntityQuotaAvailable = Get-EntityQuota -UserEntity 'Supply, Trading & Shipping' # Specifically get T&S quota

        if ($null -eq $AvailableEntityLicenses -or $null -eq $TnSEntityQuotaAvailable) {
            ScriptError -msg "Could not retrieve full quota details for $userUPN (Entity: $UserExtensionAttribute1). Halting Copilot processing for user."
            continue
        }

        $copilotTenantLicenses = (Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -like '*_Copilot*' }).PrepaidUnits.Enabled - (Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -like '*_Copilot*' }).ConsumedUnits
        
        $proceedWithAssignment = $false
        if ($UserExtensionAttribute1 -eq 'Supply, Trading & Shipping') {
            if ($TnSEntityQuotaAvailable -gt 0 -and $copilotTenantLicenses -gt 0) { $proceedWithAssignment = $true }
        } else { # Non T&S
            # Assuming non-T&S quota is overall tenant licenses minus what T&S specifically has reserved/available from its own pool
            # This logic might need refinement based on how quotas are truly managed.
            # The original script logic: ((($availableCopilotLicenses - $TnSEntityQuotaAvailable) -gt 0) -or (...T&S logic...)) AND ($AvailableEntityLicenses -gt 0)
            # This implies $AvailableEntityLicenses is the specific quota for $UserExtensionAttribute1
            # And $availableCopilotLicenses is the overall tenant pool.
            if ($AvailableEntityLicenses -gt 0 -and $copilotTenantLicenses -gt 0) { $proceedWithAssignment = $true }
        }


        if ($proceedWithAssignment) {
            Write-Log "Copilot license quota available for $userUPN (Entity: $UserExtensionAttribute1). Proceeding with SOU/TOU checks." -Level INFO

            $SOUTrainingStatus = "Error" # Default
            if (([string]::IsNullOrWhiteSpace($LAppCase)) -or ($LAppCase -like '*Invalid NTIDUser1*')) {
                Write-Log "No valid LApp case found for $userUPN ($LAppCase). Creating new LApp case." -Level INFO
                # Email for approval (original Copilot logic)
                Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Copilot license request approved' -StorageAccountNameForEmail $StorageAccountName -ContainerNameForEmail $CopilotEmailTemplateContainer -TemplateName 'license_has_been_approved.html' -Replacements @{}
                
                $LAppCaseNumberFromSF = Invoke-SalesforceCase -UserName $MgUser.DisplayName -UserNTID $MgUser.onPremisesSamAccountName
                if ($LAppCaseNumberFromSF) {
                    if ($LAppCaseNumberFromSF -like "*Case Already exists for this combination*") {
                        $LAppCase = ($LAppCaseNumberFromSF -split 'Case Number : ')[1] # Extract number
                    } else {
                        $LAppCase = $LAppCaseNumberFromSF
                    }
                    Write-Log "LApp Case for $userUPN: $LAppCase. Updating DB and SNOW." -Level INFO
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 3, LAppCase='$LAppCase', LAppCaseCreatedDate = GETUTCDATE(), ProcessedDate = GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'SOU Training assigned' WHERE ID = $ID;"
                    Update-TaskStatus -TicketNumber $TaskNumber -State '6' -WorkNotes "Copilot license approved. LApp case $LAppCase raised. Awaiting training check."
                    Update-TicketStatus -TicketNumber $RITMNumber -State '-5' -Stage 'Pending Training' -WorkNotes "Copilot license approved. LApp case $LAppCase raised. Awaiting training check."
                    Update-EntityQuota -UserEntity $UserExtensionAttribute1 -TicketStage 'Pending Training'
                    # SOU/TOU status will be checked in the next run after LApp case creation
                    $SOUTrainingStatus = "PendingLAppCreation" # Special status to indicate loop should continue to next message
                } else {
                    ScriptError -msg "Failed to create or retrieve LApp case for $userUPN."
                    $SOUTrainingStatus = "ErrorCreatingLApp" # Stop processing this user
                }
            } else { # LAppCase exists, check SOU/TOU
                 Write-Log "Existing LApp case $LAppCase for $userUPN. Checking SOU/TOU status." -Level INFO
                 if (-not $CSODReportPath) {
                     ScriptError -msg "CSOD Report path not available, cannot check SOU for $userUPN."
                     $SOUTrainingStatus = "ErrorNoCSODFile" # Stop processing this user
                 } else {
                    if ($UserExtensionAttribute1 -eq 'Supply, Trading & Shipping') {
                        $SOUTrainingStatus = Get-SOUStatus -UserUPN $userUPN -UserEntity $UserExtensionAttribute1 -CornerstoneFilePath $CSODReportPath `
                                            -DBMessageID $ID -CurrentTaskNumber $TaskNumber -CurrentRITMNumber $RITMNumber `
                                            -LAppCaseAssignedDateFromDB $LAppCaseCreatedDate -UserExtensionAttribute1FromContext $UserExtensionAttribute1
                    } else { # Non-T&S use TOU from MS Form, but also check CSOD SOU
                        $SOUCheckNonTS = Get-SOUStatus -UserUPN $userUPN -UserEntity $UserExtensionAttribute1 -CornerstoneFilePath $CSODReportPath `
                                            -DBMessageID $ID -CurrentTaskNumber $TaskNumber -CurrentRITMNumber $RITMNumber `
                                            -LAppCaseAssignedDateFromDB $LAppCaseCreatedDate -UserExtensionAttribute1FromContext $UserExtensionAttribute1
                        $TOUCheckNonTS = Get-TOUStatus -UserUPN $userUPN

                        if ($SOUCheckNonTS -eq "Passed" -and $TOUCheckNonTS -eq "Passed") { $SOUTrainingStatus = "Passed" }
                        elseif ($SOUCheckNonTS -eq "Failed" -or $TOUCheckNonTS -eq "Failed") { $SOUTrainingStatus = "Failed" }
                        elseif ($SOUCheckNonTS -eq "Expired" -or $TOUCheckNonTS -eq "Expired") { $SOUTrainingStatus = "Expired" } # Should be handled by Get-SOUStatus directly
                        elseif ($SOUCheckNonTS -eq "PTW_Failed" -or $TOUCheckNonTS -eq "PTW_Failed") { $SOUTrainingStatus = "PTW_Failed" }
                        else { $SOUTrainingStatus = "Pending" } # Default if not explicitly failed or passed
                    }
                 }
            }

            Write-Log "SOU/TOU Training status for $userUPN: $SOUTrainingStatus" -Level DEBUG

            if ($SOUTrainingStatus -notin ("PendingLAppCreation", "ErrorCreatingLApp", "ErrorNoCSODFile", "Expired", "PTW_Failed", "PTW_Missing")) {
                 $CopilotAssignmentResult = Invoke-UpgradeToCopilot -UserUPN $userUPN -SOUTrainingStatusToUse $SOUTrainingStatus -UserEntraGUID $MgUser.Id `
                                            -TaskNumberToUpdate $TaskNumber -RITMNumberToUpdate $RITMNumber -LAppCaseFromContext $LAppCase `
                                            -UserExtensionAttribute1ForQuota $UserExtensionAttribute1 -DBRecordIDForFailureUpdate $ID `
                                            -RequestedByForDV $RequestedBy -licenseCategorizationIDForDV $licenseCategorizationID -actionForDV $action `
                                            -RequestedTimeForDV $RequestedTime -ProcessedTimeForDV $ProcessedDate

                if ($CopilotAssignmentResult -eq 'Assigned') {
                    Write-Log "Copilot license successfully assigned to $userUPN. Sending emails and updating records." -Level INFO
                    Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Getting started with Copilot for Microsoft 365' -StorageAccountNameForEmail $StorageAccountName -ContainerNameForEmail $CopilotEmailTemplateContainer -TemplateName 'getting_started_with_copilot.html' -Replacements @{}
                    if ($UserExtensionAttribute1 -eq 'Supply, Trading & Shipping') {
                        Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Copilot for M365 – additional guidance for Trading & Shipping' -StorageAccountNameForEmail $StorageAccountName -ContainerNameForEmail $CopilotEmailTemplateContainer -TemplateName 'getting_started_with_copilot_T&S.html' -Replacements @{}
                    }
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'License assigned' WHERE ID = $ID;"
                    # Dataverse log for assigned
                    $completionTimeAssigned = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                    $dvBodyAssigned = @{
                        new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                        new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $ProcessedDate; new_completiontime = $completionTimeAssigned
                        new_lappcasenumber = $LAppCase; new_status = 'Completed'; new_errorcode = $null
                    } | ConvertTo-Json
                    Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dvBodyAssigned
                    Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes 'Copilot license assigned. Task closed.'
                    Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes 'Copilot license assigned. RITM closed.'
                } elseif ($CopilotAssignmentResult -eq 'Pending') {
                    Write-Log "Copilot license assignment for $userUPN is still pending SOU/TOU completion. Will re-evaluate in next run." -Level INFO
                    # DB status remains 'Pending Training' or similar. No change needed here to make it re-evaluate.
                } elseif ($CopilotAssignmentResult -eq 'Failed' -or $SOUTrainingStatus -in ("Expired", "PTW_Failed", "PTW_Missing")) { # SOU/TOU Failed or other terminal states from Get-SOUStatus
                    Write-Log "Copilot license processing for $userUPN ended with status: $CopilotAssignmentResult / $SOUTrainingStatus. Record should be closed." -Level INFO
                    # Invoke-UpgradeToCopilot or Get-SOUStatus should have handled DB/SNOW/Dataverse updates for failure.
                } else { # Error states from Invoke-UpgradeToCopilot
                     ScriptError -msg "Error during Copilot license assignment for $userUPN. Result: $CopilotAssignmentResult. SOU Status: $SOUTrainingStatus"
                }
            } # End if not LAppCreation/Error states
        } else { # No Quota
            Write-Log "Not enough Copilot licenses available for $userUPN (Entity: $UserExtensionAttribute1, Overall Tenant: $copilotTenantLicenses). Processing on-hold." -Level WARN
            $onHoldEmailTemplate = if ($EmailSentCount -lt 1) { 'added_in_waitlist_communication.html' } else { 'still_on_the_waitlist_communication.html' }
            $onHoldEmailSubject = if ($EmailSentCount -lt 1) { 'Copilot license processing on-hold' } else { 'Copilot license processing still on-hold' }
            Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject $onHoldEmailSubject -StorageAccountNameForEmail $StorageAccountName -ContainerNameForEmail $CopilotEmailTemplateContainer -TemplateName $onHoldEmailTemplate -Replacements @{}
            $EmailSentCount++
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 4, EmailSentCount=$EmailSentCount, EmailSentDate = GETUTCDATE(), ProcessedDate = GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Copilot license on-hold (quota)' WHERE ID = $ID;"
            Update-TicketStatus -TicketNumber $RITMNumber -Stage 'Waiting List' -State '5' -WorkNotes 'Copilot licenses for entity/tenant at capacity. Request on waiting list.'
            try { New-MgGroupMember -GroupId $CopilotPendingGroupID -DirectoryObjectId $MgUser.Id } catch { Write-Log "Failed to add $userUPN to Copilot pending group $CopilotPendingGroupID: $($_.Exception.Message)" -Level WARN }
        }

    } elseif ($LicenseType -eq 'Microsoft365') {
        Write-Log "Processing Microsoft365 (E1/E5) license for $userUPN" -Level INFO
        if ($ThisRunProcessedE1E5 -ge $ProcessCutoffE1E5) {
            Write-Log "E1/E5 processing cutoff ($ProcessCutoffE1E5) reached for this run. Skipping $userUPN." -Level INFO
            continue
        }
        # E1/E5 specific pre-checks (already has target license?)
        $alreadyHasTargetLicenseE1E5 = Get-LicenseAllocationStatus -emailID $userUPN -action $action -LicenseType 'Microsoft365'
        if ($alreadyHasTargetLicenseE1E5) {
            Write-Log "User $userUPN already has the target M365 license for action '$action'. Closing RITM/Task and DB record." -Level INFO
            $completionCommentE1E5 = "User already has target M365 license ($action)"
            Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes $completionCommentE1E5
            Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes $completionCommentE1E5
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + '$completionCommentE1E5' WHERE ID = $ID;"
            # Dataverse log
            $completionTimeE1E5Done = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
            $dvBodyE1E5Done = @{
                new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $ProcessedDate; new_completiontime = $completionTimeE1E5Done
                new_status = 'Completed'; new_errorcode = "Already has target license ($action)"
            } | ConvertTo-Json
            Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dvBodyE1E5Done
            continue
        }

        # Saviynt replication check for previously processed items
        if (-not ([string]::IsNullOrEmpty($SaviyntExitCodeFromDB)) -and $SaviyntExitCodeFromDB -ne "Success" -and $SaviyntExitCodeFromDB -notlike "NotE5InSaviynt*" ) { # If there was a Saviynt error code that isn't "Success" or "NotE5..."
             Write-Log "Previous Saviynt attempt for $userUPN had error: $SaviyntExitCodeFromDB. Snow Task: $SnowTicketNumberFromDB. Not reprocessing via Saviynt." -Level WARN
             # This request might need manual intervention based on the SnowTask.
             # For now, we will not re-attempt Saviynt. If it needs to be re-queued, status in DB should be reset.
             # Update RITM worknotes if needed
             Update-TicketStatus -TicketNumber $RITMNumber -WorkNotes "Previous Saviynt processing for $action $LicenseType resulted in error code '$SaviyntExitCodeFromDB'. Manual follow-up via task $SnowTicketNumberFromDB may be required."
             continue # Skip to next message
        }
        
        if (-not ([string]::IsNullOrEmpty($SaviyntTrackIDFromDB)) -and $SaviyntExitCodeFromDB -eq "Success" ) { # Successfully sent to Saviynt previously
            $isReplicated = Get-SaviyntLicenseReplicationStatus -emailID $userUPN -action $action -LicenseType 'Microsoft365'
            if ($isReplicated) {
                Write-Log "M365 license ($action) for $userUPN now replicated in Entra. Saviynt Tracking ID: $SaviyntTrackIDFromDB." -Level INFO
                $completionCommentE1E5Rep = "License $action replicated (Saviynt: $SaviyntTrackIDFromDB)"
                Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes $completionCommentE1E5Rep
                Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes $completionCommentE1E5Rep
                Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + '$completionCommentE1E5Rep' WHERE ID = $ID;"
                # Dataverse Log
                $completionTimeE1E5Rep = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                $dvBodyE1E5Rep = @{
                    new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                    new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $ProcessedDate; new_completiontime = $completionTimeE1E5Rep
                    new_saviynttrackingid = $SaviyntTrackIDFromDB; new_saviynttransactionid = $SaviyntTransactionIDFromDB; new_status = 'Success'; new_errorcode = $null
                } | ConvertTo-Json
                Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dvBodyE1E5Rep
                continue
            } else {
                # Check if it's been too long (e.g., > 6 hours as per E1-E5 script)
                if ($ProcessedDate -and ((Get-Date) -gt $ProcessedDate.AddHours(6)) -and -not $SnowTicketNumberFromDB) {
                    Write-Log "M365 license ($action) for $userUPN NOT replicated after 6 hours (Saviynt: $SaviyntTrackIDFromDB). Logging SNOW task." -Level WARN
                    $ShortDescRep = "Failure; M365 License Replication Delay for $userUPN ($action)"
                    $DescriptionRep = "M365 license $action for $userUPN not replicated after 6 hours. Saviynt Tracking ID: $SaviyntTrackIDFromDB. Investigate."
                    $replicationTicket = New-SnowTask -shortDescription $ShortDescRep -Description $DescriptionRep -UserUPN $userUPN -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET snowTicketNumber = '$replicationTicket', Comments = ISNULL(Comments + ' | ', '') + 'Replication task $replicationTicket logged.' WHERE ID = $ID;"
                    Update-TicketStatus -TicketNumber $RITMNumber -WorkNotes "License $action not replicated after 6 hours. SNOW task $replicationTicket created for follow-up."
                } else {
                     Write-Log "M365 license ($action) for $userUPN not yet replicated (Saviynt: $SaviyntTrackIDFromDB). Will check again next run." -Level INFO
                }
                continue # Check next message
            }
        }


        # If not processed by Saviynt before, or if previous was "NotE5InSaviyntNoDowngradeNeeded" for a downgrade
        if (([string]::IsNullOrEmpty($SaviyntTrackIDFromDB)) -or ($action -eq "downgrade" -and $SaviyntExitCodeFromDB -eq "NotE5InSaviyntNoDowngradeNeeded") ) {
            $ThisRunProcessedE1E5++ # Count this as a new Saviynt attempt
            $saviyntActionResult = $null
            if ($action -eq 'upgrade') {
                # Check E5 License Pool (example from E1-E5, might need adjustment)
                $e5_skus = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq 'SPE_E5' }
                $availableE5Licenses = $e5_skus.PrepaidUnits.Enabled - $e5_skus.ConsumedUnits
                $e5Threshold = $availableE5Licenses / 2 # Example threshold
                if ($availableE5Licenses -gt $e5Threshold) {
                    Write-Log "Attempting E5 upgrade for $userUPN via Saviynt." -Level INFO
                    Invoke-UpgradeToE5 -UserUPNForE5 $userUPN
                    $saviyntActionResult = "Processed"
                } else {
                    Write-Log "Not enough E5 licenses in tenant pool ($availableE5Licenses available, threshold $e5Threshold). Upgrade for $userUPN on hold." -Level WARN
                    Update-TicketStatus -TicketNumber $RITMNumber -State '5' -Stage 'On Hold' -WorkNotes "E5 license pool low. Request on hold." # Or similar status
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 4, Comments = ISNULL(Comments + ' | ', '') + 'E5 pool low, on hold.' WHERE ID = $ID;" # StatusID 4 for On-Hold
                    $saviyntActionResult = "SkippedNoPool"
                }
            } elseif ($action -eq 'downgrade') {
                # E1 pool check (example from E1-E5)
                $e1_skus = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq 'STANDARDPACK' }
                $availableE1Licenses = $e1_skus.PrepaidUnits.Enabled - $e1_skus.ConsumedUnits
                $e1Threshold = $availableE1Licenses / 2
                if ($availableE1Licenses -gt $e1Threshold) {
                    Write-Log "Attempting E1 downgrade for $userUPN via Saviynt." -Level INFO
                    Invoke-DowngradeToE1 -UserUPNForE1 $userUPN
                    $saviyntActionResult = "Processed"
                } else {
                     Write-Log "E1 license pool low ($availableE1Licenses available, threshold $e1Threshold), but downgrade should proceed as it frees up E5. Forcing downgrade attempt." -Level WARN
                     # Original E1-E5 script had on-hold logic here, but for downgrade, it might be less critical if E1 is "unlimited" or plentiful
                     Invoke-DowngradeToE1 -UserUPNForE1 $userUPN
                     $saviyntActionResult = "Processed"
                }
            }

            if ($saviyntActionResult -eq "Processed") {
                Write-Log "Saviynt action '$action' for $userUPN completed. Saviynt Refs: $($saviyntRequestReferenceIDs | ConvertTo-Json -Compress)" -Level INFO
                $dbStatusIDForSaviynt = 2 # In-Progress
                $dbCommentsSaviynt = "$action to $($LicenseType) sent to Saviynt. Exit: $($saviyntRequestReferenceIDs.ExitCode)."
                if ($saviyntRequestReferenceIDs.ExitCode -ne "Success" -and $saviyntRequestReferenceIDs.ExitCode -ne "NotE5InSaviyntNoDowngradeNeeded") {
                    $dbCommentsSaviynt += " SNOW Task: $($saviyntRequestReferenceIDs.SnowTaskNumber)."
                    # Update RITM with Saviynt error details
                     Update-TicketStatus -TicketNumber $RITMNumber -WorkNotes "Saviynt processing for $action $LicenseType resulted in ExitCode '$($saviyntRequestReferenceIDs.ExitCode)'. Associated SNOW Task: $($saviyntRequestReferenceIDs.SnowTaskNumber)."
                } else { # Success or NotE5...
                     Update-TicketStatus -TicketNumber $RITMNumber -WorkNotes "Request for $action $LicenseType sent to Saviynt. Tracking ID: $($saviyntRequestReferenceIDs.trackingID). Replication may take up to 6 hours."
                }
                
                Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = $dbStatusIDForSaviynt, ProcessedDate = GETUTCDATE(), SaviyntTrackID = '$($saviyntRequestReferenceIDs.trackingID)', SaviyntTransactionID = '$($saviyntRequestReferenceIDs.APITransactionID)', SaviyntExitCode = '$($saviyntRequestReferenceIDs.ExitCode)', snowTicketNumber = '$($saviyntRequestReferenceIDs.SnowTaskNumber)', UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + '$dbCommentsSaviynt' WHERE ID = $ID;"
                # Dataverse log for initial Saviynt submission (even if ExitCode is an error, it's an outcome of this attempt)
                $completionTimeSavSub = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                $dvBodySavSub = @{
                    new_requestedby = $RequestedBy; new_requestedfor = $userUPN; 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"; new_action = $action
                    new_requestsource = 'DWP-Automation'; new_requesttime = $RequestedTime; new_processedtime = $completionTimeSavSub # Processed now
                    new_saviynttrackingid = $saviyntRequestReferenceIDs.trackingID; new_saviynttransactionid = $saviyntRequestReferenceIDs.APITransactionID
                    new_status = if ($saviyntRequestReferenceIDs.ExitCode -eq "Success" -or $saviyntRequestReferenceIDs.ExitCode -eq "NotE5InSaviyntNoDowngradeNeeded") { "In Progress" } else { "Error" } # Reflects Saviynt submission status
                    new_errorcode = if ($saviyntRequestReferenceIDs.ExitCode -ne "Success" -and $saviyntRequestReferenceIDs.ExitCode -ne "NotE5InSaviyntNoDowngradeNeeded") { $saviyntRequestReferenceIDs.ExitCode } else { $null }
                    new_snowtasknumber = $saviyntRequestReferenceIDs.SnowTaskNumber
                } | ConvertTo-Json
                Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $dvBodySavSub
            }
        } # End if new Saviynt processing needed

    } else {
        Write-Log "Unsupported LicenseType: '$LicenseType' for UPN: $userUPN. Skipping." -Level WARN
        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 5, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Unsupported LicenseType ($LicenseType)' WHERE ID = $ID;"
        ScriptError -msg "Unsupported LicenseType '$LicenseType'"
        Update-TaskStatus -TicketNumber $TaskNumber -State '4' -WorkNotes "Unsupported LicenseType '$LicenseType'. Request cancelled."
        continue
    }
} # End foreach message

# Disconnect (common)
Write-Log "Disconnecting from Graph and Azure." -Level INFO
Disconnect-MgGraph | Out-Null
Disconnect-AzAccount -Confirm:$false | Out-Null

Write-Log '##############################################' -Level 'INFO'
Write-Log 'COMBINED SCRIPT ENDED' -Level 'INFO'
Write-Log '##############################################' -Level 'INFO'

#Stop-Transcript
