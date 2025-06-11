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
        # [Parameter(Mandatory = $false)]
        # [string]$licenseCategorizationIDForError = $licenseCategorizationID, # Removed
        [Parameter(Mandatory = $false)]
        [string]$actionForError = $action,
        [Parameter(Mandatory = $false)]
        [string]$RequestedTimeForError = $RequestedTime,
        [Parameter(Mandatory = $false)]
        [string]$ProcessedTimeForError = $ProcessedTime,
        [Parameter(Mandatory = $false)]
        [string]$LAppCaseForError = $LAppCase,
        [Parameter(Mandatory = $false)]
        [hashtable]$saviyntRequestReferenceIDsForError = $saviyntRequestReferenceIDs
        # [Parameter(Mandatory = $false)]
        # [string]$SnowTaskTicketNumber # To store SNOW task if created # Removed
    )

    $respObj = @{
        UPN   = $UserUPNForError
        Error = $msg
    }
    $response = $respObj | ConvertTo-Json

    # Detailed context logging
    $detailObject = @{
        UserUPN     = $UserUPNForError
        LicenseType = $LicenseTypeForError
        Action      = $actionForError
        RITMNumber  = $RITMNumberForError
        LAppCase    = $LAppCaseForError
        RequestedBy = $RequestedByForError
        # Add other relevant context variables if available and not too verbose for a summary
    }
    # Filter out null/empty values from detailObject for cleaner context string
    $filteredDetailObject = @{}
    foreach ($key in $detailObject.PSObject.Properties.Name) {
        if (-not ([string]::IsNullOrWhiteSpace($detailObject.$key))) {
            $filteredDetailObject[$key] = $detailObject.$key
        }
    }
    $contextString = $filteredDetailObject.GetEnumerator() | ForEach-Object { "$($_.Name): $($_.Value)" } | Join-String -Separator '; '

    Write-Log "Error: $msg. Context: $contextString" -Level 'ERROR'

    # For more detailed diagnostics, log all parameters passed to ScriptError at DEBUG level
    # Create a hashtable from PSBoundParameters, carefully excluding potentially large or circular objects if any were passed
    $boundParamsForLog = @{}
    foreach($key in $PSBoundParameters.Keys){
        # Potentially add checks here if some parameters could be very large objects
        $boundParamsForLog[$key] = $PSBoundParameters[$key]
    }
    $allParamsJson = @{
        UserUPNProvided = $UserUPNForError # Explicitly log the UPN used for the error message
        OriginalErrorMessage = $msg
        AllPassedParameters = $boundParamsForLog
    } | ConvertTo-Json -Depth 3 -WarningAction SilentlyContinue # Depth 3, suppress warnings for deep objects

    Write-Log "Complete ScriptError parameters dump: $allParamsJson" -Level 'DEBUG'


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
        # $SnowTaskTicketNumber = $ticket # Removed: No longer a parameter or used for Dataverse
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to create SNOW Task: $ex" -Level 'ERROR'
    }

    # Add Error message to Dataverse - BLOCK REMOVED
    # try {
    #     $completionTimeError = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
    #     $bodyContent = @{
    #         new_requestedby                          = $RequestedByForError
    #         new_requestedfor                         = $UserUPNForError
    #         # 'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationIDForError)" # Removed
    #         new_action                               = $actionForError
    #         new_requestsource                        = 'DWP-Automation'
    #         new_requesttime                          = $RequestedTimeForError
    #         new_processedtime                        = $ProcessedTimeForError
    #         new_completiontime                       = $completionTimeError
    #         new_lappcasenumber                       = $LAppCaseForError
    #         new_saviynttrackingid                    = $saviyntRequestReferenceIDsForError.trackingID
    #         new_status                               = "Error"
    #         new_saviynttransactionid                 = $saviyntRequestReferenceIDsForError.APITransactionID
    #         new_errorcode                            = $msg
    #         # new_snowtasknumber                       = $SnowTaskTicketNumber # Removed
    #     } | ConvertTo-Json

    #     $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent
    #     Write-Log 'Error message added to Dataverse successfully' -Level 'INFO'
    # }
    # catch {
    #     Write-Log "Dataverse body content for error: $bodyContent" -Level 'ERROR'
    #     $ex = $_.Exception.Message
    #     Write-Log "Failed to POST error record to Dataverse: $ex" -Level 'VERBOSE'
    #     Write-Log 'Failed to POST record in the dataverse table License_queue_request during scriptError.' -Level 'ERROR'
    # }
    return
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
        priority          = if ($cmdb_ci -eq 'M365 Copilot') { 4 } else { 3 }
        contact_type      = 'Via API'
        u_requested_for   = $UserUPN
        u_source          = if ($cmdb_ci -eq 'M365 Copilot') { 'DWP-Automation' } else { 'Portal' }
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
        try {
            Write-Log "Retrying SNOW task creation for $UserUPN" -Level 'INFO'
            $taskResult = (Invoke-RestMethod @params -ErrorAction Stop).result.number
            Write-Log "New-SnowTask: Successfully created SNOW task '$taskResult' on retry for User: $UserUPN." -Level 'INFO'
            return $taskResult
        }
        catch {
            $exMsgRetry = $_.Exception.Message
            Write-Log "Failed to log SNOW ticket on retry for $UserUPN. Body: $($body | ConvertTo-Json). Params: $($params | ConvertTo-Json). Error: $exMsgRetry" -Level 'ERROR'
            throw "Failed to create SNOW task after retry: $exMsgRetry"
        }
    }
}

function Convert-ToDateTime {
    param (
        [string]$dateString
    )
    $dateFormats = @(
        'dd/MM/yyyy'
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
    $scope = 'https://forms.cloud.microsoft/.default'
    $refreshTokenName = 'api-dwp-graph-refreshToken'
    $clientIdName = 'DWP-DevHub-Dataverse-AppID' # This AppID might be general purpose, not just DV.
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
        refresh_token = $refreshtoken
    }
    $tokenUri = "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token"
    try {
        $response = Invoke-WebRequest $tokenUri -ContentType 'application/x-www-form-urlencoded' -Method POST -Body $body
        $tokenobj = ConvertFrom-Json $response.Content
        return $tokenobj.access_token
    }
    catch {
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
    $UserID = '56a1894f-558a-494f-9b12-969ba3e14a45'

    try {
        $MSFormToken = Get-MSFormToken
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'Verbose'
        ScriptError('Failed to get MS Form token.')
        return
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

    $gpgExecutablePath = 'C:\Program Files (x86)\GnuPGin\gpg.exe'
    $destinationFilePath = 'D:\Temp'
    $secretFileName = 'passphrase.txt'
    $containerNameSouReport = 'copilot-sou-report-cornerstone'
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
            $gpgExecutablePath_ic = 'C:\Program Files (x86)\GnuPGin\gpg.exe'
            try {
                & $gpgExecutablePath_ic --batch --yes --pinentry-mode loopback --passphrase-file "$using:passphraseFilePath" --output "$using:decryptedFilePath" --decrypt "$using:encryptedFilePath" | Out-Null
            }
            catch {
                $ex_ic = $_.Exception.Message
                Write-Log $ex_ic -Level 'ERROR'
                throw "GPG decryption failed: $ex_ic" 
            }
        }
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
        return "Error"
    }

    try {
        $csvContent = Get-Content -Path $CornerstoneFilePath -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError("Failed to get SOU CSV report content from path: $CornerstoneFilePath.")
        return "Error"
    }
    
    $csvData = $csvContent | Select-Object -Skip 7
    $csvParsed = $null
    try {
        $csvParsed = $csvData | ConvertFrom-Csv
    }
    catch { Write-Log "Failed to parse SOU CSV data. User: $UserUPN. Error: $($_.Exception.Message)" -Level 'ERROR'; ScriptError -msg "Failed to parse SOU CSV data for user $UserUPN." -UserUPNForError $UserUPN; return "Error" }

    $selectedData = $null
    try {
        $selectedData = $csvParsed | Select-Object 'Training title', 'User full name', 'User e-mail', 'Quiz attempt date', 'Quiz SUCCESS Status', 'Training record status', 'Training record completed date'
    }
    catch { Write-Log "SOU CSV missing expected columns or error during column selection. User: $UserUPN. Error: $($_.Exception.Message)" -Level 'ERROR'; ScriptError -msg "SOU CSV missing expected columns for user $UserUPN." -UserUPNForError $UserUPN; return "Error" }
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
        if ($LAppCaseAssignedDateFromDB -lt $TwentyEightDaysAgo) {
            Write-Log "Training assignment date ($LAppCaseAssignedDateFromDB) for user $UserUPN is older than 28 days. Training has expired." -Level WARN
            try {
                Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Training expired' WHERE ID = $DBMessageID;"
                Write-Log "DB record $DBMessageID for UPN $userUPN - $LicenseType $Action marked as Training Expired."
            }
            catch { Write-Log "SQL update failed (Context: Training Expired) for DB ID $DBMessageID. User: $UserUPN. Error: $($_.Exception.Message)" -Level 'ERROR'; return "Error" }
            try {
                Update-TaskStatus -TicketNumber $CurrentTaskNumber -State '3' -WorkNotes 'Training assignment date is older than 28 days. Training has expired. Closing the task.'
            } catch { Write-Log "Failed to update Task $CurrentTaskNumber for user $UserUPN (Context: Training Expired). Error: $($_.Exception.Message)" -Level 'WARN' }
            try {
                Update-TicketStatus -TicketNumber $CurrentRITMNumber -State '3' -Stage 'Training Expired' -WorkNotes 'Training assignment date is older than 28 days. Training has expired. Closing the ticket.'
            } catch { Write-Log "Failed to update RITM $CurrentRITMNumber for user $UserUPN (Context: Training Expired). Error: $($_.Exception.Message)" -Level 'WARN' }
            try {
                Update-EntityQuota -UserEntity $UserExtensionAttribute1FromContext -TicketStage 'Training Expired'
            } catch { Write-Log "Failed to update entity quota for user $UserUPN (Entity: $UserExtensionAttribute1FromContext, Context: Training Expired). Error: $($_.Exception.Message)" -Level 'WARN' }
            return "Expired"
        } else {
            if($UserEntity -eq 'Supply, Trading & Shipping'){
                if($null -ne $UserPTWData){
                    if(($UserPTWData.'Training record status' -notcontains 'Completed') -and ($UserSOUData.'Training record status' -eq 'Completed')){
                        Write-Log "User $UserUPN (T&S) has completed SOU but PTW training is not completed. Rejecting." -Level WARN
                        try {
                            Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Copilot license request rejected' -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName 'Microsft_365_copilot_ST&S_PTW_Pending.html' -Replacements @{}
                        } catch { Write-Log "Failed to send Copilot email (Template: Microsft_365_copilot_ST&S_PTW_Pending.html) to user $UserUPN. Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Rejected due to PTW non-completion' WHERE ID = $DBMessageID;"
                        }
                        catch { Write-Log "SQL update failed (Context: PTW Non-Completion) for DB ID $DBMessageID. User: $UserUPN. Error: $($_.Exception.Message)" -Level 'ERROR'; return "Error" }
                        try {
                            Update-TaskStatus -TicketNumber $CurrentTaskNumber -State '3' -WorkNotes "User's Passport To Work training record shows as incomplete. Microsoft 365 Copilot license request rejected."
                        } catch { Write-Log "Failed to update Task $CurrentTaskNumber for user $UserUPN (Context: PTW Non-Completion). Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Update-TicketStatus -TicketNumber $CurrentRITMNumber -State '3' -Stage 'Training Expired' -WorkNotes "User's Passport To Work training record shows as incomplete. Microsoft 365 Copilot license request rejected."
                        } catch { Write-Log "Failed to update RITM $CurrentRITMNumber for user $UserUPN (Context: PTW Non-Completion). Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Update-EntityQuota -UserEntity $UserExtensionAttribute1FromContext -TicketStage 'Rejected'
                        } catch { Write-Log "Failed to update entity quota for user $UserUPN (Entity: $UserExtensionAttribute1FromContext, Context: PTW Non-Completion). Error: $($_.Exception.Message)" -Level 'WARN' }
                        return "PTW_Failed"
                    }
                } else {
                     if ($UserSOUData.'Training record status' -eq 'Completed') {
                        Write-Log "User $UserUPN (T&S) has completed SOU but no PTW training data found. Assuming PTW incomplete and rejecting." -Level WARN
                        try {
                            Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Copilot license request rejected' -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName 'Microsft_365_copilot_ST&S_PTW_Pending.html' -Replacements @{}
                        } catch { Write-Log "Failed to send Copilot email (Template: Microsft_365_copilot_ST&S_PTW_Pending.html) to user $UserUPN. Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Rejected due to missing PTW data' WHERE ID = $DBMessageID;"
                        }
                        catch { Write-Log "SQL update failed (Context: PTW Missing Data) for DB ID $DBMessageID. User: $UserUPN. Error: $($_.Exception.Message)" -Level 'ERROR'; return "Error" }
                        try {
                            Update-TaskStatus -TicketNumber $CurrentTaskNumber -State '3' -WorkNotes "User's Passport To Work training data not found. Microsoft 365 Copilot license request rejected."
                        } catch { Write-Log "Failed to update Task $CurrentTaskNumber for user $UserUPN (Context: PTW Missing Data). Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Update-TicketStatus -TicketNumber $CurrentRITMNumber -State '3' -Stage 'Training Expired' -WorkNotes "User's Passport To Work training data not found. Microsoft 365 Copilot license request rejected."
                        } catch { Write-Log "Failed to update RITM $CurrentRITMNumber for user $UserUPN (Context: PTW Missing Data). Error: $($_.Exception.Message)" -Level 'WARN' }
                        try {
                            Update-EntityQuota -UserEntity $UserExtensionAttribute1FromContext -TicketStage 'Rejected'
                        } catch { Write-Log "Failed to update entity quota for user $UserUPN (Entity: $UserExtensionAttribute1FromContext, Context: PTW Missing Data). Error: $($_.Exception.Message)" -Level 'WARN' }
                        return "PTW_Missing"
                     }
                }
            }
        }
    }

    $SOUStatus = 'Pending'
    if($UserEntity -eq 'Supply, Trading & Shipping'){
        if ($null -ne $UserSOUData -and $UserSOUData.'Training record status' -eq 'Completed' `
            -and $null -ne $UserPTWData -and $UserPTWData.'Training record status' -contains 'Completed') {
            switch ($FormResponseValue) {
                'Accept'  { $SOUStatus = 'Passed'; break }
                'Decline' { $SOUStatus = 'Failed'; break }
                'Pending' { $SOUStatus = 'Pending'; break }
                default   { Write-Log "Unknown MS Form response '$FormResponseValue' for T&S user $UserUPN." -Level WARN; $SOUStatus = 'Pending'; break }
            }
        } elseif ($null -ne $UserSOUData -and $UserSOUData.'Training record status' -eq 'Completed' `
                   -and ($null -eq $UserPTWData -or $UserPTWData.'Training record status' -notcontains 'Completed')) {
            $SOUStatus = 'Pending'
            Write-Log "T&S User $UserUPN SOU completed, but PTW is pending or failed. Status: $SOUStatus" -Level INFO
        } else {
            $SOUStatus = if ($FormResponseValue -eq 'Decline') {'Failed'} else {'Pending'}
        }
    } else {
        if ($null -ne $UserSOUData -and $UserSOUData.'Training record status' -eq 'Completed') {
             switch ($FormResponseValue) {
                'Accept'  { $SOUStatus = 'Passed'; break }
                'Decline' { $SOUStatus = 'Failed'; break }
                'Pending' { $SOUStatus = 'Pending'; break }
                default   { Write-Log "Unknown MS Form response '$FormResponseValue' for non-T&S user $UserUPN." -Level WARN; $SOUStatus = 'Pending'; break }
            }
        } else {
            $SOUStatus = if ($FormResponseValue -eq 'Decline') {'Failed'} else {'Pending'}
            Write-Log "Non-T&S User $UserUPN SOU (CSOD) not completed or data missing. MS Form was $FormResponseValue. Status: $SOUStatus" -Level INFO
        }
    }
    return $SOUStatus
}

function Get-TOUStatus {
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
        return "Error"
    }

    switch ($FormResponseValue) {
        'Accept'  { return 'Passed' }
        'Decline' { return 'Failed' }
        'Pending' { return 'Pending' }
        default   { 
            Write-Log "Unknown MS Form response '$FormResponseValue' for user $UserUPN during TOU check." -Level WARN
            return 'Pending'
        }
    }
}

function Invoke-UpgradeToCopilot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN,
        [Parameter(Mandatory = $true)]
        [string]$SOUTrainingStatusToUse,
        [Parameter(Mandatory = $true)]
        [string]$UserEntraGUID,
        [Parameter(Mandatory = $true)]
        [string]$TaskNumberToUpdate,
        [Parameter(Mandatory = $true)]
        [string]$RITMNumberToUpdate,
        [Parameter(Mandatory = $true)]
        [string]$LAppCaseFromContext,
        [Parameter(Mandatory = $true)]
        [string]$UserExtensionAttribute1ForQuota,
        [Parameter(Mandatory = $true)]
        [string]$DBRecordIDForFailureUpdate
    )

    $LicenseAssignmentStatus = "ErrorInFunction"

    if ($SOUTrainingStatusToUse -eq 'Passed') {
        try {
            New-MgGroupMember -GroupId $CopilotCompletedGroupID -DirectoryObjectId $UserEntraGUID
            Write-Log "User $UserUPN has been successfully added to the copilot licensing Entra group $CopilotCompletedGroupID." -Level 'INFO'
            $LicenseAssignmentStatus = 'Assigned'
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log "Failed to add user $UserUPN to Copilot Completed Group $CopilotCompletedGroupID: $ex" -Level 'ERROR'
            $LicenseAssignmentStatus = "ErrorAddingToGroup"
        }
    }
    elseif ($SOUTrainingStatusToUse -eq 'Pending') {
        Write-Log "User $UserUPN SOU/TOU training is still pending (LApp case $LAppCaseFromContext). Awaiting completion." -Level 'INFO'
        try {
            Update-TaskStatus -TicketNumber $TaskNumberToUpdate -State '6' -WorkNotes "Learning App case $LAppCaseFromContext has already been raised. Awaiting SOU/TOU training completion check."
        }
        catch { Write-Log "Failed to update Task $TaskNumberToUpdate for user $UserUPN (Context: SOU Status Pending). Error: $($_.Exception.Message)" -Level 'WARN' }
        try {
            Update-TicketStatus -TicketNumber $RITMNumberToUpdate -State '-5' -Stage 'Pending Training' -WorkNotes "Learning App case $LAppCaseFromContext has already been raised. Awaiting SOU/TOU training completion check."
        }
        catch { Write-Log "Failed to update RITM $RITMNumberToUpdate for user $UserUPN (Context: SOU Status Pending). Error: $($_.Exception.Message)" -Level 'WARN' }
        $LicenseAssignmentStatus = 'Pending'
    }
    elseif ($SOUTrainingStatusToUse -eq 'Failed') {
        Write-Log "User $UserUPN has failed or declined SOU/TOU training." -Level 'WARN'
        try {
            Update-TaskStatus -TicketNumber $TaskNumberToUpdate -State '3' -WorkNotes 'User has failed the SOU/TOU training or declined. Closing the task.'
        }
        catch { Write-Log "Failed to update Task $TaskNumberToUpdate for user $UserUPN (Context: SOU Status Failed). Error: $($_.Exception.Message)" -Level 'WARN' }
        try {
            Update-TicketStatus -TicketNumber $RITMNumberToUpdate -State '3' -Stage 'Completed' -WorkNotes 'User has failed the SOU/TOU training or declined. Closing the RITM.'
        }
        catch { Write-Log "Failed to update RITM $RITMNumberToUpdate for user $UserUPN (Context: SOU Status Failed). Error: $($_.Exception.Message)" -Level 'WARN' }

        try {
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'SOU/TOU Failed' WHERE ID = $DBRecordIDForFailureUpdate;"
            Write-Log "DB record $DBRecordIDForFailureUpdate for $userUPN marked as SOU/TOU Failed."
        }
        catch { Write-Log "SQL update failed for 'SOU/TOU Failed' status for DB ID $DBRecordIDForFailureUpdate. User: $UserUPN. Error: $($_.Exception.Message)" -Level 'ERROR'; $LicenseAssignmentStatus = "ErrorUpdatingDB_SOUFailure" }

        try {
            Update-EntityQuota -UserEntity $UserExtensionAttribute1ForQuota -TicketStage 'Rejected'
        }
        catch { Write-Log "Failed to update entity quota for user $UserUPN (Entity: $UserExtensionAttribute1ForQuota, Context: SOU Status Failed). Error: $($_.Exception.Message)" -Level 'WARN' }
        $LicenseAssignmentStatus = 'Failed'
    } else {
        Write-Log "Invoke-UpgradeToCopilot called with unexpected SOU/TOU status: '$SOUTrainingStatusToUse' for user $UserUPN." -Level ERROR
        $LicenseAssignmentStatus = "ErrorInvalidSOUStatus"
    }
    return $LicenseAssignmentStatus
}

function Get-SaviyntLicenseReplicationStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$emailID,
        [Parameter(Mandatory = $true)]
        [string]$action,
        [Parameter(Mandatory = $true)]
        [string]$LicenseType
    )
    try {
        $licenses = Get-MgUserLicenseDetail -UserId $emailID
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Error getting license details for $emailID: $ex" -Level 'ERROR'
        return $false
    }

    $lic_allocation = $false
    if ($action -eq 'downgrade') {
        if (($LicenseType -eq 'Microsoft365') -and ($licenses.skupartnumber -contains 'STANDARDPACK')) {
            Write-Log "User $emailID has an E1 license (STANDARDPACK)." -Level 'DEBUG'
            $lic_allocation = $true
        }
    }
    elseif ($action -eq 'upgrade') {
        if (($LicenseType -eq 'Microsoft365') -and ($licenses.skupartnumber -contains 'SPE_E5')) {
            Write-Log "User $emailID has an E5 license (SPE_E5)." -Level 'DEBUG'
            $lic_allocation = $true
        }
        elseif (($LicenseType -eq 'MicrosoftCopilot') -and ($licenses.skupartnumber -like '*_Copilot*')) {
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
    $SkuPartNumber = 'Microsoft_365_Copilot'
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
        return $null
    }
    $AllEntityDetails = $response.result
    $EntityAvailableLicenses = 0

    foreach ($entity in $AllEntityDetails) {
        if ($entity.entity -like $UserEntity) {
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
        [string]$TicketStage
    )

    $CurrentEntityAvailableLicenses = Get-EntityQuota -UserEntity $UserEntity
    if ($null -eq $CurrentEntityAvailableLicenses) {
         Write-Log "Could not retrieve current quota for $UserEntity. Aborting Update-EntityQuota." -Level ERROR
         ScriptError "Failed to retrieve current quota for $UserEntity during Update-EntityQuota."
         return 'failed'
    }

    $SysIDs = @{
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
        [string]$StorageAccountNameForEmail,
        [Parameter(Mandatory = $true)]
        [string]$ContainerNameForEmail,
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,
        [Parameter(Mandatory = $false)]
        [array]$Replacements
    )
    $bodyEmailAuth = @{
        client_id     = $Email_AppID
        client_secret = $Email_Secret
        grant_type    = 'client_credentials'
        scope         = "api://$EmailUtilScope/.default"
    }
    $uriEmailAuth = "https://login.microsoftonline.com:443/$tenantId/oauth2/v2.0/token"
    $bearerEmail = $null
    try {
        $bearerEmail = Invoke-RestMethod -Method POST -Uri $uriEmailAuth -Body $bodyEmailAuth -ErrorAction Stop
    }
    catch {
        $sanitizedBody = $bodyEmailAuth | Select-Object * -ExcludeProperty 'client_secret'
        $sanitizedBodyJson = $sanitizedBody | ConvertTo-Json -Compress
        Write-Log "Failed to retrieve auth token for email utility. URI: $uriEmailAuth. Body: $sanitizedBodyJson. Error: $($_.Exception.Message)" -Level 'ERROR'
        return
    }

    $headerEmail = @{
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $($bearerEmail.access_token)"
    }
    $bodyEmailSend = @{
        SendTo             = $SendTo
        Cc                 = $CC
        EmailSubject       = $EmailSubject
        StorageAccountName = $StorageAccountNameForEmail
        ContainerName      = $ContainerNameForEmail
        TemplateName       = $TemplateName
        Replacements       = $Replacements
    }
    $jsonBodyEmail = $bodyEmailSend | ConvertTo-Json
    $paramsEmail = @{
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

function Get-TicketStatus {
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
        return [PSCustomObject]@{ stage = $response.result.stage; state = $response.result.state }
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to get RITM $TicketNumber status from ServiceNow: $ex" -Level 'ERROR'
        return $null
    }
}

function Update-TicketStatus {
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
        Invoke-RestMethod @params -ErrorAction Stop
        Write-Log "RITM $TicketNumber status updated: State=$State, Stage=$Stage." -Level INFO
        return $true
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to update RITM $TicketNumber status in ServiceNow: $ex. Body: $jsonBody" -Level 'ERROR'
        return $false
    }
}

function Update-TaskStatus {
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
        Invoke-RestMethod @params -ErrorAction Stop
        Write-Log "Task $TicketNumber status updated: State=$State." -Level INFO
        return $true
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Failed to update Service Task $TicketNumber status in ServiceNow: $ex. Body: $jsonBody" -Level 'ERROR'
        return $false
    }
}

function Get-SalesforceJWTToken {
    $certificateDir = 'D:\Temp\SF_Cert'
    if (!(Test-Path $certificateDir)) { New-Item -ItemType Directory -Force -Path $certificateDir }

    try {
        $azSfContext = Set-AzContext -Subscription $StorageAccountSubscription -ErrorAction Stop
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
    $expiryDate = [math]::Round((Get-Date).AddMinutes(5).Subtract((Get-Date '1970-01-01')).TotalSeconds)
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

function Invoke-SalesforceCase {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserName,
        [Parameter(Mandatory = $false)]
        [string]$UserNTID
    )
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

Function Invoke-sqlquery {
    param(
        $qry
    )
    try{
        Invoke-Sqlcmd -ServerInstance "$sqlsvr" -Database "$sqldb" -Username "$sqluser" -Password "$sqlpass" -Query "$qry" -ErrorAction Stop -QueryTimeout 60
    }catch{
        $ErrorMessage = $_.Exception.Message
        Write-Log "SQL Query failed: $qry. Error: $ErrorMessage" -Level 'ERROR'
        throw "SQL Query failed: $ErrorMessage"
    }
}

# Functions from E1-E5.ps1
function Invoke-UpgradeToE5 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPNForE5 = $UserUPN
    )

    $script:saviyntRequestReferenceIDs = $null

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
    $ExceptionErrorCode = "GenericError"

    if (!([string]::IsnullOrEmpty($result.attributes))) {
        Write-Log "Saviynt record found for user $UserUPNForE5." -Level INFO
        $saviyntUserSystemName = $result.attributes.systemUserName.value

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
                $ExceptionErrorCode = 'Success'
            } else {
                Write-Log "Saviynt record for $UserUPNForE5 shows E5 attributes already set, but M365 license not reflected." -Level WARN
                $ShortDesc = "Failure; M365 E5 Upgrade - Saviynt/M365 Mismatch for $UserUPNForE5"
                $Description = "Saviynt shows E5 attributes for $UserUPNForE5, but M365 license is not E5. Investigate. Transaction ID: $BPIdentityAPITransactionID"
                try {
                    $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE5 -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
                }
                catch { Write-Log "Failed to create SNOW task (SaviyntE5TrueM365False case) for user $UserUPNForE5. Error: $($_.Exception.Message)" -Level 'WARN' }
                try {
                    Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "Saviynt/M365 E5 mismatch for $UserUPNForE5. SNOW Task $ticket created."
                }
                catch { Write-Log "Failed to update task status (SaviyntE5TrueM365False case) for user $UserUPNForE5. Error: $($_.Exception.Message)" -Level 'WARN' }
                $ExceptionErrorCode = "SaviyntE5TrueM365False-$ticket"
            }
        } else {
            Write-Log "Saviynt customproperty65 for $UserUPNForE5 not set correctly for E5 upgrade. Current: $($result.attributes.customproperty65.value)" -Level WARN
            $ShortDesc = "Failure; M365 E5 Upgrade - Incorrect Saviynt Mailbox Info for $UserUPNForE5"
            $Description = "Saviynt customproperty65 for $UserUPNForE5 (Mailbox Type) is not suitable for E5 upgrade. Current: $($result.attributes.customproperty65.value). Investigate. Transaction ID: $BPIdentityAPITransactionID"
            try {
                $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE5 -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
            }
            catch { Write-Log "Failed to create SNOW task (EmptyCustomproperty65 case) for user $UserUPNForE5. Error: $($_.Exception.Message)" -Level 'WARN' }
            try {
                Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "Incorrect Saviynt mailbox info for $UserUPNForE5 for E5 upgrade. SNOW Task $ticket created."
            }
            catch { Write-Log "Failed to update task status (EmptyCustomproperty65 case) for user $UserUPNForE5. Error: $($_.Exception.Message)" -Level 'WARN' }
            $ExceptionErrorCode = "EmptyCustomproperty65-$ticket"
        }
    } else {
        Write-Log "Saviynt user record not found for $UserUPNForE5 during E5 upgrade." -Level WARN
        $ShortDesc = "Failure; M365 E5 Upgrade - User Not Found in Saviynt for $UserUPNForE5"
        $Description = "Saviynt user record not found for $UserUPNForE5. Cannot process E5 upgrade. Investigate. Transaction ID: $BPIdentityAPITransactionID"
        try {
            $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE5 -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
        }
        catch { Write-Log "Failed to create SNOW task (SaviyntNoUserRecord case) for user $UserUPNForE5. Error: $($_.Exception.Message)" -Level 'WARN' }
        try {
            Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "User $UserUPNForE5 not found in Saviynt for E5 upgrade. SNOW Task $ticket created."
        }
        catch { Write-Log "Failed to update task status (SaviyntNoUserRecord case) for user $UserUPNForE5. Error: $($_.Exception.Message)" -Level 'WARN' }
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
        [string]$UserUPNForE1 = $UserUPN
    )
    $script:saviyntRequestReferenceIDs = $null

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

        if ((($result.attributes.customproperty53.value).ToLower() -eq $E5_customproperty53_true.ToLower()) -or (($result.attributes.customproperty63.value).ToLower() -eq $E5_customproperty63.ToLower())) {
            Write-Log "User $UserUPNForE1 has E5 attributes in Saviynt. Requesting E1 downgrade." -Level INFO
            $headerUpdate = @{ 'Content-Type' = 'application/json'; Authorization = "Bearer $($bearer.access_token)"; client_id = $Saviynt_ClientID; client_secret = $Saviynt_Secret; 'BP-IdentityAPI-TransactionID' = "DWP-devhub-$BPIdentityAPITransactionID" }
            $bodyUpdate = @{ attributes = @{ customproperty53 = @{ value = $E1_customproperty53 }; customproperty63 = @{ value = $E1_customproperty63 } } }
            $paramsUpdate = @{ method = 'PUT'; uri = "$SaviyntApiBaseUrl/identity-api/v1/async/users/$saviyntUserSystemName"; headers = $headerUpdate; body = ($bodyUpdate | ConvertTo-Json) }

            try { $TransactionResponse = Invoke-RestMethod @paramsUpdate -ErrorAction Stop }
            catch { Write-Log "Saviynt E1 downgrade request for $UserUPNForE1 failed: $($_.Exception.Message)" -Level ERROR; ScriptError "Saviynt E1 downgrade request failed."; return }
            
            $TransactionID = $TransactionResponse.TRACKING_ID
            Write-Log "Saviynt E1 downgrade request for $UserUPNForE1 logged. Tracking ID: $TransactionID" -Level INFO
            $ExceptionErrorCode = 'Success'
        } else {
            Write-Log "Saviynt record for $UserUPNForE1 does not show E5 attributes; cannot downgrade or already E1/other. Current customproperty53: $($result.attributes.customproperty53.value), customproperty63: $($result.attributes.customproperty63.value)." -Level WARN
            $ExceptionErrorCode = "NotE5InSaviyntNoDowngradeNeeded" 
        }
    } else {
        Write-Log "Saviynt user record not found for $UserUPNForE1 during E1 downgrade." -Level WARN
        $ShortDesc = "Failure; M365 E1 Downgrade - User Not Found in Saviynt for $UserUPNForE1"
        $Description = "Saviynt user record not found for $UserUPNForE1. Cannot process E1 downgrade. Investigate. Transaction ID: $BPIdentityAPITransactionID"
        try {
            $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPNForE1 -TicketType "ReplicationTask" -cmdb_ci "Digital Collaboration Tools"
        }
        catch { Write-Log "Failed to create SNOW task (SaviyntNoUserRecord case for E1 downgrade) for user $UserUPNForE1. Error: $($_.Exception.Message)" -Level 'WARN' }
        try {
            Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "User $UserUPNForE1 not found in Saviynt for E1 downgrade. SNOW Task $ticket created."
        }
        catch { Write-Log "Failed to update task status (SaviyntNoUserRecord case for E1 downgrade) for user $UserUPNForE1. Error: $($_.Exception.Message)" -Level 'WARN' }
        $ExceptionErrorCode = "SaviyntNoUserRecord-$ticket"
    }
    $script:saviyntRequestReferenceIDs = [PSCustomObject]@{
        trackingID       = if($TransactionID){$TransactionID}else{$null}
        APITransactionID = $BPIdentityAPITransactionID
        ExitCode         = $ExceptionErrorCode
        SnowTaskNumber   = if($ticket){$ticket}else{$null}
    }
}

function Get-LicenseAllocationStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$emailID,
        [Parameter(Mandatory = $true)]
        [string]$action,
        [Parameter(Mandatory = $true)]
        [string]$LicenseType
    )
    try {
        $licenses = Get-MgUserLicenseDetail -UserId $emailID
    } catch {
        Write-Log "Get-LicenseAllocationStatus: Error getting licenses for $emailID: $($_.Exception.Message)" -Level WARN
        return $false
    }

    if ($action -eq 'downgrade') {
        if ($licenses.skupartnumber -contains 'STANDARDPACK') {
            Write-Log "User $emailID already has an E1 license (STANDARDPACK)." -Level INFO
            return $true
        }
    } elseif ($action -eq 'upgrade') {
        if ($licenses.skupartnumber -contains 'SPE_E5') {
            Write-Log "User $emailID already has an E5 license (SPE_E5)." -Level INFO
            return $true
        }
    } else {
        Write-Log "Invalid action '$action' specified in Get-LicenseAllocationStatus for $emailID." -Level WARN
        return $false
    }
    return $false
}

function Get-SnowAccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SnowURLForToken,
        [Parameter(Mandatory = $true)]
        [string]$SnowApiScopeForToken, 
        [Parameter(Mandatory = $true)]
        [string]$SnowClientIdForToken,
        [Parameter(Mandatory = $true)]
        [string]$SnowClientSecretForToken
    )
    $tokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "$SnowApiScopeForToken/.default"
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
        throw "SNOW Access Token generation failed: $ex"
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
        $StorageAccountSubscription = 'zne-evcs-n-dwp-sbc'
        $StorageAccountNameRSG = 'ZNE-EVCS-N-17-DWP-RSG'
        $StorageAccountName = 'zneevcsn17dwpappstg'
        $CopilotEmailTemplateContainer = 'copilot-license-allocation-email-templates'
        $SouReportContainer = 'copilot-sou-report-cornerstone'
        
        $KeyvaultName = 'zne-dwp-n-kvl'
        # $DataverseEnvironmentURL = 'https://orga8dae9a2.crm4.dynamics.com' # Removed
        # $Copilot_GUID = '58586b15-2e27-ef11-840a-000d3ab44827' # Removed
        # $E1_GUID = '135f4d11-300d-ef11-9f8a-6045bd8865c3'      # Removed
        # $E5_GUID = 'db56a5c3-250d-ef11-9f89-000d3a222c58'      # Removed

        $SnowURL = 'https://bpdev.service-now.com'
        $snowclient_id_KV_Name = if($SnowURL -like "*bptest*") {'SNOW-Test-AppID'} else {'SNOW-Dev-AppID'}
        $snowclient_secret_KV_Name = if($SnowURL -like "*bptest*") {'SNOW-Test-Secret'} else {'SNOW-Dev-Secret'}
        $SnowApiScopeKV_Name = 'SNOW-Api-Scope-Test'

        $Email_AppID_KV_Name = 'DWP-DevHub-Email-AppID'
        $Email_Secret_KV_Name = 'DWP-DevHub-Email-Secret'
        $EmailUtilScope = 'c390e4a4-f797-4ef8-8d82-8ad8c5438743'
        $Email_URI = 'https://dwp-functions-dev.bpglobal.com/api/Email-Common-Utility'

        $CopilotCompletedGroupID = '2dcedb7c-77ad-452b-9c64-6724aea37c76'
        $CopilotPendingGroupID = '735c9f9c-b778-4020-94c8-e6a07d73bed7'

        $sqluser_KV_Name = 'SQL-UserName-Licensingwrite'
        $sqlpass_KV_Name = 'SQL-Password-Licensingwrite'

        $SalesforceCertContainer = 'bau-license-allocation-process'
        $SalesforceCertBlobName = 'bpcolleagues.my.salesforce.com.pfx'
        $SalesforceCertKeyVaultName = 'zne-dwp-n-kvl'
        $SalesforceCertPasswordSecretName = 'Salesforce-API-Cert-Key-Test'
        $SalesforceClientId = '3MVG91LYYD8O4krRFZk502yUZjm5Gonr_Z_Mj8pL0DuEtyWnZSw_O_Ob2PxDzxiCH9tKQ1AFX6FiBoK3Cw5co'
        $SalesforceUsername = 'pcsalesforce1@bp.com.colleagues.hrmtest'
        $SalesforceAudienceUrl = 'test.salesforce.com'
        $SalesforceTokenUrl = 'https://test.salesforce.com/services/oauth2/token'
        $SalesforceApiUrl = 'https://bpcolleagues--hrmtest.sandbox.my.salesforce.com/services/apexrest/createCaseRMS/'
        $SalesforceMTLID = '1000198'

        $SaviyntApiBaseUrl = 'https://apis-001-nonprod.bpweb.bp.com/test'
        $SaviyntApiScope = 'https://api-001-nonprod.bpglobal.com/tst/ieeo-grpitsidentity/proxy/v1/'
        $Saviynt_Oauth_ClientID_KV_Name = 'SaviyntApi-TEST-Oauth-ClientID'
        $Saviynt_Oauth_Secret_KV_Name = 'SaviyntApi-TEST-Oauth-Secret'
        $Saviynt_ClientID_KV_Name = 'SaviyntApi-TEST-ClientID'
        $Saviynt_Secret_KV_Name = 'SaviyntApi-TEST-Secret'
    }
    'AA-DWP-Prod' {
        $TestMode = $false
        $StorageAccountSubscription = 'zne-evcs-p-dwp-sbc'
        $StorageAccountNameRSG = 'ZNE-EVCS-P-27-DWP-RSG'
        $StorageAccountName = 'zneevcspdwpstg'
        $CopilotEmailTemplateContainer = 'copilot-license-allocation-email-templates'
        $SouReportContainer = 'copilot-sou-report-cornerstone'

        $KeyvaultName = 'zne-dwp-p-kvl'
        # $DataverseEnvironmentURL = 'https://orgee396095.crm4.dynamics.com' # Removed
        # $Copilot_GUID = '58586b15-2e27-ef11-840a-000d3ab44827' # Removed
        # $E1_GUID = '52bf2013-2e27-ef11-840a-000d3a660d83'      # Removed
        # $E5_GUID = '54586b15-2e27-ef11-840a-000d3ab44827'      # Removed

        $SnowURL = 'https://bp.service-now.com'
        $SNOW_Oauth_Token_KV_Name = 'SNOW-Oauth-Token'
        $SnowApiScopeKV_Name = 'SNOW-Api-Scope-Prod'

        $Email_AppID_KV_Name = 'DWP-DevHub-Email-AppID'
        $Email_Secret_KV_Name = 'DWP-DevHub-Email-Secret'
        $EmailUtilScope = '00c59037-c0c7-4637-9ba7-2b6b98cff3b5'
        $Email_URI = 'https://dwp-functions.bpglobal.com/api/Send-GraphEmailApi'

        $CopilotCompletedGroupID = 'ffe25b27-0c4a-418e-b2f4-52562b038b89'
        $CopilotPendingGroupID = '735c9f9c-b778-4020-94c8-e6a07d73bed7'

        $sqluser_KV_Name = 'SQL-LicensingWrite-UserName'
        $sqlpass_KV_Name = 'SQL-LicensingWrite-Password'

        $SalesforceCertContainer = 'bau-license-allocation-process'
        $SalesforceCertBlobName = 'bpcolleagues.my.salesforce.com.pfx'
        $SalesforceCertKeyVaultName = 'zne-dwp-p-kvl' 
        $SalesforceCertPasswordSecretName = 'Salesforce-API-Cert-Key'
        $SalesforceClientId = '3MVG95NPsF2gwOiMXVE8sXplWeRSDv9Y5kUjPN13fh69vyD2H__M0uLCe1s4J.KVNUVC3wapNcAOcC1BPO009'
        $SalesforceUsername = 'pcsalesforcecopilot1@bp.com.colleagues'
        $SalesforceAudienceUrl = 'login.salesforce.com'
        $SalesforceTokenUrl = 'https://login.salesforce.com/services/oauth2/token'
        $SalesforceApiUrl = 'https://bpcolleagues.my.salesforce.com/services/apexrest/createCaseRMS/'
        $SalesforceMTLID = '908547'

        $SaviyntApiBaseUrl = 'https://apis.bpglobal.com'
        $SaviyntApiScope = 'https://api-001.bpglobal.com/ieeo-grpitsidentity/proxy/v1/'
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

# Define Saviynt E1/E5 attribute comparison values.
# These were previously fetched from Dataverse.
# !!! USER REVIEW REQUIRED !!!
# Please verify these values are correct for your Prod and NonProd Saviynt configurations.
# These are common string values used in Saviynt for M365 license attributes.

$E1_customproperty53 = "True"       # Example: Typically indicates some form of E1/standard feature enabled
$E1_customproperty65 = "RemoteUserMailbox" # Example: Mailbox type or location
$E1_customproperty63 = "non-bp"     # Example: User segment or type
$E1_attributes65     = "RemoteUserMailbox" # Might be the same as customproperty65 or another attribute

$E5_customproperty63      = "win10"    # Example: User segment or type for E5
$E5_customproperty53_true = "True"     # Example: Indicates E5 feature is true
$E5_customproperty53_false = "False"   # Example: Indicates E5 feature is false
# !!! END USER REVIEW REQUIRED !!!

# Fetch secrets from KeyVault based on environment
try {
    Set-AzContext -Subscription $StorageAccountSubscription -ErrorAction Stop
    $Dataverse_AppID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Dataverse-AppID' -AsPlainText # Kept for now
    # $Dataverse_ClientSecret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Dataverse-ClientSecret' -AsPlainText # Removed
    $sqluser = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $sqluser_KV_Name -AsPlainText
    $sqlpass = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $sqlpass_KV_Name -AsPlainText

    $Email_AppID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $Email_AppID_KV_Name -AsPlainText
    $Email_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $Email_Secret_KV_Name -AsPlainText
    
    if ($AutomationAccountName -eq 'AA-DWP-Prod') {
        $SNOW_Oauth_Token = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name $SNOW_Oauth_Token_KV_Name -AsPlainText
        Write-Log "Successfully fetched SNOW_Oauth_Token directly from KeyVault for Prod." -Level INFO
    } else {
        Write-Log "Attempting to fetch SNOW client ID, secret, and scope from KeyVault for NonProd." -Level DEBUG
        $kvSnowClientId = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name $snowclient_id_KV_Name -AsPlainText 
        $kvSnowClientSecret = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name $snowclient_secret_KV_Name -AsPlainText
        $kvSnowApiScope = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name $SnowApiScopeKV_Name -AsPlainText
        
        if ($kvSnowClientId -and $kvSnowClientSecret -and $kvSnowApiScope) {
            Write-Log "Successfully fetched SNOW client credentials and scope from KeyVault for NonProd. Now calling Get-SnowAccessToken for $SnowURL with scope $kvSnowApiScope." -Level INFO
            try {
                $SNOW_Oauth_Token = Get-SnowAccessToken -SnowURLForToken $SnowURL -SnowApiScopeForToken $kvSnowApiScope -SnowClientIdForToken $kvSnowClientId -SnowClientSecretForToken $kvSnowClientSecret
                 if ($SNOW_Oauth_Token) {
                    Write-Log "Successfully obtained SNOW_Oauth_Token via Get-SnowAccessToken for NonProd." -Level INFO
                } else {
                    ScriptError -msg "Get-SnowAccessToken returned null/empty token for NonProd, and did not throw an exception that was caught."
                }
            } catch {
                 $DetailedErrorMessage = "Failed to obtain SNOW_Oauth_Token via Get-SnowAccessToken for NonProd. Error: $($_.Exception.Message). Check KeyVault values for $snowclient_id_KV_Name, $snowclient_secret_KV_Name, $SnowApiScopeKV_Name in ZSCEVCSP05MGMKVT and ensure the Entra App Registration is correct."
                 ScriptError -msg $DetailedErrorMessage
            }
        } else {
            $missingSnowCreds = "Missing one or more SNOW credentials from KeyVault ZSCEVCSP05MGMKVT for NonProd. Cannot generate SNOW token. "
            if(-not $kvSnowClientId) {$missingSnowCreds += "Missing: $snowclient_id_KV_Name. "}
            if(-not $kvSnowClientSecret) {$missingSnowCreds += "Missing: $snowclient_secret_KV_Name. "}
            if(-not $kvSnowApiScope) {$missingSnowCreds += "Missing: $SnowApiScopeKV_Name. "}
            ScriptError -msg $missingSnowCreds
        }
    }
    if(-not $SNOW_Oauth_Token) {
        ScriptError -msg "SNOW_Oauth_Token is NOT available after configuration attempts. SNOW-dependent operations will fail. This is a critical failure. Please check previous logs for specific errors in token retrieval or generation."
        Write-Log "CRITICAL FAILURE: SNOW_Oauth_Token could not be obtained. Exiting script." -Level ERROR
        exit 1
    }

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

# Dataverse Authentication - BLOCK REMOVED

# Dataverse Configuration Fetch - BLOCK REMOVED


# Fetch all messages from DB
try {
    $dbmessagesAll = Invoke-Sqlquery -qry "Select * from Licensing_Dev.LicenseRequestView where status in ('New', 'In-Progress','Pending Training','On-Hold')"
} catch { ScriptError('Failed to fetch messages from DB.'); exit }

$numberOfMessagesTotal = $dbmessagesAll.count
Write-Log "Total messages fetched from DB: $numberOfMessagesTotal" -Level 'INFO'

# Initialize Cornerstone SOU Report Path (Copilot specific)
$CSODReportPath = $null
if ($AutomationAccountName -ne $null) {
    Write-Log "Attempting to download SOU Cornerstone Report..." -Level INFO
    $CSODReportPath = Get-SOUCornerstoneReport
    if (-not $CSODReportPath) {
        Write-Log "SOU Cornerstone Report could not be obtained. Copilot SOU checks will likely fail." -Level WARN
    } else {
        Write-Log "SOU Cornerstone Report obtained at: $CSODReportPath" -Level INFO
    }
}


$ThisRunProcessedCopilot = 0
$ThisRunProcessedE1E5 = 0
$ProcessCutoffCopilot = if($TestMode) {10} else {1000}
$ProcessCutoffE1E5 = if($TestMode) {5} else {100}

$i = 0
foreach ($messageString in $dbmessagesAll) {
    $i++
    Write-Log "########################## PROCESSING MESSAGE $i OF $numberOfMessagesTotal ##########################" -Level 'INFO'
    Start-Sleep -Seconds 1

    $saviyntRequestReferenceIDs = $null
    $LAppCase = $null

    $ID = $messageString.ID; $Status = $messageString.Status; $userUPN = $messageString.UserUPN; $RequestedBy = $messageString.RequestedBy
    $LicenseType = $messageString.LicenseType; $action = $messageString.Action; $RequestedSource = $messageString.RequestSource
    $RITMNumber = $messageString.RITMNumber; $TaskNumber = $messageString.TaskNumber; $RequestedDate = $messageString.RequestedDate
    $ProcessedDate = $messageString.ProcessedDate; $EmailSentCount = [int]$messageString.EmailSentCount; $EmailSentDate = $messageString.EmailSentDate
    $LAppCase = $messageString.LAppCase; $LAppCaseCreatedDate = $messageString.LAppCaseCreatedDate
    $SOUAgreedDate = $messageString.SOUAgreedDate
    $SaviyntTrackIDFromDB = $messageString.SaviyntTrackID
    $SaviyntTransactionIDFromDB = $messageString.saviyntTransactionID
    $SaviyntExitCodeFromDB = $messageString.saviyntExitCode
    $SnowTicketNumberFromDB = $messageString.snowTicketNumber
    
    if ($LAppCaseCreatedDate -is [string] -and -not([string]::IsNullOrWhiteSpace($LAppCaseCreatedDate))) { $LAppCaseCreatedDate = Convert-ToDateTime $LAppCaseCreatedDate }
    if ($ProcessedDate -is [string] -and -not([string]::IsNullOrWhiteSpace($ProcessedDate))) { $ProcessedDate = Convert-ToDateTime $ProcessedDate }

    Write-Log "Processing UPN: $userUPN, LicenseType: $LicenseType, Action: $action, RITM: $RITMNumber, Task: $TaskNumber, DB_ID: $ID" -Level 'INFO'

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
            ScriptError -msg "User $userUPN not found in Entra." -UserUPNForError $userUPN -LicenseTypeForError $LicenseType -RITMNumberForError $RITMNumber
            Update-TaskStatus -TicketNumber $TaskNumber -State '9' -WorkNotes "User $userUPN not found in Entra. Request cancelled."
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
        Update-TaskStatus -TicketNumber $TaskNumber -State '9' -WorkNotes "User $userUPN account disabled in Entra. Request cancelled."
        continue
    }
    
    if ($action -eq 'upgrade') {
        $RITMInfo = Get-TicketStatus -TicketNumber $RITMNumber
        if ($RITMInfo) {
            $closedStateCodes = @('3', '4', '7', '9')
            if ($closedStateCodes -contains $RITMInfo.state) {
                Write-Log "RITM $RITMNumber for $userUPN is already closed (State: $($RITMInfo.state), Stage: $($RITMInfo.stage)). Skipping request." -Level INFO
                Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'RITM already closed' WHERE ID = $ID;"
                continue
            }
        } else {
            Write-Log "Could not retrieve RITM $RITMNumber status for $userUPN. Proceeding with caution." -Level WARN
        }
    }

    if ($LicenseType -eq 'MicrosoftCopilot') {
        Write-Log "Processing MicrosoftCopilot license for $userUPN" -Level INFO
        if ($ThisRunProcessedCopilot -ge $ProcessCutoffCopilot) {
            Write-Log "Copilot processing cutoff ($ProcessCutoffCopilot) reached for this run. Skipping $userUPN." -Level INFO
            continue
        }
        $ThisRunProcessedCopilot++

        if ($action -ne "upgrade") {
            Write-Log "Action '$action' is not 'upgrade' for Copilot. Skipping $userUPN." -Level WARN
            continue
        }

        $hasCopilotLicense = Get-SaviyntLicenseReplicationStatus -emailID $userUPN -action 'upgrade' -LicenseType 'MicrosoftCopilot'
        if ($hasCopilotLicense) {
            Write-Log "User $userUPN already has a Copilot license. Closing RITM/Task and DB record." -Level INFO
            Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes 'User already has Copilot license. Request completed.'
            Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes 'User already has Copilot license. Task closed.'
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'User already has Copilot license' WHERE ID = $ID;"
            continue
        }
        
        $UserExtensionAttribute1 = $MgUser.onPremisesExtensionAttributes.extensionAttribute1
        if (-not $UserExtensionAttribute1) { ScriptError -msg "User $userUPN onPremisesExtensionAttributes.extensionAttribute1 (Entity) is missing."; continue }
        
        $AvailableEntityLicenses = Get-EntityQuota -UserEntity $UserExtensionAttribute1
        $TnSEntityQuotaAvailable = Get-EntityQuota -UserEntity 'Supply, Trading & Shipping'

        if ($null -eq $AvailableEntityLicenses -or $null -eq $TnSEntityQuotaAvailable) {
            ScriptError -msg "Could not retrieve full quota details for $userUPN (Entity: $UserExtensionAttribute1). Halting Copilot processing for user."
            continue
        }

        $copilotTenantLicenses = (Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -like '*_Copilot*' }).PrepaidUnits.Enabled - (Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -like '*_Copilot*' }).ConsumedUnits
        
        $proceedWithAssignment = $false
        if ($UserExtensionAttribute1 -eq 'Supply, Trading & Shipping') {
            if ($TnSEntityQuotaAvailable -gt 0 -and $copilotTenantLicenses -gt 0) { $proceedWithAssignment = $true }
        } else {
            if ($AvailableEntityLicenses -gt 0 -and $copilotTenantLicenses -gt 0) { $proceedWithAssignment = $true }
        }

        if ($proceedWithAssignment) {
            Write-Log "Copilot license quota available for $userUPN (Entity: $UserExtensionAttribute1). Proceeding with SOU/TOU checks." -Level INFO
            $SOUTrainingStatus = "Error"
            if (([string]::IsNullOrWhiteSpace($LAppCase)) -or ($LAppCase -like '*Invalid NTIDUser1*')) {
                Write-Log "No valid LApp case found for $userUPN ($LAppCase). Creating new LApp case." -Level INFO
                Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Copilot license request approved' -StorageAccountNameForEmail $StorageAccountName -ContainerNameForEmail $CopilotEmailTemplateContainer -TemplateName 'license_has_been_approved.html' -Replacements @{}
                $LAppCaseNumberFromSF = Invoke-SalesforceCase -UserName $MgUser.DisplayName -UserNTID $MgUser.onPremisesSamAccountName
                if ($LAppCaseNumberFromSF) {
                    if ($LAppCaseNumberFromSF -like "*Case Already exists for this combination*") {
                        $LAppCase = ($LAppCaseNumberFromSF -split 'Case Number : ')[1]
                    } else {
                        $LAppCase = $LAppCaseNumberFromSF
                    }
                    Write-Log "LApp Case for $userUPN: $LAppCase. Updating DB and SNOW." -Level INFO
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 3, LAppCase='$LAppCase', LAppCaseCreatedDate = GETUTCDATE(), ProcessedDate = GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'SOU Training assigned' WHERE ID = $ID;"
                    Update-TaskStatus -TicketNumber $TaskNumber -State '6' -WorkNotes "Copilot license approved. LApp case $LAppCase raised. Awaiting training check."
                    Update-TicketStatus -TicketNumber $RITMNumber -State '-5' -Stage 'Pending Training' -WorkNotes "Copilot license approved. LApp case $LAppCase raised. Awaiting training check."
                    Update-EntityQuota -UserEntity $UserExtensionAttribute1 -TicketStage 'Pending Training'
                    $SOUTrainingStatus = "PendingLAppCreation"
                } else {
                    ScriptError -msg "Failed to create or retrieve LApp case for $userUPN."
                    $SOUTrainingStatus = "ErrorCreatingLApp"
                }
            } else {
                 Write-Log "Existing LApp case $LAppCase for $userUPN. Checking SOU/TOU status." -Level INFO
                 if (-not $CSODReportPath) {
                     ScriptError -msg "CSOD Report path not available, cannot check SOU for $userUPN."
                     $SOUTrainingStatus = "ErrorNoCSODFile"
                 } else {
                    if ($UserExtensionAttribute1 -eq 'Supply, Trading & Shipping') {
                        $SOUTrainingStatus = Get-SOUStatus -UserUPN $userUPN -UserEntity $UserExtensionAttribute1 -CornerstoneFilePath $CSODReportPath `
                                            -DBMessageID $ID -CurrentTaskNumber $TaskNumber -CurrentRITMNumber $RITMNumber `
                                            -LAppCaseAssignedDateFromDB $LAppCaseCreatedDate -UserExtensionAttribute1FromContext $UserExtensionAttribute1
                    } else {
                        $SOUCheckNonTS = Get-SOUStatus -UserUPN $userUPN -UserEntity $UserExtensionAttribute1 -CornerstoneFilePath $CSODReportPath `
                                            -DBMessageID $ID -CurrentTaskNumber $TaskNumber -CurrentRITMNumber $RITMNumber `
                                            -LAppCaseAssignedDateFromDB $LAppCaseCreatedDate -UserExtensionAttribute1FromContext $UserExtensionAttribute1
                        $TOUCheckNonTS = Get-TOUStatus -UserUPN $userUPN
                        if ($SOUCheckNonTS -eq "Passed" -and $TOUCheckNonTS -eq "Passed") { $SOUTrainingStatus = "Passed" }
                        elseif ($SOUCheckNonTS -eq "Failed" -or $TOUCheckNonTS -eq "Failed") { $SOUTrainingStatus = "Failed" }
                        elseif ($SOUCheckNonTS -eq "Expired" -or $TOUCheckNonTS -eq "Expired") { $SOUTrainingStatus = "Expired" }
                        elseif ($SOUCheckNonTS -eq "PTW_Failed" -or $TOUCheckNonTS -eq "PTW_Failed") { $SOUTrainingStatus = "PTW_Failed" }
                        else { $SOUTrainingStatus = "Pending" }
                    }
                 }
            }

            Write-Log "SOU/TOU Training status for $userUPN: $SOUTrainingStatus" -Level DEBUG
            if ($SOUTrainingStatus -notin ("PendingLAppCreation", "ErrorCreatingLApp", "ErrorNoCSODFile", "Expired", "PTW_Failed", "PTW_Missing")) {
                 $CopilotAssignmentResult = Invoke-UpgradeToCopilot -UserUPN $userUPN -SOUTrainingStatusToUse $SOUTrainingStatus -UserEntraGUID $MgUser.Id `
                                            -TaskNumberToUpdate $TaskNumber -RITMNumberToUpdate $RITMNumber -LAppCaseFromContext $LAppCase `
                                            -UserExtensionAttribute1ForQuota $UserExtensionAttribute1 -DBRecordIDForFailureUpdate $ID `
                                            -TaskNumberToUpdate $TaskNumber -RITMNumberToUpdate $RITMNumber -LAppCaseFromContext $LAppCase `
                                            -UserExtensionAttribute1ForQuota $UserExtensionAttribute1 -DBRecordIDForFailureUpdate $ID
                if ($CopilotAssignmentResult -eq 'Assigned') {
                    Write-Log "Copilot license successfully assigned to $userUPN. Sending emails and updating records." -Level INFO
                    Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Getting started with Copilot for Microsoft 365' -StorageAccountNameForEmail $StorageAccountName -ContainerNameForEmail $CopilotEmailTemplateContainer -TemplateName 'getting_started_with_copilot.html' -Replacements @{}
                    if ($UserExtensionAttribute1 -eq 'Supply, Trading & Shipping') {
                        Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject 'Copilot for M365 – additional guidance for Trading & Shipping' -StorageAccountNameForEmail $StorageAccountName -ContainerNameForEmail $CopilotEmailTemplateContainer -TemplateName 'getting_started_with_copilot_T&S.html' -Replacements @{}
                    }
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'License assigned' WHERE ID = $ID;"
                    Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes 'Copilot license assigned. Task closed.'
                    Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes 'Copilot license assigned. RITM closed.'
                } elseif ($CopilotAssignmentResult -eq 'Pending') {
                    Write-Log "Copilot license assignment for $userUPN is still pending SOU/TOU completion. Will re-evaluate in next run." -Level INFO
                } elseif ($CopilotAssignmentResult -eq 'Failed' -or $SOUTrainingStatus -in ("Expired", "PTW_Failed", "PTW_Missing")) {
                    Write-Log "Copilot license processing for $userUPN ended with status: $CopilotAssignmentResult / $SOUTrainingStatus. Record should be closed." -Level INFO
                } else {
                     ScriptError -msg "Error during Copilot license assignment for $userUPN. Result: $CopilotAssignmentResult. SOU Status: $SOUTrainingStatus"
                }
            }
        } else {
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
        $alreadyHasTargetLicenseE1E5 = Get-LicenseAllocationStatus -emailID $userUPN -action $action -LicenseType 'Microsoft365'
        if ($alreadyHasTargetLicenseE1E5) {
            Write-Log "User $userUPN already has the target M365 license for action '$action'. Closing RITM/Task and DB record." -Level INFO
            $completionCommentE1E5 = "User already has target M365 license ($action)"
            Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes $completionCommentE1E5
            Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes $completionCommentE1E5
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + '$completionCommentE1E5' WHERE ID = $ID;"
            continue
        }

        if (-not ([string]::IsNullOrEmpty($SaviyntExitCodeFromDB)) -and $SaviyntExitCodeFromDB -ne "Success" -and $SaviyntExitCodeFromDB -notlike "NotE5InSaviynt*" ) {
             Write-Log "Previous Saviynt attempt for $userUPN had error: $SaviyntExitCodeFromDB. Snow Task: $SnowTicketNumberFromDB. Not reprocessing via Saviynt." -Level WARN
             Update-TicketStatus -TicketNumber $RITMNumber -WorkNotes "Previous Saviynt processing for $action $LicenseType resulted in error code '$SaviyntExitCodeFromDB'. Manual follow-up via task $SnowTicketNumberFromDB may be required."
             continue
        }
        
        if (-not ([string]::IsNullOrEmpty($SaviyntTrackIDFromDB)) -and $SaviyntExitCodeFromDB -eq "Success" ) {
            $isReplicated = Get-SaviyntLicenseReplicationStatus -emailID $userUPN -action $action -LicenseType 'Microsoft365'
            if ($isReplicated) {
                Write-Log "M365 license ($action) for $userUPN now replicated in Entra. Saviynt Tracking ID: $SaviyntTrackIDFromDB." -Level INFO
                $completionCommentE1E5Rep = "License $action replicated (Saviynt: $SaviyntTrackIDFromDB)"
                Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes $completionCommentE1E5Rep
                Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes $completionCommentE1E5Rep
                Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + '$completionCommentE1E5Rep' WHERE ID = $ID;"
                continue
            } else {
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
                continue
            }
        }

        if (([string]::IsNullOrEmpty($SaviyntTrackIDFromDB)) -or ($action -eq "downgrade" -and $SaviyntExitCodeFromDB -eq "NotE5InSaviyntNoDowngradeNeeded") ) {
            $ThisRunProcessedE1E5++
            $saviyntActionResult = $null
            if ($action -eq 'upgrade') {
                $e5_skus = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq 'SPE_E5' }
                $availableE5Licenses = $e5_skus.PrepaidUnits.Enabled - $e5_skus.ConsumedUnits
                $e5Threshold = $availableE5Licenses / 2
                if ($availableE5Licenses -gt $e5Threshold) {
                    Write-Log "Attempting E5 upgrade for $userUPN via Saviynt." -Level INFO
                    Invoke-UpgradeToE5 -UserUPNForE5 $userUPN
                    $saviyntActionResult = "Processed"
                } else {
                    Write-Log "Not enough E5 licenses in tenant pool ($availableE5Licenses available, threshold $e5Threshold). Upgrade for $userUPN on hold." -Level WARN
                    Update-TicketStatus -TicketNumber $RITMNumber -State '5' -Stage 'On Hold' -WorkNotes "E5 license pool low. Request on hold."
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 4, Comments = ISNULL(Comments + ' | ', '') + 'E5 pool low, on hold.' WHERE ID = $ID;"
                    $saviyntActionResult = "SkippedNoPool"
                }
            } elseif ($action -eq 'downgrade') {
                $e1_skus = Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq 'STANDARDPACK' }
                $availableE1Licenses = $e1_skus.PrepaidUnits.Enabled - $e1_skus.ConsumedUnits
                $e1Threshold = $availableE1Licenses / 2
                if ($availableE1Licenses -gt $e1Threshold) {
                    Write-Log "Attempting E1 downgrade for $userUPN via Saviynt." -Level INFO
                    Invoke-DowngradeToE1 -UserUPNForE1 $userUPN
                    $saviyntActionResult = "Processed"
                } else {
                     Write-Log "E1 license pool low ($availableE1Licenses available, threshold $e1Threshold), but downgrade should proceed as it frees up E5. Forcing downgrade attempt." -Level WARN
                     Invoke-DowngradeToE1 -UserUPNForE1 $userUPN
                     $saviyntActionResult = "Processed"
                }
            }

            if ($saviyntActionResult -eq "Processed") {
                Write-Log "Saviynt action '$action' for $userUPN completed. Saviynt Refs: $($saviyntRequestReferenceIDs | ConvertTo-Json -Compress)" -Level INFO
                $dbStatusIDForSaviynt = 2
                $dbCommentsSaviynt = "$action to $($LicenseType) sent to Saviynt. Exit: $($saviyntRequestReferenceIDs.ExitCode)."
                if ($saviyntRequestReferenceIDs.ExitCode -ne "Success" -and $saviyntRequestReferenceIDs.ExitCode -ne "NotE5InSaviyntNoDowngradeNeeded") {
                    $dbCommentsSaviynt += " SNOW Task: $($saviyntRequestReferenceIDs.SnowTaskNumber)."
                     Update-TicketStatus -TicketNumber $RITMNumber -WorkNotes "Saviynt processing for $action $LicenseType resulted in ExitCode '$($saviyntRequestReferenceIDs.ExitCode)'. Associated SNOW Task: $($saviyntRequestReferenceIDs.SnowTaskNumber)."
                } else {
                     Update-TicketStatus -TicketNumber $RITMNumber -WorkNotes "Request for $action $LicenseType sent to Saviynt. Tracking ID: $($saviyntRequestReferenceIDs.trackingID). Replication may take up to 6 hours."
                }
                
                Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = $dbStatusIDForSaviynt, ProcessedDate = GETUTCDATE(), SaviyntTrackID = '$($saviyntRequestReferenceIDs.trackingID)', SaviyntTransactionID = '$($saviyntRequestReferenceIDs.APITransactionID)', SaviyntExitCode = '$($saviyntRequestReferenceIDs.ExitCode)', snowTicketNumber = '$($saviyntRequestReferenceIDs.SnowTaskNumber)', UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + '$dbCommentsSaviynt' WHERE ID = $ID;"
            }
        }

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
