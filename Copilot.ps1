<#
.SYNOPSIS
    License-Queue-Process
.DESCRIPTION
    Picks message from azure queue and process it.
    it can process assignment of Copilot licenses.
.NOTES
.COMPONENT
    Requires Modules Az,Graph
.NOTES
    Name                : Vinay Gupta
    Email               : vinay.gupta1@bp.com
    CreatedDate         : 2024/05/03
    Version             : 1.2
    Enhancement Date    : 2025/10/02 (YYYY/MM/DD)
    Enhancements        : Included ST&S entity copilot license allocation
.WEBHOOKS
    # Need to provide WEBHOOKS
#>

$PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
Write-Output "Using Hybrid Worker: $($env:computername)"

#Start-Transcript -Path 'D:\Temp\copilot_logs.txt'

# Define the license pool threshold limit
$threshold = 30
$ProcessCutoff = 1000

$TestMode = $false
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
        $msg
    )

    $respObj = @{
        UPN   = $UserUPN
        Error = $msg
    }
    $response = $respObj | ConvertTo-Json

    Write-Log $msg -Level 'ERROR'
    Write-Log $response -Level 'ERROR'
    Write-Log 'One or more errors occurred, Refer the output screen for details' -Level 'ERROR'

    if($LicenseType -eq 'MicrosoftCopilot'){
        try{
            Update-TicketStatus -TicketNumber $RITMNumber -Stage 'Validation' -State '-5' -WorkNotes "Failed for : $UserUPN, Error : $msg"
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
        }
    }
    
    $ShortDesc = 'Failure; Automatic Fulfilment Not Possible - M365 License'
    try{
        $ticket = New-SnowTask -shortDescription $ShortDesc -Description $response -UserUPN $UserUPN
        Write-Log "SNOW ticket logged: $ticket" -Level 'ERROR'
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
    }
    
    # Add Error message to Dataverse
    try {
        $bodyContent = @{
            new_requestedby                          = $RequestedBy
            new_requestedfor                         = $userUPN
            'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
            new_action                               = $action
            new_requestsource                        = 'DWP-Automation'
            new_requesttime                          = $RequestedTime
            new_processedtime                        = $ProcessedTime
            new_completiontime                       = $completionTime
            new_lappcasenumber                       = $LAppCase
            new_saviynttrackingid                    = $saviyntRequestReferenceIDs.trackingID
            new_status                               = 'Error'
            new_saviynttransactionid                 = $saviyntRequestReferenceIDs.APITransactionID
            new_errorcode                            = $msg
        } | ConvertTo-Json

        $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

        Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
    }
    catch {
        Write-Log $bodyContent -Level 'ERROR'
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'Verbose'
        Write-Log 'Failed to POST record in the dataverse table License_queue_request during scriptError.' -Level 'ERROR'
    }
    return
}

Function New-SnowTask {
    param(
        $shortDescription,
        $Description,
        $UserUPN
    )

    $header = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $SNOW_Oauth_Token"
    }

    $body = @{
        short_description = $shortDescription
        description       = $Description
        cmdb_ci           = 'M365 Copilot'
        #assignment_group  = 'cf4ddcb5db8f1f00953fa103ca961925'
        assignment_group  =  '5373ac80db20a59017dbcf8315961995'
        priority          = 4
        contact_type      = 'Via API'
        u_requested_for   = $UserUPN
        u_source          = 'DWP-Automation'
    }

    $params = @{
        method = 'POST'
        uri    = "$SnowURL/api/snc/v1/bp_rest_api/createRecord/c12586b6db9818d0389f3951f396197c/createServiceTask"
        body   = $body | ConvertTo-Json
        header = $header
    }

    try {
		(Invoke-RestMethod @params -ErrorAction stop).result.number
    }
    catch {
        $ex = $_
        $ex.message
        # Error logging SNOW ticket. Trying again with 'RequestedBy' value
        $body.u_requested_for = $UserUPN
        $params = @{
            method = 'POST'
            uri    = "$SnowURL/api/snc/v1/bp_rest_api/createRecord/c12586b6db9818d0389f3951f396197c/createServiceTask"
            body   = $body | ConvertTo-Json
            header = $header
        }
        try {
                (Invoke-RestMethod @params -ErrorAction stop).result.number
        }
        catch {
            $ex = $_
            $body
            $params
            Write-Log "Failed to log SNOW ticket`n$($ex.message)" -Level 'Verbose'
            Continue
        }
    }
}

function Convert-ToDateTime {
    param (
        [string]$dateString
    )
 
    # Define an array of date formats to check against
    $dateFormats = @(
        'dd/MM/yyyy'
    )
 
    foreach ($format in $dateFormats) {
        try {
            # Try to parse the date string using the current format
            $dateTime = [datetime]::ParseExact($dateString, $format, $null)
            return $dateTime
        }
        catch {
            # Continue if the current format does not match
            continue
        }
    }
 
    try {
        # Try to parse the date using the general Parse method as a fallback
        $dateTime = [datetime]::Parse($dateString)
        return $dateTime
    }
    catch {
        # Throw an error if the date format could not be determined or parsed
        throw "Unable to determine the date format of '$dateString'. Please provide a date in a recognized format."
    }
}

function Get-MSFormToken {
    $KeyvaultName = 'zne-dwp-p-kvl'
    $scope = 'https://forms.cloud.microsoft/.default'

    $refreshtoken = Get-AzKeyVaultSecret -VaultName 'zne-dwp-p-kvl' -Name 'api-dwp-graph-refreshToken' -AsPlainText
    $clientId = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Dataverse-AppID' -AsPlainText
    $tenantid = 'ea80952e-a476-42d4-aaf4-5457852b0f7e'

    $body = @{
        client_id     = $clientId
        scope         = $scope
        grant_type    = 'refresh_token'
        refresh_token = $refreshToken
    }
    $response = Invoke-WebRequest "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Method POST -Body $body
    $tokenobj = ConvertFrom-Json $response.Content

    return $tokenobj.access_token
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
    }

    $Headers = @{
        'Authorization' = "Bearer $MSFormToken"
    }

    # GET FORM RESPONSES
    $formResponsesUrl = "https://forms.office.com/formapi/api/$TenantId/users/$UserID/forms('$formId')/responses"
    $response = Invoke-RestMethod -Uri $formResponsesUrl -Headers $headers -Method Get

    $ResponseObject = $response.value | Where-Object { $_.responder -eq $userUPN }

    if ($null -eq $ResponseObject) {
        #$Answer = 'Pending'

        return "Pending"
    }
    else {
        $Responder = $responseObject.responder
        $ResponseDate = $responseObject.submitDate
        $Answer = ($responseObject.answers | ConvertFrom-Json).answer1

        return $Answer
    }
}

function Get-SOUCornerstoneReport{
    # Set the Storage Account Context
    $azcontext = Set-AzContext -Subscription $StorageAccountSubscription

    try {
        $storageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountNameRSG -Name $storageAccountName -DefaultProfile $azcontext
        $storageAccountContext = $storageAccount.Context
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError('Failed to get storage account details.')
    }

    $gpgExecutablePath = 'C:\Program Files (x86)\GnuPG\bin\gpg.exe'
    $destinationFilePath = 'D:\Temp'
    $secretFileName = 'passphrase.txt'
    $containerName = 'copilot-sou-report-cornerstone'
    $PrivateKeyFile = 'copilot_prod_SECRET.asc'

    if (!(Test-Path $destinationFilePath)) {
        # Create D:\Temp if it doesn't exist
        New-Item -ItemType Directory -Force -Path $destinationFilePath
    }

    $passphraseFilePath = $destinationFilePath + '\' + $secretFileName
    $PrivateKeyFilePath = Join-Path $destinationFilePath $PrivateKeyFile

    try {
        $blobs = Get-AzStorageBlob -Container $containerName -Context $storageAccountContext | Where-Object { $_.Name -like 'Copilot_SOUReport_CSOD*' }
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError('Failed to get CSV file from container matching with name Copilot_SOUReport_CSOD.')
    }

    # Check if there are any matching blobs
    if ($blobs) {
        # Sort blobs by LastModified date and get the latest one
        $latestBlob = $blobs | Sort-Object -Property LastModified -Descending | Select-Object -First 1

        # Get the blob name
        $blobName = $latestBlob.Name

        $decryptedFilePath = 'D:\Temp\' + ($blobName -replace '\.pgp$', '')

        try {
            # Download the latest blob
            $fileblob = Get-AzStorageBlobContent -Blob $blobName -Container $containerName -Destination $destinationFilePath -Context $storageAccountContext -Force
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to download latest CSV file from storage container.')
        }

        try {
            # Download passphrase file in temp dir
            $passblob = Get-AzStorageBlobContent -Blob $secretFileName -Container $containerName -Destination $destinationFilePath -Context $storageAccountContext -Force
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to download passphrase file from storage container.')
        }

        # Set the path for the encrypted file and the passphrase file
        $encryptedFilePath = Join-Path $destinationFilePath $blobName
        $passphraseFilePath = Join-Path $destinationFilePath $secretFileName

        try {
            # Download the private key file
            $privatekeyblob = Get-AzStorageBlobContent -Blob $PrivateKeyFile -Container $containerName -Destination $destinationFilePath -Context $storageAccountContext -Force
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to download private key file from storage container.')
        }

        try {
            & $gpgExecutablePath --batch --yes --import $PrivateKeyFilePath | Out-Null
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to run GPG command to import the secret keys on hybrid worker.')
        }

        # Decrypt the file
        Invoke-Command -ScriptBlock {
            $gpgExecutablePath = 'C:\Program Files (x86)\GnuPG\bin\gpg.exe'
            try {
                & $gpgExecutablePath --batch --yes --pinentry-mode loopback --passphrase-file "$passphraseFilePath" --output "$decryptedFilePath" --decrypt "$encryptedFilePath" | Out-Null
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                ScriptError('Failed to decrypt the CSV report. GPG command failed.')
            }
        }

        return $decryptedFilePath
    }
    else {
        Write-Log "No blobs found matching the pattern 'Copilot_SOUReport_CSOD*' in storage container." -Level VERBOSE
        ScriptError('No blobs found matching the pattern Copilot_SOUReport_CSOD* in storage container.')
    }
}

#Function to get the SOU acceptance status from CSOD Report and TOU acceptance from MS Form for T&S users
function Get-SOUStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN,
        [Parameter(Mandatory = $true)]
        [string]$UserEntity,
        [Parameter(Mandatory = $true)]
        [string]$CornerstoneFilePath
    )

    #----------------------------GET MS FORM STATUS FOR THE USER----------------------------#
    try {
        $FormResponseValue = Get-MSFormResponse -UserUPN $UserUPN
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError("Failed to get MS Form response for the user $UserUPN.")
    }

    #------------GET STATUS FROM THE CSOD CVS FILE--------------------
    try {
        $csvContent = Get-Content -Path $CornerstoneFilePath -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError('Failed to get SOU CSV report content.')
    }
    # Skip the first 7 lines to get to the actual data
    $csvData = $csvContent | Select-Object -Skip 7
    $csvParsed = $csvData | ConvertFrom-Csv

    $selectedData = $csvParsed | Select-Object 'Training title', 'User full name', 'User e-mail', 'Quiz attempt date', 'Quiz SUCCESS Status', 'Training record status', 'Training record completed date'
    $today = (Get-Date)
    $TwentyEightDaysAgo = (Get-Date).AddDays(-28)
    $365DaysAgo = (Get-Date).AddDays(-365)

    # Filter records where "Training record completed date" is within the last 28 days (ignoring time)
    $filteredData = $selectedData | Where-Object {
        ($null -ne $_.'Training record completed date') `
        -and (!([string]::IsNullOrWhiteSpace($_.'Training record completed date'))) `
        -and (!([string]::IsnullOrEmpty($_.'Training record completed date')))
    } | Where-Object {
        $TrainingCompletedString = $_.'Training record completed date'
        $trainingCompletedDate = $TrainingCompletedString -split ' ' | Select-Object -First 1
        (Convert-ToDateTime($trainingCompletedDate)) -ge $365DaysAgo -and (Convert-ToDateTime($trainingCompletedDate)) -le $today
    }

    $UserSOUData = $filteredData | Where-Object { ($_.'User e-mail' -eq $UserUPN) -and ($_.'Training title' -like '*Copilot for Microsoft 365*')  } | Select-Object -Unique
    $UserPTWData = $selectedData | Where-Object { ($_.'User e-mail' -eq $UserUPN) -and ($_.'Training title' -like '*PTW - Microsoft 365 Copilot Generative AI*') }

    if($null -ne $LAppCaseAssignedDate){
        $LAppCaseAssignedDate = Get-Date $LAppCaseAssignedDate

        if ($LAppCaseAssignedDate -lt $TwentyEightDaysAgo) {
            Write-Log 'Training assignment date is older than 28 days. Training has expired.'

            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Training expired' WHERE ID = $id;"
            Write-Log "Message with UPN $userUPN - $LicenseType $Action deleted from the DB."
            
            try {
                $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes 'Training assignment date is older than 28 days. Training has expired. Closing the task.'
                Write-Log "Task $TaskNumber updated - Training has expired."
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                ScriptError 'Failed to update task in snow at Training has expired..'
            }

            try {
                $UpdateTicket = Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Training Expired' -WorkNotes 'Training assignment date is older than 28 days. Training has expired. Closing the ticket.'
                Write-Log "Ticket $RITMNumber updated - Training has expired."
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                Write-Log 'Failed to update ticket status at Training has expired.'
            }

            try {
                $SnowTableUpdateStatus = Update-EntityQuota -UserEntity $UserExtensionAttribute1 -TicketStage 'Training Expired'

                if ($SnowTableUpdateStatus -eq 'Success') {
                    Write-Log 'SNOW Table updated successfully'
                }
                else {
                    Write-Log 'SNOW Table update failed'
                }
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                ScriptError('Failed to update SNOW table with new available license count.')
            }

            # Add Final message to Dataverse
            $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')

            try {
                $bodyContent = @{
                    new_requestedby                          = $RequestedBy
                    new_requestedfor                         = $userUPN
                    'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
                    new_action                               = $action
                    new_requestsource                        = 'DWP-Automation'
                    new_requesttime                          = $RequestedTime
                    new_processedtime                        = $ProcessedTime
                    new_completiontime                       = $completionTime
                    new_lappcasenumber                       = $LAppCase
                    new_saviynttrackingid                    = $saviyntRequestReferenceIDs.trackingID
                    new_status                               = 'Complete'
                    new_saviynttransactionid                 = $saviyntRequestReferenceIDs.APITransactionID
                    new_errorcode                            = 'Training Expired'
                } | ConvertTo-Json

                $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

                Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
                Write-Log "**********************************************************************"
                continue
            }
            catch {
                Write-Log $bodyContent -Level 'ERROR'
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                Write-Log 'Failed to POST record in the dataverse table License_queue_request after training expiry.' -Level 'ERROR'
                Write-Log "**********************************************************************"
                continue
            }
        }else{
            # Check if the user has completed the PTW training
            if($null -ne $UserPTWData){
                if(($UserPTWData.'Training record status' -notcontains 'Completed') -and ($UserSOUData.'Training record status' -eq 'Completed')){
                    #Send email for license rejection
                    try {
                        $EmailSubject = 'Copilot license request rejected'
                        $TemplateName = 'Microsft_365_copilot_ST&S_PTW_Pending.html'
                        $Replacements = @{}
                        Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject $EmailSubject -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName $TemplateName -Replacements $Replacements
                        Write-Log 'Sent email to the user - Copilot license request rejected due to PTW non-completion'
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex
                        Write-Log 'Failed to send email - rejected due to PTW non-completion.'
                    }

                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Rejected due to PTW non-completion' WHERE ID = $id;"
                    Write-Log "Message with UPN $userUPN - $LicenseType $Action deleted from the queue."
                    
                    try {
                        $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes "User's Passport To Work training record shows as incomplete. Microsoft 365 Copilot license request rejected. Closing the task."
                        Write-Log "Task $TaskNumber updated - rejected due to PTW non-completion."
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError 'Failed to update task in snow at rejected due to PTW non-completion..'
                    }

                    try {
                        $UpdateTicket = Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Training Expired' -WorkNotes "User's Passport To Work training record shows as incomplete. Microsoft 365 Copilot license request rejected. Closing the task."
                        Write-Log "Ticket $RITMNumber updated - rejected due to PTW non-completion."
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to update ticket status at rejected due to PTW non-completion.'
                    }

                    try {
                        $SnowTableUpdateStatus = Update-EntityQuota -UserEntity $UserExtensionAttribute1 -TicketStage 'Training Expired'

                        if ($SnowTableUpdateStatus -eq 'Success') {
                            Write-Log 'SNOW Table updated successfully'
                        }
                        else {
                            Write-Log 'SNOW Table update failed'
                        }
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError('Failed to update SNOW table with new available license count.')
                    }

                    # Add Final message to Dataverse
                    $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')

                    try {
                        $bodyContent = @{
                            new_requestedby                          = $RequestedBy
                            new_requestedfor                         = $userUPN
                            'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
                            new_action                               = $action
                            new_requestsource                        = 'DWP-Automation'
                            new_requesttime                          = $RequestedTime
                            new_processedtime                        = $ProcessedTime
                            new_completiontime                       = $completionTime
                            new_lappcasenumber                       = $LAppCase
                            new_saviynttrackingid                    = $saviyntRequestReferenceIDs.trackingID
                            new_status                               = 'Complete'
                            new_saviynttransactionid                 = $saviyntRequestReferenceIDs.APITransactionID
                            new_errorcode                            = 'PTW Training incomplete'
                        } | ConvertTo-Json

                        $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

                        Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
                        Write-Log "**********************************************************************"
                        continue
                    }
                    catch {
                        Write-Log $bodyContent -Level 'ERROR'
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to POST record in the dataverse table License_queue_request after training expiry.' -Level 'ERROR'
                        Write-Log "**********************************************************************"
                        continue
                    }
                }
            }
        }
    }

    
    if($UserEntity -eq 'Supply, Trading & Shipping' -and ($null -ne $UserPTWData)){
        if ($null -ne $UserSOUData) {
            if (($UserPTWData.'Training record status' -contains 'Completed') -and ($UserSOUData.'Training record status' -eq 'Completed')) {
                # Use a switch statement for FormResponseValue
                switch ($FormResponseValue) {
                    'Accept' { 
                        $SOUStatus = 'Passed' 
                        break 
                    }
                    'Decline' { 
                        $SOUStatus = 'Failed' 
                        break 
                    }
                    'Pending' { 
                        $SOUStatus = 'Pending' 
                        break 
                    }
                    default { 
                        ScriptError 'Unknown response received from SOU acceptance MS Form.' 
                    }
                }
            }
            else {
                $SOUStatus = 'Failed'
            }
        }
        else {
            $SOUStatus = 'Pending'
        }
        return $SOUStatus
    }elseif($null -ne $UserSOUData) {
        if ($UserSOUData.'Training record status' -eq 'Completed') {
            # Use a switch statement for FormResponseValue
            switch ($FormResponseValue) {
                'Accept' { 
                    $SOUStatus = 'Passed' 
                    break 
                }
                'Decline' { 
                    $SOUStatus = 'Failed' 
                    break 
                }
                'Pending' { 
                    $SOUStatus = 'Pending' 
                    break 
                }
                default { 
                    ScriptError 'Unknown response received from SOU acceptance MS Form.' 
                }
            }
        }
        else {
            $SOUStatus = 'Failed'
        }
        return $SOUStatus
    }else {
        $SOUStatus = 'Pending'
        return $SOUStatus
    }
}

#Function to get the TOU acceptance status from MS Form for Non-T&S users
function Get-TOUStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN
    )

    #----------------------------GET MS FORM STATUS FOR THE USER----------------------------#
    try {
        $FormResponseValue = Get-MSFormResponse -UserUPN $UserUPN
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError("Failed to get MS Form response for the user $UserUPN.")
    }

    # Use a switch statement for FormResponseValue
    switch ($FormResponseValue) {
        'Accept' { 
            $SOUStatus = 'Passed' 
            break 
        }
        'Decline' { 
            $SOUStatus = 'Failed'
            break 
        }
        'Pending' { 
            $SOUStatus = 'Pending' 
            break 
        }
        default { 
            ScriptError 'Unknown response received from SOU acceptance MS Form.' 
        }
    }

    return $SOUStatus
}

function Invoke-UpgradeToCopilot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN,

        [Parameter(Mandatory = $true)]
        [string]$SOUTrainingStatus,

        [Parameter(Mandatory = $true)]
        [string]$UserEntraGUID,

        [Parameter(Mandatory = $true)]
        [string]$TaskNumber
    )

    if ($SOUTrainingStatus -eq 'Passed') {
        #Add user to copilot security group
        # G O365 Copilot EAP Pilot users (ffe25b27-0c4a-418e-b2f4-52562b038b89)
        # G AAD CoPilot M365 Pending License Users (735c9f9c-b778-4020-94c8-e6a07d73bed7)

        #$CopilotCompletedGroupID = 'ffe25b27-0c4a-418e-b2f4-52562b038b89'   # G O365 Copilot EAP Pilot users
        #$CopilotCompletedGroupID = '2dcedb7c-77ad-452b-9c64-6724aea37c76'    # G O365 Copilot PoC users
        try {
            New-MgGroupMember -GroupId $CopilotCompletedGroupID -DirectoryObjectId $UserEntraGUID
            Write-Log "User $UserUPN has been successfully added to the copilot licensing Entra group." -Level 'INFO'
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to add user to Copilot Completed Group.')
        }
  
        $LicenseAssignmentStatus = 'Assigned'
        
    }
    elseif ($SOUTrainingStatus -eq 'Pending') {

        Write-Log "User is yet to complete the SOU training with LApp case $LAppCase. Awaiting completion report..." -Level 'INFO'
        $LicenseAssignmentStatus = 'Pending'
        
        try {
            $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '6' -WorkNotes "Learning App case $LAppCase has already been raised. Awaiting SOU training completion check."
            Write-Log "Task $TaskNumber updated - Awaiting training completion check."
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to update task in snow at Awaiting training status check..')
        }

        try {
            $UpdateTicket = Update-TicketStatus -TicketNumber $RITMNumber -State '-5' -Stage 'Pending Training' -WorkNotes "Learning App case $LAppCase has already been raised. Awaiting SOU training completion check."
            Write-Log "Ticket $RITMNumber updated - Awaiting training completion check."
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            Write-Log 'Failed to update ticket status at Awaiting training status check.'
        }
						
        continue
    }
    elseif ($SOUTrainingStatus -eq 'Failed') {

        Write-Log 'User has failed the SOU training or declined SOU. Check CSOD report for further clarification.'
        try {
            $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes 'User has failed the SOU training or declined SOU. Check CSOD report for further clarification. Closing the ticket.'
            Write-Log "Task $TaskNumber updated - User has failed the SOU training or declined SOU.."
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to update task in snow at declined SOU.')
        }

        try {
            $UpdateTicket = Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes 'User has failed the SOU training or declined SOU. Check CSOD report for further clarification. Closing the ticket.'
            Write-Log "RITM $RITMNumber updated - User has failed the SOU training or declined SOU."
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            Write-Log 'Failed to update ticket status at declined SOU.'
        }

        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'SOU/TOU Failed' WHERE ID = $id;"
        Write-Log "Message with UPN $userUPN - $LicenseType $Action deleted from the queue due to SOU or TOU failure."

        try {
            $SnowTableUpdateStatus = Update-EntityQuota -UserEntity $UserExtensionAttribute1 -TicketStage 'Training Expired'

            if ($SnowTableUpdateStatus -eq 'Success') {
                Write-Log 'SNOW Table updated successfully'
            }
            else {
                Write-Log 'SNOW Table update failed'
            }
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to update SNOW table with new available license count.')
        }

        # Add Final message to Dataverse
        $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')

        try {
            $bodyContent = @{
                new_requestedby                          = $RequestedBy
                new_requestedfor                         = $userUPN
                'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
                new_action                               = $action
                new_requestsource                        = 'DWP-Automation'
                new_requesttime                          = $RequestedTime
                new_processedtime                        = $ProcessedTime
                new_completiontime                       = $completionTime
                new_lappcasenumber                       = $null
                new_saviynttrackingid                    = $saviyntRequestReferenceIDs.trackingID
                new_status                               = 'Complete'
                new_saviynttransactionid                 = $saviyntRequestReferenceIDs.APITransactionID
                new_errorcode                            = 'SOU/TOU Failed'
            } | ConvertTo-Json

            $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

            Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
            Write-Log "**********************************************************************"
            continue
        }
        catch {
            Write-Log $bodyContent -Level 'ERROR'
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            Write-Log 'Failed to POST record in the dataverse table License_queue_request after training expiry.' -Level 'ERROR'
            Write-Log "**********************************************************************"
            continue
        }

        $LicenseAssignmentStatus = 'Failed'
    }

    return $LicenseAssignmentStatus
}

#Function to check license upgrade/downgrade replication status after processing
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
        Write-Log $ex -Level 'ERROR'
        ScriptError('Failed to get allocated license details for the user.')
    }

    if ($action -eq 'upgrade') {
        if (($LicenseType -eq 'MicrosoftCopilot' -and $licenses.skupartnumber -like '*365_Copilot*')) {
            Write-Log 'User has a Copilot license.' -Level 'DEBUG'
            $lic_allocation = $true
        }
        else {
            $lic_allocation = $false
        }
    }
    else {
        $lic_allocation = $false
    }

    return $lic_allocation
}

function Get-EntityQuota {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserEntity
    )
    # Check for entity wise available licenses
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
        $response = Invoke-RestMethod @params -ErrorAction stop
    }
    catch {
        Write-Log 'Failed to get entity license details from SNOW table.' -Level 'ERROR'
        $ex = $_.Exception.Message
        ScriptError 'Failed to get entity license details from SNOW table.'
    }
    $AllEntityDetails = $response.result

    foreach ($entity in $AllEntityDetails) {
        if ($entity.entity -like $UserEntity) {
            $EntityQuota = $entity.quota
            $EntityAvailableLicenses = $entity.available_licenses
        }
    }

    return $EntityAvailableLicenses
}

function Update-EntityQuota {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserEntity,

        [Parameter(Mandatory = $true)]
        [string]$TicketStage
    )

    $EntityAvailableLicenses = Get-EntityQuota -UserEntity $UserEntity

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

    $header = @{    
        'Content-Type' = 'application/json'    
        Authorization  = "Bearer $SNOW_Oauth_Token"
        'Accept'       = 'application/json'
    }

    $EntityAvailableLicenses = [int]$EntityAvailableLicenses

    if ($TicketStage -eq 'Pending Training') {
        $EntityAvailableLicenses -= 1
        $body = @{
            available_licenses = $EntityAvailableLicenses
        } | ConvertTo-Json
    }
    elseif ($TicketStage -eq 'Training Expired') {
        $EntityAvailableLicenses += 1
        $body = @{
            available_licenses = $EntityAvailableLicenses
        } | ConvertTo-Json
    }
    elseif ($TicketStage -eq 'Rejected') {
        $EntityAvailableLicenses += 1
        $body = @{
            available_licenses = $EntityAvailableLicenses
        } | ConvertTo-Json
    }
    else {
        $body = @{
            available_licenses = $EntityAvailableLicenses
        } | ConvertTo-Json
    }
    
    $params = @{    
        method = 'PUT'
        uri    = "$SnowURL/api/snc/v2/bp_rest_api/c12586b6db9818d0389f3951f396197c/UpdateProductLicense/$sysid"
        body   = $body
        header = $header
    }
    
    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        return 'success'
    }
    catch {
        Write-Log 'Failed to update entity license details in SNOW table.' -Level 'ERROR'
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError 'Failed to update entity license details in SNOW table.'
    }
}

function Send-CopilotEmail {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SendTo,

        [Parameter(Mandatory = $true)]
        [string]$CC,

        [Parameter(Mandatory = $true)]
        [string]$EmailSubject,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$TemplateName,

        [Parameter(Mandatory = $false)]
        [array]$Replacements
    )

    $body = @{
        client_id     = $Email_AppID
        client_secret = $Email_Secret
        grant_type    = 'client_credentials'
        scope         = "api://$scope/.default"
    }

    $uri = 'https://login.microsoftonline.com:443/ea80952e-a476-42d4-aaf4-5457852b0f7e/oauth2/v2.0/token'
    $bearer = Invoke-RestMethod -Method POST -Uri "$uri" -Body $body

    $header = @{
        'Content-Type' = 'application/json'
        Authorization  = "Bearer $($bearer.access_token)"
    }

    $body = @{
        SendTo             = $SendTo
        Cc                 = $CC
        EmailSubject       = $EmailSubject
        StorageAccountName = $StorageAccountName
        ContainerName      = $ContainerName
        TemplateName       = $TemplateName
        Replacements       = $Replacements
    }

    $jsonBody = $body | ConvertTo-Json

    $params = @{
        method  = 'POST'
        uri     = $Email_URI
        headers = $header
        body    = $jsonBody
    }

    try {
        Invoke-RestMethod @params
    }
    catch {
        Write-Log 'Failed to send email to the user. Error during Invoke.' -Level 'ERROR'
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
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
        $response = Invoke-RestMethod @params -ErrorAction stop
    }
    catch {
        Write-Log 'Failed to get RITM status from Service now. Error during Invoke.' -Level 'ERROR'
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
    }

    $response.result

    $script:ritmStatuses = [PSCustomObject]@{
        stage = $response.result.stage
        state = $response.result.state
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

    $body = @{
        state      = $State
        stage      = $Stage
        work_notes = $WorkNotes
    }

    $jsonBody = $body | ConvertTo-Json

    $params = @{
        method = 'PUT'
        uri    = "$snowURL/api/snc/v2/bp_rest_api/c12586b6db9818d0389f3951f396197c/updateRITM/$TicketNumber"
        header = $header
        body   = $jsonBody

    }

    try {
        Invoke-RestMethod @params
    }
    catch {
        Write-Log 'Failed to update RITM status in Service now. Error during Invoke.' -Level 'ERROR'
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
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

    $body = @{
        state      = $State
        work_notes = $WorkNotes
    }

    $jsonBody = $body | ConvertTo-Json

    $params = @{
        method = 'PUT'
        uri    = "$snowURL/api/snc/v1/bp_rest_api/updateRecord/c12586b6db9818d0389f3951f396197c/updateServiceTask?searchVal=numberIN$TicketNumber"
        header = $header
        body   = $jsonBody

    }
    try {
        Invoke-RestMethod @params
    }
    catch {
        Write-Log 'Failed to update Service Task status in Service now. Error during Invoke.' -Level 'ERROR'
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
    }
}

function Get-SalesforceJWTToken {
    try {
        $ContainerName = 'bau-license-allocation-process'
        $blobName = 'bpcolleagues.my.salesforce.com.pfx'
        $certificateDir = 'D:\Temp\'

        if (!(Test-Path $certificateDir)) {
            New-Item -ItemType Directory -Force -Path $certificateDir
        }

        try {
            $azcontext = Set-AzContext -Subscription $StorageAccountSubscription
            $storageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountNameRSG -Name $storageAccountName -DefaultProfile $azcontext
            $storageAccountContext = $storageAccount.Context

            $CertificateDownload = Get-AzStorageBlobContent -Container $containerName -Blob $blobName -Destination $certificateDir -Context $storageAccountContext -Force
        }
        catch {
            Write-Log $_.Exception.Message -Level 'ERROR'
            Write-Log 'Failed to get Azure context or retrieve SF certificate from container' -Level 'ERROR'
            ScriptError 'Failed to get Azure context or retrieve SF certificate from container'
        }

        try {
            $certificateName = (Get-ChildItem -Path $certificateDir | Where-Object Name -Like '*salesforce*').Name
            $certificatePath = $certificateDir + $certificateName
        }
        catch {
            Write-Log $_.Exception.Message -Level 'ERROR'
            Write-Log 'Failed to retrieve certificate name' -Level 'ERROR'
            ScriptError 'Failed to retrieve certificate name'
        }

        try {
            $certificatePassword = Get-AzKeyVaultSecret -VaultName 'zne-dwp-p-kvl' -Name 'Salesforce-API-Cert-Key' -AsPlainText
        }
        catch {
            Write-Log $_.Exception.Message -Level 'ERROR'
            Write-Log 'Failed to retrieve certificate password from Key Vault' -Level 'ERROR'
            ScriptError 'Failed to retrieve certificate password from Key Vault'
        }

        <#
        #DEV SF Env details
        $clientId = '3MVG91LYYD8O4krRFZk502yUZjncmXBIQ3ZAK50nWMywj9WNnGbA1vfq9hsl7Vsp4u_5LDv96YgWvyOxu0YGw'
        $usernameSF = 'pcsalesforce1@bp.com.colleagues.hrmdev'
        $audienceUrl = 'test.salesforce.com'
        $tokenUrl = 'https://test.salesforce.com/services/oauth2/token'


        #TEST SF Env details
        $clientId = "3MVG91LYYD8O4krRFZk502yUZjm5Gonr_Z_Mj8pL0DuEtyWnZSw_O_Ob2PxDzxiCH9tKQ1AFX6FiBoK3Cw5co"
        $usernameSF = "pcsalesforce1@bp.com.colleagues.hrmtest"
        $audienceUrl = "test.salesforce.com"
        $tokenUrl = "https://test.salesforce.com/services/oauth2/token"
        #>
        try {
            $securePassword = ConvertTo-SecureString -String $certificatePassword -AsPlainText -Force
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            )
        }
        catch {
            Write-Log $_.Exception.Message -Level 'ERROR'
            Write-Log 'Failed to load certificate' -Level 'ERROR'
            ScriptError 'Failed to load certificate'
        }

        $header = @{
            alg = 'RS256'
        }

        $expiryDate = [math]::Round((Get-Date).AddMinutes(60).Subtract((Get-Date '1970-01-01')).TotalSeconds)

        $claimset = @{
            iss = $clientId
            prn = $usernameSF
            aud = $audienceUrl
            exp = $expiryDate
        }

        try {
            $headerJson = $header | ConvertTo-Json -Compress
            $claimsetJson = $claimset | ConvertTo-Json -Compress
            $headerEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $claimsetEncoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($claimsetJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $inputToken = "$headerEncoded.$claimsetEncoded"
        }
        catch {
            Write-Log $_.Exception.Message -Level 'ERROR'
            Write-Log 'Failed to create JWT header and claimset' -Level 'ERROR'
            ScriptError 'Failed to create JWT header and claimset'
        }

        try {
            $signatureBytes = $certificate.PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($inputToken), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $signatureEncoded = [System.Convert]::ToBase64String($signatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $jwt = "$headerEncoded.$claimsetEncoded.$signatureEncoded"
        }
        catch {
            Write-Log $_.Exception.Message -Level 'ERROR'
            Write-Log 'Failed to sign JWT' -Level 'ERROR'
            ScriptError 'Failed to sign JWT'
        }

        $uri = $tokenUrl

        $body = @{
            'assertion'  = $jwt
            'grant_type' = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        }

        $nameValueCollection = New-Object System.Collections.Specialized.NameValueCollection
        foreach ($key in $body.Keys) {
            $nameValueCollection.Add($key, $body[$key])
        }

        try {
            $client = New-Object System.Net.WebClient
            $client.Encoding = [System.Text.Encoding]::UTF8
            $uri = $tokenUrl
            $response = $client.UploadValues($uri, 'POST', $nameValueCollection)
            $responseString = [System.Text.Encoding]::UTF8.GetString($response)
        }
        catch {
            Write-Log $_.Exception.Message -Level 'ERROR'
            Write-Log 'Failed to send request to Salesforce' -Level 'ERROR'
            ScriptError 'Failed to send request to Salesforce'
        }
        finally {
            $client.Dispose()
        }

        try {
            $result = $responseString | ConvertFrom-Json
            $token = $result.access_token
        }
        catch {
            Write-Log $_.Exception.Message -Level 'ERROR'
            Write-Log 'Failed to parse response or extract token' -Level 'ERROR'
            ScriptError 'Failed to parse response or extract token'
        }
        return $token
    }
    catch {
        Write-Log $_.Exception.Message -Level 'ERROR'
        Write-Log 'An unexpected error occurred' -Level 'ERROR'
    }
}

function Invoke-SalesforceCase {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserName,

        [Parameter(Mandatory = $false)]
        [string]$UserNTID
    )

    try {
        $token = Get-SalesforceJWTToken
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
    }

    #Dev API URL
    #$apiurl = 'https://bpcolleagues--hrmdev.sandbox.my.salesforce.com/services/apexrest/createCaseRMS/'

    $headers = @{
        'Sforce-Auto-Assign' = 'false'
        'Content-Type'       = 'application/json'
        'Authorization'      = "Bearer $token"
    }

    # Then remove any character that belongs to the "Mark" category, which includes accents
    $sanitizedName = $UserName.Normalize([Text.NormalizationForm]::FormD) -replace '\p{Mn}', ''

    # Optionally, remove commas and trim extra spaces
    $sanitizedName = $sanitizedName -replace ',', '' -replace '\s{2,}', ' ' # Replaces multiple spaces with a single space

    Write-Host "Sanitized Name: '$sanitizedName'"

    $body = @{
        WheredoyousitinBP = '1'
        ActionRequired    = 'Add Learners'
        MTLID             = $MTLID
        User1             = $sanitizedName
        NTIDUser1         = $UserNTID
    } | ConvertTo-Json

    try {
        $LappTicketNumber = Invoke-RestMethod -Uri $SFapiurl -Headers $headers -Method Post -Body $body -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        Write-Log $body -Level 'ERROR'
        ScriptError 'Error while raising LApp case'
    }


    return $LappTicketNumber
}

Function Invoke-sqlquery {
    param(
        $qry
    )

    try{
        # Run query
        Invoke-Sqlcmd `
            -ServerInstance "$sqlsvr" `
            -Database "$sqldb" `
            -Username "$sqluser" `
            -Password "$sqlpass" `
            -Query "$qry" -ErrorAction stop
    }catch{
        $ErrorMessage = $_.Exception.Message
        Write-Log $ErrorMessage -Level 'ERROR'
        Write-Log 'Error while running SQL query' -Level 'ERROR'
    }
}
##############################################
Write-Log 'SCRIPT STARTED' -Level 'INFO'
##############################################

# Connect to Azure
Disable-AzContextAutosave -Scope Process | Out-Null

try {
    # Logging in to Azure...
    #Connect-AzAccount
    Connect-AzAccount -Identity -WarningAction Ignore | Out-Null
}
catch {
    $ex = $_.Exception.Message
    $ErrorMsg = 'Azure Authentication failed'
    Write-Log $ex.message -Level 'ERROR'
    exit
}
Write-Log 'Azure Authentication Successful' -Level 'INFO'

# Logging in to MS Graph with identity
try {
    #Connect-MgGraph
    Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
}
catch {
    $ex = $_.Exception.Message
    $ErrorMsg = 'MS Graph Authentication Failed'
    Write-Log $ex.message -Level 'ERROR'
    exit
}
Write-Log 'MS Graph Authentication Successful' -Level 'INFO'

$sqlsvr = "ze1e2p3d301-dbserver-gu4ne.database.windows.net"
$sqldb = "ZE1E2P3D301-DB-7VI9S"

# Define details needed to use further in script
$AutomationAccountName = Get-AutomationVariable -Name 'AutomationAccountName'
#$AutomationAccountName = 'AA-DWP-NonProd'

switch ($AutomationAccountName) {
    'AA-DWP-NonProd' {
        $StorageAccountSubscription = 'zne-evcs-n-dwp-sbc'
        $StorageAccountNameRSG = 'ZNE-EVCS-N-17-DWP-RSG'
        $StorageAccountName = 'zneevcsn17dwpappstg'
        $ContainerName = 'copilot-license-allocation-email-templates'
        $DataverseEnvironmentURL = 'https://orga8dae9a2.crm4.dynamics.com'
        $KeyvaultName = 'zne-dwp-n-kvl'
        $Copilot_GUID = '58586b15-2e27-ef11-840a-000d3ab44827'
        $TestMode = $true
    }
    'AA-DWP-Prod' {
        $StorageAccountSubscription = 'zne-evcs-p-dwp-sbc'
        $StorageAccountNameRSG = 'ZNE-EVCS-P-27-DWP-RSG'
        $StorageAccountName = 'zneevcspdwpstg'
        $ContainerName = 'copilot-license-allocation-email-templates'
        $DataverseEnvironmentURL = 'https://orgee396095.crm4.dynamics.com'
        $KeyvaultName = 'zne-dwp-p-kvl'
        $Copilot_GUID = '58586b15-2e27-ef11-840a-000d3ab44827'
    }
}

try {
    Set-AzContext -Subscription $StorageAccountSubscription
}
catch {
    $ex = $_.Exception.Message
    Write-Log $ex -Level 'ERROR'
    Write-Log 'Failed to set azcontext to get Dataverse app ID and Secret.' -Level 'ERROR'
}

try {
    $Dataverse_AppID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Dataverse-AppID' -AsPlainText
    $Dataverse_ClientSecret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Dataverse-ClientSecret' -AsPlainText
}
catch {
    $ex = $_.Exception.Message
    Write-Log $ex -Level 'ERROR'
    ScriptError -msg "Failed to get Dataverse client ID and Secret`n$($ex.message)"
}

# Authentication with Azure AD to get the access token
$tenantId = 'ea80952e-a476-42d4-aaf4-5457852b0f7e'
$authority = "https://login.microsoftonline.com/$tenantId"
$tokenEndpoint = "$authority/oauth2/token"

$body = @{
    grant_type    = 'client_credentials'
    client_id     = $Dataverse_AppID
    client_secret = $Dataverse_ClientSecret
    resource      = $DataverseEnvironmentURL
}

try {
    # Obtain the access token
    $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $tokenResponse.access_token
}
catch {
    $ex = $_.Exception.Message
    Write-Log $ex -Level 'ERROR'
    $body
    ScriptError -msg "Failed to get access token from Dataverse`n$($ex.message)"
}
# Construct the API request headers with the access token
$Dataverseheaders = @{
    Authorization      = "Bearer $accessToken"
    'Content-Type'     = 'application/json'
    'OData-MaxVersion' = '4.0'
    'OData-Version'    = '4.0'
    Accept             = 'application/json'
}

try {
    # Define the API endpoint for the operation you want to perform
    $lic_category_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/crd15_license_categories"
    $lic_attr_map_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/new_license_attribute_mappings"
    $lic_queue_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/new_license_queue_requests"

    $lic_category_response = Invoke-RestMethod -Uri $lic_category_apiUrl -Headers $Dataverseheaders -Method Get
    $lic_category_response_details = $lic_category_response.value
}
catch {
    $ex = $_.Exception.Message
    Write-Log $ex -Level 'ERROR'
    ScriptError -msg "Failed to get get attribute mapping details from Dataverse`n$($ex.message)"
}

# Set azure context to subscription of storage account
try {
    $azcontext = Set-AzContext -Subscription $StorageAccountSubscription
}
catch {
    ScriptError('Failed to set context.')
}

if ($TestMode) {
    # If TestMode is set, use SNOW and Saviynt test environments
    $SnowURL = 'https://bpdev.service-now.com'
    $Email_AppID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Email-AppID' -AsPlainText
    $Email_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Email-Secret' -AsPlainText
    $scope = 'c390e4a4-f797-4ef8-8d82-8ad8c5438743'
    $Email_URI = 'https://dwp-functions-dev.bpglobal.com/api/Email-Common-Utility'
    $SNOW_Oauth_Token = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Oauth-Token-Test' -AsPlainText
    $CopilotCompletedGroupID = '2dcedb7c-77ad-452b-9c64-6724aea37c76'    # G O365 Copilot PoC users
    $sqluser   = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SQL-UserName-Licensingwrite' -asPlainText
    $sqlpass   = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SQL-Password-Licensingwrite' -asPlainText

    #Salesforce TEST variables
    $clientId = '3MVG91LYYD8O4krRFZk502yUZjm5Gonr_Z_Mj8pL0DuEtyWnZSw_O_Ob2PxDzxiCH9tKQ1AFX6FiBoK3Cw5co'
    $usernameSF = 'pcsalesforce1@bp.com.colleagues.hrmtest'
    $audienceUrl = 'test.salesforce.com'
    $tokenUrl = 'https://test.salesforce.com/services/oauth2/token'
    $SFapiurl = 'https://bpcolleagues--hrmtest.sandbox.my.salesforce.com/services/apexrest/createCaseRMS/'
    $MTLID = '1000198'
}
else {
    $SnowURL = 'https://bp.service-now.com'
    $Email_AppID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Email-AppID' -AsPlainText
    $Email_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'DWP-DevHub-Email-Secret' -AsPlainText
    $scope = '00c59037-c0c7-4637-9ba7-2b6b98cff3b5'
    $Email_URI = 'https://dwp-functions.bpglobal.com/api/Send-GraphEmailApi'
    $SNOW_Oauth_Token = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Oauth-Token' -AsPlainText
    $CopilotCompletedGroupID = 'ffe25b27-0c4a-418e-b2f4-52562b038b89'   # G O365 Copilot EAP Pilot users
    $sqluser   = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SQL-LicensingWrite-UserName' -asPlainText
    $sqlpass   = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SQL-LicensingWrite-Password' -asPlainText

    #Salesforce PROD variables
    $clientId = '3MVG95NPsF2gwOiMXVE8sXplWeRSDv9Y5kUjPN13fh69vyD2H__M0uLCe1s4J.KVNUVC3wapNcAOcC1BPO009'
    $usernameSF = 'pcsalesforcecopilot1@bp.com.colleagues'
    $audienceUrl = 'login.salesforce.com'
    $tokenUrl = 'https://login.salesforce.com/services/oauth2/token'
    $SFapiurl = 'https://bpcolleagues.my.salesforce.com/services/apexrest/createCaseRMS/'
    $MTLID = '908547'
}

try{
    $dbmessages = Invoke-Sqlquery -qry "Select * from Licensing_Dev.LicenseRequestView where status in ('New', 'In-Progress','Pending Training','On-Hold')"
}
catch {
    $ex = $_.Exception.Message
    Write-Log $ex -Level 'ERROR'
    ScriptError('Failed to fetch messages from DB.')
}

$numberOfMessages = $dbmessages.count

Write-Log "Number of messages to be processed : $numberOfMessages" -Level 'INFO'
#$visibilityTime = $numberOfMessages * 20

# TO BE REMOVED
#$visibilityTime = 60

# Main loop
$ThisRunProcessed = 0
$i = 0

$CSODReportPath = Get-SOUCornerstoneReport

foreach ($messageString in $dbmessages) {
    Write-Log '#####################################################################' -Level 'INFO'

    Write-Log "Processing message : $i" -Level 'INFO'

    $EmailSentCount = 0

    Start-Sleep 2
    
    $i = $i + 1

    $ID = $messageString.ID
    $Status = $messageString.Status
    $userUPN = $messageString.UserUPN
    $RequestedBy = $messageString.RequestedBy
    $LicenseType = $messageString.LicenseType
    $action = $messageString.Action
    $RequestedSource = $messageString.RequestSource
    $RITMNumber = $messageString.RITMNumber
    $TaskNumber = $messageString.TaskNumber
    $RequestedDate = $messageString.RequestedDate
    $ProcessedDate = $messageString.ProcessedDate
    $EmailSentCount = $messageString.EmailSentCount
    $EmailSentDate = $messageString.EmailSentDate
    $LAppCase = $messageString.LAppCase
    $LAppCaseCreatedDate = $messageString.LAppCaseCreatedDate
    $CompletionDate = $messageString.CompletionDate
    $SOUAgreedDate = $messageString.SOUAgreedDate
    $LastUpdatedDate = $messageString.LastUpdatedDate
    $UpdatedBy = $messageString.UpdatedBy
    $Comments = $messageString.Comments

    Write-Log "User UPN : $userUPN" -Level 'INFO'

    if($LicenseType -eq 'Microsoft365'){
        Write-Log "Mircosoft 365 license assignment is handled by a separate automation runbook 'E1-E5-Upgrade-Downgrade'. This request will be processed accordingly." -Level 'INFO'
        Write-Log '#####################################################################' -Level 'INFO'
        Continue
    }

    #Capture licenseCategorizationID based on category
    if ($action -eq 'downgrade') {
        $licenseCategory = $lic_category_response_details | Where-Object { $_.new_sub_category -eq 'E1' }
        $licenseCategorizationID = $licenseCategory.crd15_License_CategoryId
    }

    if ($action -eq 'upgrade') {
        switch ($LicenseType) {
            'Microsoft365' {
                $licenseCategory = $lic_category_response_details | Where-Object { $_.new_sub_category -eq 'E5' }
                $licenseCategorizationID = $licenseCategory.crd15_License_CategoryId
            }
            'MicrosoftCopilot' {
                $licenseCategory = $lic_category_response_details | Where-Object { $_.new_sub_category -eq 'Copilot' }
                $licenseCategorizationID = $licenseCategory.crd15_License_CategoryId
            }
            Default {
                ScriptError('No valid license type found in the request message.')
            }
        }
    }

    try{
        $SNOW_Oauth_Token = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Oauth-Token' -AsPlainText
    }
    catch{
        Write-Log "Unable to get SNOW token from keyvault." -Level 'ERROR'
        Write-Log $_.Exception.message -Level 'ERROR'
    }

    #Generating Dataverse token
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $Dataverse_AppID
        client_secret = $Dataverse_ClientSecret
        resource      = $DataverseEnvironmentURL
    }

    try {
        # Obtain the access token
        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $tokenResponse.access_token
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        $body
        ScriptError -msg "Failed to get access token from Dataverse`n$($ex.message)"
    }
    # Construct the API request headers with the access token
    $Dataverseheaders = @{
        Authorization      = "Bearer $accessToken"
        'Content-Type'     = 'application/json'
        'OData-MaxVersion' = '4.0'
        'OData-Version'    = '4.0'
        Accept             = 'application/json'
    }

    if($action -ne "upgrade" -and $LicenseType -ne "MicrosoftCopilot") {
        Write-Log "Skipping Non-Copilot request. Proceeding to next message ..." -Level 'INFO'
        continue
    }

    try{
        $UserExists = $null
        $UserExists = Get-MgUser -UserId $userUPN
        if($UserExists){
            Write-Log "User $UserUPN is a valid user in Entra." -Level 'INFO'
        }
    }
    catch{
        $msg = $_.Exception.Message
        if($msg -like '*does not exist*'){
            Write-Log "User $UserUPN is not a valid user in Entra." -Level 'ERROR'



            Write-Output 'Deleting message from DB and adding to Dataverse...'
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 5, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Invalid user in Entra' WHERE ID = $id;"
            
            # Add Final message to Dataverse
            $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')

            try {
                $bodyContent = @{
                    new_requestedby                          = $RequestedBy
                    new_requestedfor                         = $userUPN
                    'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
                    new_action                               = $action
                    new_requestsource                        = $RequestedSource
                    new_requesttime                          = $RequestedTime
                    new_processedtime                        = $ProcessedTime
                    new_completiontime                       = $completionTime
                    new_saviynttrackingid                    = $saviyntRequestReferenceIDs.trackingID
                    new_status                               = "Completed"
                    new_saviynttransactionid                 = $saviyntRequestReferenceIDs.APITransactionID
                    new_errorcode                            = $saviyntRequestReferenceIDs.ExitCode
                } | ConvertTo-Json

                $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

                Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
                Write-Log '#####################################################################' -Level 'INFO'
                continue
            }
            catch {
                Write-Log $bodyContent -Level 'ERROR'
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                Write-Log 'Failed to POST record in the dataverse table License_Category.' -Level 'ERROR'
                Write-Log '#####################################################################' -Level 'INFO'
                continue
            }
        }else{
            ScriptError "Error while getting user details from Entra for validating the user."
        }
    }

    Write-Log "Checking if the user $userUPN already has requested license ..." -Level 'INFO'
    try {
        #Check license replication status in Entra ID
        $ReplicationStatus = Get-SaviyntLicenseReplicationStatus -emailID $userUPN -action $action -LicenseType $LicenseType
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        Write-Log 'Failed to get license replication status.' -Level 'ERROR'
    }
    $RequestCompletionStatus = $ReplicationStatus

    Write-Log "User license allocation status is : $ReplicationStatus" -Level 'INFO'

    if($LicenseType -eq "MicrosoftCopilot") {
        if (($ReplicationStatus -eq $false)) {

            #Write-Log "Checking copilot license replication status for $userUPN"
            try {
                #Check license replication status in Entra ID
                $ReplicationStatus = Get-SaviyntLicenseReplicationStatus -emailID $userUPN -action $action -LicenseType $LicenseType
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                ScriptError('Failed to get license replication status.')
            }
            $RequestCompletionStatus = $ReplicationStatus

        }
        else {
            Write-Log "User's license replication is not completed yet."
            continue
        }
    }


    #Update Dataverse if request is completed
    if ($RequestCompletionStatus -eq $true) {
        Write-Log "Closing the RITM as license replication completed for the user $UserUPN" -Level 'INFO'
        try {
            Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes 'Copilot license assigned and replicated for the user. This request is marked as completed.'
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            Write-Log 'Failed to update ticket status at replication check.'
        }

        write-log 'Deleting message from DB and adding to Dataverse...'
        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'License replicated' WHERE ID = $id;"

        # Add Final message to Dataverse
        $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')

        try {
            $bodyContent = @{
                new_requestedby                          = $RequestedBy
                new_requestedfor                         = $userUPN
                'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
                new_action                               = $action
                new_requestsource                        = $RequestedSource
                new_requesttime                          = $RequestedTime
                new_processedtime                        = $ProcessedTime
                new_completiontime                       = $completionTime
                new_saviynttrackingid                    = $saviyntRequestReferenceIDs.trackingID
                new_status                               = if ($SaviyntStatus -eq 'Success') { 'Success' } else { 'Failed' }
                new_saviynttransactionid                 = $saviyntRequestReferenceIDs.APITransactionID
                new_errorcode                            = $saviyntRequestReferenceIDs.ExitCode
            } | ConvertTo-Json

            $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

            Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
            continue
        }
        catch {
            Write-Log $bodyContent -Level 'ERROR'
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            Write-Log 'Failed to POST record in the dataverse table License_queue_request after checking replication.' -Level 'ERROR'
            continue
        }
    }

    Write-Log "Processing $action for $userUPN" -Level 'INFO'

    try {
        $skus = Get-MgSubscribedSku | Select-Object SkuPartNumber, @{Name = 'AvailableUnits'; Expression = { $_.PrepaidUnits.Enabled - $_.ConsumedUnits } }
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
        ScriptError('Failed to get all sku details.')
    }

    if ($action -eq 'upgrade') {
        if ($LicenseType -eq "MicrosoftCopilot") {
            $CopilotPendingGroupID = '735c9f9c-b778-4020-94c8-e6a07d73bed7'    # G AAD CoPilot M365 Pending License Users

            # Get ticket status
            try {
                $RITMStatus = Get-TicketStatus -TicketNumber $RITMNumber

                if ($RITMStatus) {
                    $CurrentState = $RITMStatus.state
                    $CurrentStage = $RITMStatus.stage

                    Write-Log "Current State of the ticket is : $CurrentState"
                    Write-Log "Current Stage of the ticket is : $CurrentStage"

                    $statecode = @(3, 4, 7, 9)
                    if (($statecode -contains $CurrentState)) {
                        Write-Log "RITM $RITMNumber is not in open state. Skipping the request." -Level 'INFO'

                        write-log 'Deleting message from queue and adding to Dataverse...'
                        try {
                            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'RITM not in open state' WHERE ID = $id;"
                            Write-Log "Request closed due to RITM not in open state." -Level 'INFO'
                        }
                        catch {
                            $ex = $_.Exception.Message
                            Write-Log $ex -Level 'ERROR'
                            Write-Log 'Failed to update record in DB.'
                        }

                        $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')

                        try {
                            $bodyContent = @{
                                new_requestedby                          = $RequestedBy
                                new_requestedfor                         = $userUPN
                                'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
                                new_action                               = $action
                                new_requestsource                        = 'DWP-Automation'
                                new_requesttime                          = $RequestedTime
                                new_processedtime                        = $ProcessedTime
                                new_completiontime                       = $completionTime
                                new_saviynttrackingid                    = $null
                                new_lappcasenumber                       = $LAppCase
                                new_status                               = 'Aborted'
                                new_saviynttransactionid                 = $null
                                new_errorcode                            = 'RITM already closed'
                            } | ConvertTo-Json

                            $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

                            Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
                            Write-Log "#####################################################################"
                            continue
                        }
                        catch {
                            Write-Log $bodyContent -Level 'ERROR'
                            $ex = $_.Exception.Message
                            Write-Log $ex -Level 'ERROR'
                            Write-Log 'Failed to POST record in the dataverse table License_queue_request after skipping the request.' -Level 'ERROR'
                            continue
                        }
                    }
                }
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                Write-Log 'Failed to retrieve ticket status.'
            }

            try {
                $copilot_skus = $skus | Where-Object { $_.SkuPartNumber -like '*365_Copilot*' }
                $availableCopilotLicenses = $copilot_skus.AvailableUnits
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                ScriptError 'Error retrieving copilot license available units.'
            }

            Write-Log "Available overall Copilot Licenses : $availableCopilotLicenses" -Level 'INFO'

            try {
                $Userid = (Get-MgUser -UserId $userUPN).Id
                $User = Get-MgUser -UserId $Userid -Property OnPremisesExtensionAttributes
                $UserExtensionAttribute1 = $User.onPremisesExtensionAttributes.extensionAttribute1
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                ScriptError 'Error retrieving user entity details.'
            }

            try {
                $EntityQuotaAvailable = Get-EntityQuota -UserEntity $UserExtensionAttribute1
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                ScriptError 'Error retrieving user entity available quota details.'
            }

            try {
                $TnSEntityQuotaAvailable = Get-EntityQuota -UserEntity 'Supply, Trading & Shipping'
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex -Level 'ERROR'
                ScriptError 'Error retrieving user entity available quota details.'
            }

            #Write-Log "Available $UserExtensionAttribute1 entity Copilot Licenses : $EntityQuotaAvailable"

            Write-Log "Available licenses for T & S are : $TnSEntityQuotaAvailable" -Level 'INFO'

            $AvailableEntityLicenses = $EntityQuotaAvailable
            Write-Log "ThisRunProcessed : $ThisRunProcessed" -Level 'DEBUG'
            Write-Log "ProcessCutoff : $ProcessCutoff" -Level 'DEBUG'

            $LappCaseNumber = $null

            if (((($availableCopilotLicenses - $TnSEntityQuotaAvailable) -gt 0) -or (($UserExtensionAttribute1 -eq 'Supply, Trading & Shipping') -and ($TnSEntityQuotaAvailable -gt 0))) `
                -and ($ThisRunProcessed -lt $ProcessCutoff) `
                -and (($AvailableEntityLicenses -gt 0) -or ($UserExtensionAttribute1 -ne 'Supply, Trading & Shipping'))) {
                Write-Log "Processing $LicenseType $action for $userUPN" -Level 'INFO'

                $ThisRunProcessed++

                try {
                    $UserEntraID = Get-MgUser -UserId $userUPN -ErrorAction Stop
                    $UserEntraDetails = Get-MgUser -UserId $($UserEntraID.ID) -Property 'onPremisesSamAccountName' -ErrorAction Stop
                    Write-Log "User NTID : $($UserEntraDetails.onPremisesSamAccountName)"
                }
                catch {
                    $ex = $_.Exception.Message
                    write-log $ex
                    ScriptError('Failed to get UserDetails.')
                }

                if (([string]::IsNullOrWhiteSpace($LAppCase)) -or ($LAppCase -like '*Invalid NTIDUser1*')) {
                    #Send email for license approval
                    try {
                        $EmailSubject = 'Copilot license request approved'
                        $TemplateName = 'license_has_been_approved.html'
                        $Replacements = @{}
                        Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject $EmailSubject -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName $TemplateName -Replacements $Replacements
                        Write-Log 'Sent email to the user - Copilot license request approved' -Level 'INFO'
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex
                        Write-Log 'Failed to send approved email.'
                    }

                    #RAISE A CASE WITH L-APP
                    write-log 'Getting Lapp case number' -Level 'INFO'
                    try {
                        $LappCaseNumber = Invoke-SalesforceCase -UserName $UserEntraID.DisplayName -UserNTID $UserEntraDetails.onPremisesSamAccountName
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex
                        ScriptError('Failed to get Lapp case number.')
                    }

                    if ($LappCaseNumber -like "*Case Already exists for this combination*") {
                        # Define the regex pattern to extract the case number
                        $regexPattern = 'Case Number : (\d+)'
                        
                        # Perform the regex match to extract the case number
                        if ($LappCaseNumber -match $regexPattern) {
                            $ExtractedLappCaseNumber = $matches[1]  # The first captured group contains the case number
                            Write-Host "Extracted LApp Case Number: $ExtractedLappCaseNumber"

                            $LAppCaseNum = $ExtractedLappCaseNumber.ToString()
                        }else{
                            ScriptError "Unable to identify LApp Case number"
                        }
                    }else{
                        $LAppCaseNum = $LappCaseNumber.ToString()
                    }

                    Write-Log "Case $LappCaseNumber created in L-App." -Level 'INFO'

                    Write-Log 'Updating the queue message with Lapp case number ... ' -Level 'INFO'
                    
                    try {
                        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 3, LAppCase='$LAppCaseNum', LAppCaseCreatedDate = GETUTCDATE(), ProcessedDate = GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'SOU Training assigned' WHERE ID = $id;"
                        Write-Log "Message with UPN $userUPN - $LicenseType $Action updated with Lapp case number $LAppCaseNum" -Level 'INFO'                    
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex
                        ScriptError('Failed to update Lapp case to the DB.')
                    }

                    try {
                        $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '6' -WorkNotes "Copilot license approved for the user. Learning App case $LappCaseNumber raised. Awaiting training status check."
                        Write-Log "Task $TaskNumber updated with LAppCase $LappCaseNumber - Awaiting training status check."
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError 'Failed to update task in snow at Awaiting training status check..'
                    }

                    try {
                        $UpdateTicket = Update-TicketStatus -TicketNumber $RITMNumber -State '-5' -Stage 'Pending Training' -WorkNotes "Copilot license approved for the user. Learning App case $LappCaseNumber raised. Awaiting training status check."
                        Write-Log "Ticket $RITMNumber updated with LAppCase $LappCaseNumber - Awaiting training status check."
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to update ticket status at Awaiting training status check.' -Level 'ERROR'
                    }

                    Write-Log "Updating SNOW table with new available license count for entity $UserExtensionAttribute1 ."


                    try {
                        $SnowTableUpdateStatus = Update-EntityQuota -UserEntity $UserExtensionAttribute1 -TicketStage 'Pending Training'

                        if ($SnowTableUpdateStatus -eq 'Success') {
                            Write-Log 'SNOW Table updated successfully'
                        }
                        else {
                            Write-Log 'SNOW Table update failed'
                            ScriptError 'SNOW Table update failed'
                        }
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError 'Failed to update SNOW table with new available license count'
                    }
                    
                    Write-Log "#####################################################################"
                    continue
                }
                
                if($UserExtensionAttribute1 -eq 'Supply, Trading & Shipping'){
                    Write-Log "User $userUPN is part of T&S entity. Proceeding with SOU training status check." -Level 'INFO'
                    try {
                        $SOUTrainingStatus = Get-SOUStatus -userupn $UserEntraID.UserPrincipalName -UserEntity $UserExtensionAttribute1 -CornerstoneFilePath $CSODReportPath
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError('Failed to get SOU training status for the user.')
                    }
                }
                else {
                    Write-Log "User $userUPN is not part of T&S entity. Proceeding with SOU training status check." -Level 'INFO'
                    try {
                        $SOUTrainingStatus = Get-TOUStatus -userupn $UserEntraID.UserPrincipalName
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError('Failed to get SOU training status for the user.')
                    }
                }
                

                Write-log "SOU training status is : $SOUTrainingStatus" -Level 'DEBUG'

                try {
                    $InvokeUpgradeToCopilotParam = @{
                        UserUPN           = $UserEntraID.UserPrincipalName
                        TaskNumber        = $TaskNumber
                        UserEntraGUID     = $UserEntraID.ID
                        SOUTrainingStatus = $SOUTrainingStatus
                    }

                    $CopilotAssignmentStatus = Invoke-UpgradeToCopilot @InvokeUpgradeToCopilotParam
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex
                    ScriptError('Error during Invoke-UpgradeToCopilot function call.')
                }

                if ($CopilotAssignmentStatus -contains 'Assigned') {
                    write-log 'Copilot license assigned. Sending email to the user : Copilot license request completed.' -Level 'INFO'

                    try {
                        $EmailSubject = 'Getting started with Copilot for Microsoft 365'
                        $TemplateName = 'getting_started_with_copilot.html'
                        $Replacements = @{}
                        Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject $EmailSubject -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName $TemplateName -Replacements $Replacements
                        Write-Log 'Sent email to the user - Copilot license request completed' -Level 'INFO'
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to send license assigned email.' -Level 'ERROR'
                    }

                    if($UserEntity -eq 'Supply, Trading & Shipping'){
                        try {
                            $EmailSubject = 'Copilot for M365 – additional guidance for Trading & Shipping'
                            $TemplateName = 'getting_started_with_copilot_T&S.html'
                            $Replacements = @{}
                            Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject $EmailSubject -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName $TemplateName -Replacements $Replacements
                            Write-Log 'Sent email to the T&S user - Copilot license request approved' -Level 'INFO'
                        }
                        catch {
                            $ex = $_.Exception.Message
                            Write-Log $ex -Level 'ERROR'
                            Write-Log 'Failed to send license assigned email to T&S User.' -Level 'ERROR'
                        }
                    }

                    write-log 'Deleting message from queue and adding to Dataverse...'
                    try {
                        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'License assigned' WHERE ID = $id;"
                        Write-Log "Message with UPN $userUPN - $LicenseType $Action license assigned" -Level 'INFO'
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to delete message from queue.' -Level 'ERROR'
                    }

                    $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')
                                                        
                    try {
                        $bodyContent = @{
                            new_requestedby                          = $RequestedBy
                            new_requestedfor                         = $userUPN
                            'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
                            new_action                               = $action
                            new_requestsource                        = 'DWP-Automation'
                            new_requesttime                          = $RequestedTime
                            new_processedtime                        = $ProcessedTime
                            new_completiontime                       = $completionTime
                            new_saviynttrackingid                    = $null
                            new_lappcasenumber                       = $LAppCase
                            new_status                               = 'Completed'
                            new_saviynttransactionid                 = $null
                            new_errorcode                            = $null
                        } | ConvertTo-Json

                        $DataverseUpdate = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

                        Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
                    }
                    catch {
                        Write-Log $bodyContent -Level 'ERROR'
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to POST record in the dataverse table License_queue_request after assigning copilot license.' -Level 'ERROR'
                    }
                
                    try {
                        $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes 'Copilot license assigned to the user. Closing the task.'
                        Write-Log "Task $TaskNumber updated - Copilot license assigned." -Level 'INFO'
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError('Failed to update task in snow at Copilot license assigned..')
                    }

                    try {
                        $UpdateTicket = Update-TicketStatus -TicketNumber $RITMNumber -State '3' -Stage 'Completed' -WorkNotes 'Copilot license assigned to the user. Closing the ticket.'
                        Write-Log "RITM $RITMNumber updated - Copilot license assigned." -Level 'INFO'
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to update ticket status at Copilot license assigned..' -Level 'ERROR'
                    }
                    Write-Log "#####################################################################"
                    continue
                }
                elseif ($CopilotAssignmentStatus -contains 'Failed') {
                    write-log 'Copilot license declined. Deleting message from queue and adding to Dataverse...' -Level 'INFO'
                    try {
                        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'License declined' WHERE ID = $id;"
                        Write-Log "Message with UPN $userUPN - $LicenseType $Action license declined" -Level 'INFO'
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to delete message from queue.' -Level 'ERROR'
                    }

                    $completionTime = (Get-Date).ToString('MM/dd/yyyy HH:mm:ss')

                    try {
                        $bodyContent = @{
                            new_requestedby                          = $RequestedBy
                            new_requestedfor                         = $userUPN
                            'new_LicenseCategorizationID@odata.bind' = "/crd15_license_categories($licenseCategorizationID)"
                            new_action                               = $action
                            new_requestsource                        = 'DWP-Automation'
                            new_requesttime                          = $RequestedTime
                            new_processedtime                        = $ProcessedTime
                            new_completiontime                       = $completionTime
                            new_saviynttrackingid                    = $null
                            new_lappcasenumber                       = $LAppCase
                            new_status                               = 'Declined'
                            new_saviynttransactionid                 = $null
                            new_errorcode                            = 'SOU Failed'
                        } | ConvertTo-Json

                        $DataverseInvoke = Invoke-RestMethod -Uri $lic_queue_apiUrl -Method Post -Headers $Dataverseheaders -Body $bodyContent

                        Write-Log 'Message added to Dataverse successfully' -Level 'INFO'
                    }
                    catch {
                        Write-Log $bodyContent -Level 'ERROR'
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to POST record in the dataverse table License_queue_request after declining copilot license request.' -Level 'ERROR'
                    }

                    Write-Log "Updating SNOW table with new available license count for entity $UserExtensionAttribute1 ." -Level 'INFO'

                    try {
                        $SnowTableUpdateStatus = Update-EntityQuota -UserEntity $UserExtensionAttribute1 -TicketStage 'Rejected'

                        if ($SnowTableUpdateStatus -eq 'Success') {
                            Write-Log 'SNOW Table updated successfully'
                        }
                        else {
                            Write-Log 'SNOW Table update failed'
                            ScriptError 'SNOW Table update failed'
                        }
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError 'Failed to update SNOW table with new available license count'
                    }

                    Write-Log "#####################################################################"
                    continue
                }
                else {
                    Write-Log 'Error while getting copilot license allocation function output' -Level 'ERROR'

                    try {
                        Update-TaskStatus -TicketNumber $TaskNumber -State '-19' -WorkNotes 'Copilot license allocation error.'
                        Write-Log "Task $TaskNumber updated - Copilot license allocation error."
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        ScriptError('Failed to update task in snow at Copilot license allocation error.')
                    }

                    try {
                        Update-TicketStatus -TicketNumber $RITMNumber -State '-19' -Stage 'Validation' -WorkNotes 'Copilot license allocation error.'
                        Write-Log "RITM $RITMNumber updated - Copilot license allocation error."
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex -Level 'ERROR'
                        Write-Log 'Failed to update ticket status at Copilot license allocation error.'
                    }
                    Write-Log "#####################################################################"
                    continue
                }
            }
            else {
                Write-Log "Not enough Copilot licenses available for entity $UserExtensionAttribute1. Processing is on-hold..." -Level 'WARN'

                try {
                    if ($EmailSentCount -lt 1) {
                        $EmailSubject = 'Copilot license processing on-hold'
                        $TemplateName = 'added_in_waitlist_communication.html'
                        $Replacements = @{}

                        Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject $EmailSubject -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName $TemplateName -Replacements $Replacements
                        Write-Log 'Sent email to the user - Copilot license processing on-hold' -Level 'INFO'
                    }
                    else {
                        $EmailSubject = 'Copilot license processing still on-hold'
                        $TemplateName = 'still_on_the_waitlist_communication.html'
                        $Replacements = @{}

                        Send-CopilotEmail -SendTo $userUPN -CC 'ITRequest@bp.com' -EmailSubject $EmailSubject -StorageAccountName $StorageAccountName -ContainerName $ContainerName -TemplateName $TemplateName -Replacements $Replacements
                        Write-Log 'Sent email to the user - Copilot license processing still on-hold' -Level 'INFO'
                    }
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex -Level 'ERROR'
                    Write-Log 'Failed to send on-hold email.' -Level 'ERROR'
                    ScriptError 'Failed to send on-hold email.'
                }

                $EmailSentCount++
                $EmailSentDate = Get-Date -Format 'MM-dd-yy HH:mm:ss'

                try {
                    Update-TicketStatus -TicketNumber $RITMNumber -Stage 'Waiting List' -State '5' -WorkNotes 'Copilot licenses for entity are at capacity. Request will be processed once there are enough available licenses.'
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex -Level 'ERROR'
                    Write-Log 'Failed to update ticket to Waiting List.'
                }

                Write-Log 'Deleting the existing message, Add EmailSentCount and Date, Adding it back to the queue' -Level 'INFO'

                try {
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 4, EmailSentCount=$EmailSentCount, EmailSentDate = GETUTCDATE(), ProcessedDate = GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Copilot license processing on-hold' WHERE ID = $id;"
                    Write-Log "Message with UPN $userUPN - $LicenseType $Action - Copilot license processing still on-hold" -Level 'INFO'
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex -Level 'ERROR'
                    ScriptError('Failed to update record at waiting list stage.')
                }

                try {
                    $Userid = (Get-MgUser -UserId $userUPN).Id
                    New-MgGroupMember -GroupId $CopilotPendingGroupID -DirectoryObjectId $Userid
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex -Level 'ERROR'
                    Write-Log 'Failed to add user to Copilot pending group.' -Level 'ERROR'
                }
            }
            Default {
                write-log "License Type -> $LicenseType is not valid." -Level 'ERROR'
                #Update SNOW ticket status
                try {
                    $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '4' -WorkNotes 'Invalid license type received. Please raise new request with correct details. Closing the ticket.'
                    Write-Log "Task $TaskNumber updated - Invalid license type received."
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex -Level 'ERROR'
                    ScriptError('Failed to update task in snow at Invalid license type received..')
                }

                try {
                    Update-TicketStatus -TicketNumber $RITMNumber -State '4' -Stage 'Cancelled' -WorkNotes 'Invalid license type received. Please raise new request with correct details. Closing the ticket.'
                    Write-Log "RITM $RITMNumber updated - Invalid license type received."
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex -Level 'ERROR'
                    Write-Log 'Failed to update ticket status at Invalid license type received..' -Level 'ERROR'
                }
            }
        }
        
    }
    else {
        write-log "Action -> $action is not valid." -Level 'ERROR'
        #Update SNOW ticket status
        try {
            $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '4' -WorkNotes 'Invalid action received. Acceptable values are Upgrade or Downgrade. Please raise new request with correct details. Closing the ticket.'
            Write-Log "Task $TaskNumber updated - Invalid action received."
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            ScriptError('Failed to update task in snow at Invalid action received.')
        }

        try {
            Update-TicketStatus -TicketNumber $RITMNumber -State '4' -Stage 'Cancelled' -WorkNotes 'Invalid action received. Acceptable values are Upgrade or Downgrade. Please raise new request with correct details. Closing the ticket.'
            Write-Log "RITM $RITMNumber updated - Invalid license type received."
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex -Level 'ERROR'
            Write-Log 'Failed to update ticket status at Invalid action received.' -Level 'ERROR'
        }
    }
}