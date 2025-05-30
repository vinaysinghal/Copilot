<# 
.SYNOPSIS 
    License-Queue-Process
.DESCRIPTION 
    Picks message from azure queue and process it.
    it can process upgrade/downgrde of E1 and E5.
.NOTES  
.COMPONENT 
    Requires Modules Az,Graph
.NOTES
    Name          : Vinay Gupta
    Email         : vinay.gupta1@bp.com
    CreatedDate   : 2024/05/03
    Version       : 1.1
.WEBHOOKS
    # Need to provide WEBHOOKS        
#>

$PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
Write-Output "Using Hybrid Worker: $($env:computername)"

# Define the license pool threshold limit
$threshold = 30
$ProcessCutoff = 100

$TestMode = $false
if ($TestMode) { Write-Output 'TESTMODE ENABLED' }

# Hardcoded Saviynt Attribute Mapping Variables
# IMPORTANT: Replace these placeholder values with the actual values from your environment.
$E1_customproperty53 = "PLACEHOLDER_E1_customproperty53" # Example: "false" or specific string
$E1_customproperty65 = "PLACEHOLDER_E1_customproperty65" # Example: "Exchange Online (Plan 1)"
$E1_customproperty63 = "PLACEHOLDER_E1_customproperty63" # Example: "STANDARDWOFFPACK_IW"
$E1_attributes65 = "PLACEHOLDER_E1_attributes65"         # Example: "Online"

$E5_customproperty63 = "PLACEHOLDER_E5_customproperty63" # Example: "ENTERPRISEPREMIUM_IW"
$E5_customproperty53_true = "PLACEHOLDER_E5_customproperty53_true"   # Example: "true"
$E5_customproperty53_false = "PLACEHOLDER_E5_customproperty53_false" # Example: "false"

Write-Log "Using hardcoded Saviynt attribute mapping variables. Ensure these are correctly set for your environment." -Level "WARN"

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
        UPN   = $UserUPN # Ensure $UserUPN is available in this scope
        Error = $msg
    }
    $response = $respObj | ConvertTo-Json

    Write-Log $msg -Level 'ERROR'
    Write-Log $response -Level 'ERROR'
    Write-Log 'One or more errors occurred, Refer the output screen for details' -Level 'ERROR' # Changed to ERROR

    $ShortDesc = 'Failure; Automatic Fulfilment Not Possible - M365 License'
    try{
       # $ticket = New-SnowTask -shortDescription $ShortDesc -Description $response -UserUPN $UserUPN # $ticket variable is not used in the new SQL update logic for comments.
       # Write-Log "SNOW ticket logged: $ticket" -Level 'INFO'
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log $ex -Level 'ERROR'
    }

    # Update DB entry with error status and message
    try {
        # Ensure $ID is available in this scope. It's typically the ID of the current item being processed in the loop that calls ScriptError.
        $updateQuery = "UPDATE Licensing_Dev.License_Requests SET StatusID = 5, Comments = ISNULL(Comments + ' | ', '') + 'Error: $msg', UpdatedBy = 'DW-Automation', CompletionDate = GETUTCDATE() WHERE ID = $ID;"
        Invoke-Sqlquery -qry $updateQuery
        Write-Log "DB entry for ID $ID updated with error status." -Level 'INFO'
        Write-Log "**********************************************************************"
        # This 'continue' is important if ScriptError is called within a loop processing multiple items.
        # It allows the script to move to the next item instead of halting.
        continue
    }
    catch {
        $ex = $_.Exception.Message
        Write-Log "Exception during DB update in ScriptError: $($ex)" -Level 'ERROR' # Changed level
        Write-Log "Failed to update DB entry for ID $ID during ScriptError." -Level 'ERROR'
        Write-Log "**********************************************************************"
        continue
    }
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
        [string]$TicketType
    )
	
    $header = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $SNOW_Oauth_Token"
    }

    $body = @{
        short_description = $shortDescription
        description       = $Description
        cmdb_ci           = 'Digital Collaboration Tools'
        assignment_group  = if ($TicketType -eq 'ReplicationTask') { '5373ac80db20a59017dbcf8315961995' } else { 'cf4ddcb5db8f1f00953fa103ca961925' }
        priority          = 3
        contact_type      = 'Via API'
        u_requested_for   = $UserUPN
        u_source          = 'Portal'
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
        $ex = $_.Exception.Message
        # Error logging SNOW ticket. Trying again with 'RequestedBy' value
        Write-Log $ex
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
            $ex = $_.Exception.Message
            Write-Log $ex
            Continue
        }
    }
}

# Function to process license upgrade to E5
function Invoke-UpgradeToE5 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN
    )

    $saviyntRequestReferenceIDs = $null

    $body = @{
        client_id     = $Saviynt_Oauth_ClientID
        client_secret = $Saviynt_Oauth_Secret
        grant_type    = 'client_credentials'
        scope         = "$SavScope/ieeo-grpitsidentity/proxy/v1//.default"
    }

    $uri = 'https://login.microsoftonline.com:443/ea80952e-a476-42d4-aaf4-5457852b0f7e/oauth2/v2.0/token'
    try{
        $bearer = Invoke-RestMethod -Method POST -Uri "$uri" -Body $body
    }
    catch {
        $ex = $_.Exception.Message
        write-log $ex
    }

    # Lookup user
    $body = @{
        customproperty16 = $UserUPN
        max              = 100
        offset           = 0
    }
    $header = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
        Authorization  = "Bearer $($bearer.access_token)"
    }
    $params = @{
        method  = 'GET'
        uri     = "$SavURL/iam-integration-services/identity-api/v1/users"
        headers = $header
        body    = $body
    }
    try {
        $result = Invoke-RestMethod @params -ErrorAction Stop
    }
    catch {
        $ex = $_.Exception.Message
        write-log $ex
    }
    Write-Log 'Results from user lookup'
    $result.attributes

    $BPIdentityAPITransactionID = (New-Guid).Guid -replace '-[a-f|0-9]{12}$'

    if (!([string]::IsnullOrEmpty($result.attributes))) {
        write-log 'Saviynt record found for user'

        if ((($result.attributes.customproperty65.value).ToLower() -eq $E1_attributes65.ToLower()) -or (($result.attributes.customproperty65.value).ToLower() -eq $E1_customproperty65.ToLower())) {
            if ((($result.attributes.customproperty53.value).ToLower() -eq $E5_customproperty53_false.ToLower()) -or (!$result.attributes.customproperty53.value) -or (($result.attributes.customproperty63.value).ToLower() -ne $E5_customproperty63.ToLower())) {
                write-log 'User does not have an E5 license allocated. Request an uplift'

                $header = @{
                    'Content-Type'                 = 'application/json'
                    Authorization                  = "Bearer $($bearer.access_token)"
                    client_id                      = $Saviynt_ClientID
					client_secret                  = $Saviynt_Secret
                    'BP-IdentityAPI-TransactionID' = "DWP-$BPIdentityAPITransactionID"
                }
                $body = @{
                    attributes = @{
                        customproperty53 = @{
                            value = $E5_customproperty53_true
                        }
                        customproperty63 = @{
                            value = $E5_customproperty63
                        }
                    }
                }
                $params = @{
                    method  = 'PUT'
                    uri     = "$SavURL/iam-integration-services/identity-api/v1/async/users/$($result.attributes.systemUserName.value)"
                    headers = $header
                    body    = $body | ConvertTo-Json
                }

                try{
                    $TransactionId = Invoke-RestMethod @params -ErrorAction Stop
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Host $ex
                }

                write-log "Saviynt request logged for user uplift. Tracking ID: $($TransactionID.TRACKING_ID)"
                $header = @{
                    'Content-Type' = 'application/x-www-form-urlencoded'
                    client_id      = $Saviynt_ClientID
					client_secret  = $Saviynt_Secret
                    Authorization  = "Bearer $($bearer.access_token)"
                }

                $params = @{
                    method  = 'GET'
                    uri     = "$SavURL/iam-integration-services/identity-api/v1/async/request/$($TransactionID.TRACKING_ID)"
                    headers = $header
                }

                try{
                    $status = Invoke-RestMethod @params -ErrorAction Stop
                }
                catch {
                    $ex = $_.Exception.Message
                    write-log $ex
                }

                if ($Status.response_status.status -ge 400) {
                    $Status.response_status.status
                    ScriptError -msg 'Error requesting Saviynt E5 uplift'
                }

                $ExceptionErrorCode = 'Success'
            }
            else {
                write-log 'Saviynt record shows user should have E5, but this is not reflected in M365'
                $ShortDesc = 'Failure; Automatic Fulfilment Not Possible - M365 E5 Downgrade'
                $Description = "The automatic fulfilment service is unable to fulfil the M365 E5 Downgrade for the below request. Saviynt record shows user should have E5, `
                                but this is not reflected in M365. Please investigate this ASAP and correct the data, provide the E5 license and then close this ticket once completed.`nRequested By: $RequestedBy`nRequest For: $userUPN`nTransaction ID: $BPIdentityAPITransactionID`nSource: 'M365 License Automation Process'"
                        
                try{
                    $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPN
                    write-log "SNOW ticket logged: $ticket"
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex
                    Write-Log 'Failed to create SNOW Ticket.'
                }  

                try {
                    $worknote = "The automatic fulfilment service is unable to fulfil the M365 E5 Upgrade for the below request. Saviynt record shows user should have E5, but this is not reflected in M365. The request is under investigation.`
                                    `nTask: $ticket`nRequested By: $RequestedBy`nRequest For: $userUPN`nTransaction ID: $BPIdentityAPITransactionID`nSource: 'M365 License Automation Process'"
                    $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes $worknote
                    Write-Log "Task $TaskNumber updated - Saviynt record shows user should have E5, but this is not reflected in M365."
                }
                catch {
                    $ex = $_.Exception.Message
                    write-log $ex
                    ScriptError('Failed to update task in snow at License assigned and replicated..')
                }

                $ExceptionErrorCode = "SaviyntE5True-$ticket"
            }
        }
        else {
            write-log 'customproperty65 not set correctly in Saviynt. Log SNOW ticket'
            $ShortDesc = 'Failure; Automatic Fulfilment Not Possible - M365 E5 Downgrade'
            $Description = "The automatic fulfilment service is unable to fulfil the M365 E5 Downgrade for the below request due to Saviynt not holding accurate mailbox information. `
                                Please investigate this ASAP and correct the data, provide the E5 license and then close this ticket once completed.`nRequested By: $RequestedBy`nRequest For: $userUPN`nTransaction ID: $BPIdentityAPITransactionID`nSource: 'M365 License Automation Process'"

            try{
                $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPN
                write-log "SNOW ticket logged: $ticket"
            }
            catch {
                $ex = $_.Exception.Message
                Write-Log $ex
                Write-Log 'Failed to create SNOW Ticket.'
            }  

            try {
                $worknote = "The automatic fulfilment service is unable to fulfil the M365 E5 Upgrade for the below request. Saviynt attribute customproperty65 is not set correctly. The request is under investigation.`
                                `nTask: $ticket`nRequested By: $RequestedBy`nRequest For: $userUPN`nTransaction ID: $BPIdentityAPITransactionID`nSource: 'M365 License Automation Process'"
                $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes $worknote
                Write-Log "Task $TaskNumber updated - customproperty65 not set correctly in Saviynt."
            }
            catch {
                $ex = $_.Exception.Message
                write-log $ex
                ScriptError('Failed to update task in snow at License assigned and replicated..')
            }

            $ExceptionErrorCode = "EmptyCustomproperty65-$ticket"
        }
    }
    else {
        write-log "Couldn't find user in Saviynt. Log a ticket." 
        $ShortDesc = 'Failure: Automatic Fulfilment Not Possible - M365 E5 Upgrade'
        $Description = "The automatic fulfilment service is unable to fulfil the M365 E5 Upgrade for the below request due to Saviynt not returning a profile for the identity.`n`n `
                            Error: Identity not found in Saviynt `n`nPlease provide the E5 license and then close this ticket once completed.`nRequested By: $RequestedBy`nRequest For: $userUPN`nSource: 'M365 License Automation Process'"
        
        try{
            $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPN
            write-log "SNOW ticket logged: $ticket"
        }
        catch {
            $ex = $_.Exception.Message
            Write-Log $ex
            Write-Log 'Failed to create SNOW Ticket.'
        }  

        try {
            $worknote = "The automatic fulfilment service is unable to fulfil the M365 E5 Upgrade for the below request. Couldn't find user in Saviynt. The request is under investigation.`
                            `nTask: $ticket`nRequested By: $RequestedBy`nRequest For: $userUPN`nTransaction ID: $BPIdentityAPITransactionID`nSource: 'M365 License Automation Process'"
            $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes $worknote
            Write-Log "Task $TaskNumber updated - Couldn't find user in Saviynt."
        }
        catch {
            $ex = $_.Exception.Message
            write-log $ex
            ScriptError('Failed to update task in snow at License assigned and replicated..')
        }

        $ExceptionErrorCode = "SaviyntNoUserRecord-$ticket"
    }

    $script:saviyntRequestReferenceIDs = [PSCustomObject]@{
        trackingID       = $TransactionID.TRACKING_ID
        APITransactionID = $BPIdentityAPITransactionID
        ExitCode         = $ExceptionErrorCode
    }
}

# Function to downgrade license to E1
function Invoke-DowngradeToE1 {

    param(
        [Parameter(Mandatory = $true)]
        [string]$UserUPN
    )

    $saviyntRequestReferenceIDs = $null

    $body = @{
        client_id     = $Saviynt_Oauth_ClientID
        client_secret = $Saviynt_Oauth_Secret
        grant_type    = 'client_credentials'
        scope         = "$SavScope/ieeo-grpitsidentity/proxy/v1//.default"
    }

    $uri = 'https://login.microsoftonline.com:443/ea80952e-a476-42d4-aaf4-5457852b0f7e/oauth2/v2.0/token'
    $bearer = Invoke-RestMethod -Method POST -Uri "$uri" -Body $body

    # Lookup user
    $body = @{
        customproperty16 = $UserUPN
        max              = 100
        offset           = 0
    }

    $header = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
        Authorization  = "Bearer $($bearer.access_token)"
    }

    $params = @{
        method      = 'GET'
        uri         = "$SavURL/iam-integration-services/identity-api/v1/users"
        headers     = $header
        body        = $body
        ErrorAction = 'Continue'
    }
    try {
        $result = Invoke-RestMethod @params 
    }
    catch {
        $ex = $_.Exception.Message
        write-log $ex
    }
    Write-Log 'Results from user lookup'
    $result.attributes

    $BPIdentityAPITransactionID = (New-Guid).Guid -replace '-[a-f|0-9]{12}$'

    if (!([string]::IsnullOrEmpty($result.attributes))) {
        write-log 'Saviynt record found for user'
        if ((($result.attributes.customproperty53.value).ToLower() -eq $E5_customproperty53_true.ToLower()) -or (($result.attributes.customproperty63.value).ToLower() -eq $E5_customproperty63.ToLower())) {
            write-log 'User has an E5 license allocated. Request a downgrade'

            $header = @{
                'Content-Type'                 = 'application/json'
                Authorization                  = "Bearer $($bearer.access_token)"
                client_id                      = $Saviynt_ClientID
				client_secret                  = $Saviynt_Secret
                'BP-IdentityAPI-TransactionID' = "DW-devhub-$BPIdentityAPITransactionID"
            }
            $body = @{
                attributes = @{
                    customproperty53 = @{
                        value = $E1_customproperty53
                    }
                    customproperty63 = @{
                        value = $E1_customproperty63
                    }
                }
            }
            $params = @{
                method  = 'PUT'
                uri     = "$SavURL/iam-integration-services/identity-api/v1/async/users/$($result.attributes.systemUserName.value)"
                headers = $header
                body    = $body | ConvertTo-Json
            }
            $TransactionId = Invoke-RestMethod @params

            write-log "Saviynt request logged for user license downgrade. Tracking ID: $($TransactionID.TRACKING_ID)"
            $header = @{
                'Content-Type' = 'application/x-www-form-urlencoded'
                client_id      = $Saviynt_ClientID
				client_secret  = $Saviynt_Secret
                Authorization  = "Bearer $($bearer.access_token)"
            }

            $params = @{
                method  = 'GET'
                uri     = "$SavURL/iam-integration-services/identity-api/v1/async/request/$($TransactionID.TRACKING_ID)"
                headers = $header
            }

            $status = Invoke-RestMethod @params

            if ($Status.response_status.status -ge 400) {
                $Status.response_status.status
                ScriptError -msg 'Error requesting Saviynt E1 downgrade'
            }

            $ExceptionErrorCode = 'Success'
        }
        else {
            write-log 'Saviynt record shows user should have E5, but this is not reflected in M365'
            $ShortDesc = 'Failure; Automatic Fulfilment Not Possible - M365 E5 Downgrade'
            $Description = "The automatic fulfilment service is unable to fulfil the M365 E5 Downgrade for the below request. Saviynt record shows user should have E5, `
                            but this is not reflected in M365. Please investigate this ASAP and correct the data, provide the E5 license and then close this ticket once completed.`nRequested By: $RequestedBy`nRequest For: $userUPN`nSaviynt Job ID: $($TransactionID.TRACKING_ID)`nGeneratedBy : 'License-Queuing-Runbook'"
                    
            $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $userUPN
            write-log "SNOW ticket logged: $ticket"
            $ExceptionErrorCode = "SaviyntE5True-$ticket"
        }
    }
    else {
        write-log "Couldn't find user in Saviynt. Log ticket to O365 team" 
        $ShortDesc = 'Failure: Automatic Fulfilment Not Possible - M365 E5 Downgrade'
        $Description = "The automatic fulfilment service is unable to fulfil the M365 E5 Downgrade for the below request due to Saviynt not returning a profile for the identity.`n`n `
                        Error: Identity not found in Saviynt `n`nPlease provide the E5 license and then close this ticket once completed.`nRequested By: $RequestedBy`nRequest For: $userUPN`nSource: 'M365 License Automation Process'"
        $ticket = New-SnowTask -shortDescription $ShortDesc -Description $Description -UserUPN $UserUPN
        write-log "SNOW ticket logged: $ticket"  
        $ExceptionErrorCode = "SaviyntNoUserRecord-$ticket"     
    }

    $script:saviyntRequestReferenceIDs = [PSCustomObject]@{
        trackingID       = $TransactionID.TRACKING_ID
        APITransactionID = $BPIdentityAPITransactionID
        ExitCode         = $ExceptionErrorCode
        SnowTaskNumber   = $ticket
    }
}

# Function to get license replication status
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
        write-log $ex
        ScriptError('Failed to get allocated license details for the user.')
    }

    if ($action -eq 'downgrade') {
        if (($licenses.skupartnumber -contains 'STANDARDPACK')) {
            write-log 'User has an E1 license.'
            $lic_allocation = $true
        }
        else {
            $lic_allocation = $false
        }
    }
    elseif ($action -eq 'upgrade') {
        if (($LicenseType -eq 'Microsoft365' -and $licenses.skupartnumber -contains 'SPE_E5')) {
            write-log 'User has an E5 license.'
            $lic_allocation = $true
        }
        elseif (($LicenseType -eq 'MicrosoftCopilot' -and $licenses.skupartnumber -like '*365_Copilot*')) {
            write-log 'User has a Copilot license.'
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
        Write-Log 'Failed to get RITM status from Service now. Error during Invoke.'
        $ex = $_.Exception.Message
        write-log $ex
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
        Write-Log 'Failed to update RITM status in Service now. Error during Invoke.'
        $ex = $_.Exception.Message
        write-log $ex
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
        Write-Log 'Failed to update Service Task status in Service now. Error during Invoke.'
        $ex = $_.Exception.Message
        write-log $ex
    }
}

#Function to check license allocation before processing
function Get-LicenseAllocationStatus {

    param(
        [Parameter(Mandatory = $true)]
        [string]$emailID,

        [Parameter(Mandatory = $true)]
        [string]$action,

        [Parameter(Mandatory = $true)]
        [string]$LicenseType
    )

    $licenses = Get-MgUserLicenseDetail -UserId $emailID
    
    if ($action -eq 'downgrade') {
        if ($licenses.skupartnumber -contains 'STANDARDPACK') {
            Write-Output 'User has an E1 license.'
            return $true
        }
    }elseif ($action -eq 'upgrade') {
        if ($licenses.skupartnumber -contains 'SPE_E5') {
            Write-Output 'User has an E5 license.'
            return $true
        }
    } else {
        Write-Output 'Invalid action specified.'
        return $false
    }
    
    return $false
}

function Get-SnowAcessToken() {    
    $tenantId = 'ea80952e-a476-42d4-aaf4-5457852b0f7e'
    $tokenBody = @{  
        Grant_Type    = "client_credentials"  
        Scope         = "$SnowURL/api/snc/bp_rest_api/.default"
        Client_Id     = $snowclient_id    
        Client_Secret = $snowclient_secret
    }  
    $SnowToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody #| Select-Object -ExpandProperty Access_Token
    return $SnowToken.access_token
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

Write-Log '##############################################'
Write-Log 'SCRIPT STARTED'
Write-Log '##############################################'

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
    Write-Output $ex.message
    scriptError($ErrorMsg)    
}
Write-Log 'Azure Authentication Successful'

# Logging in to MS Graph with identity
try {
    #Connect-MgGraph
    Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
}
catch {
    $ex = $_.Exception.Message
    $ErrorMsg = 'MS Graph Authentication Failed'
    Write-Output $ex.message
    scriptError($ErrorMsg)
}
Write-Log 'MS Graph Authentication Successful'

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
        # $DataverseEnvironmentURL = 'https://orga8dae9a2.crm4.dynamics.com' # Removed
        $KeyvaultName = 'zne-dwp-n-kvl'
        # $E1_GUID = '135f4d11-300d-ef11-9f8a-6045bd8865c3' # Removed
        # $E5_GUID = 'db56a5c3-250d-ef11-9f89-000d3a222c58' # Removed
        $TestMode = $true
    }
    'AA-DWP-Prod' { 
        $StorageAccountSubscription = 'zne-evcs-p-dwp-sbc'
        $StorageAccountNameRSG = 'ZNE-EVCS-P-27-DWP-RSG'
        $StorageAccountName = 'zneevcspdwpstg'
        # $DataverseEnvironmentURL = 'https://orgee396095.crm4.dynamics.com' # Removed
        $KeyvaultName = 'zne-dwp-p-kvl'
        # $E1_GUID = '52bf2013-2e27-ef11-840a-000d3a660d83' # Removed
        # $E5_GUID = '54586b15-2e27-ef11-840a-000d3ab44827' # Removed
    }
}

# The following Set-AzContext and Key Vault fetches for Dataverse AppID/Secret are no longer needed.
# try {
#     Set-AzContext -Subscription 'zne-evcs-p-dwp-sbc'
# }
# catch {
#     $ex = $_.Exception.Message
#     write-log $ex
#     Write-Log 'Failed to set azcontext to get Dataverse app ID and Secret.'
# }

# try {
#     $Dataverse_AppID = Get-AzKeyVaultSecret -VaultName 'zne-dwp-p-kvl' -Name 'DWP-DevHub-Dataverse-AppID' -AsPlainText
#     $Dataverse_ClientSecret = Get-AzKeyVaultSecret -VaultName 'zne-dwp-p-kvl' -Name 'DWP-DevHub-Dataverse-ClientSecret' -AsPlainText
# }
# catch {
#     $ex = $_.Exception.Message
#     write-log $ex
#     ScriptError -msg "Failed to get Dataverse client ID and Secret`n$($ex.message)"
# }

# Authentication with Azure AD to get the access token for Dataverse - REMOVED
# $tenantId = 'ea80952e-a476-42d4-aaf4-5457852b0f7e'
# $authority = "https://login.microsoftonline.com/$tenantId"
# $tokenEndpoint = "$authority/oauth2/token"

# $body = @{
#     grant_type    = 'client_credentials'
#     client_id     = $Dataverse_AppID
#     client_secret = $Dataverse_ClientSecret
#     resource      = $DataverseEnvironmentURL
# }

# try {
#     # Obtain the access token
#     $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
#     $accessToken = $tokenResponse.access_token
# }
# catch {
#     $ex = $_.Exception.Message
#     write-log $ex
#     $body
#     ScriptError -msg "Failed to get access token from Dataverse`n$($ex.message)"
# }

# Construct the API request headers with the access token - REMOVED
# $Dataverseheaders = @{
#     Authorization      = "Bearer $accessToken"
#     'Content-Type'     = 'application/json'
#     'OData-MaxVersion' = '4.0'
#     'OData-Version'    = '4.0'
#     Accept             = 'application/json'
# }

# Dataverse API calls and attribute mapping logic - REMOVED
# try {
    # Define the API endpoint for the operation you want to perform
    # $lic_category_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/crd15_license_categories"
    # $lic_attr_map_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/new_license_attribute_mappings"
    # $lic_queue_apiUrl = "$DataverseEnvironmentURL/api/data/v9.2/new_license_queue_requests"

    # $lic_category_response = Invoke-RestMethod -Uri $lic_category_apiUrl -Headers $Dataverseheaders -Method Get
    # $lic_category_response_details = $lic_category_response.value

    # $lic_attr_map_response = Invoke-RestMethod -Uri $lic_attr_map_apiUrl -Headers $Dataverseheaders -Method Get
    # $lic_attr_map_response_details = $lic_attr_map_response.value

    # $license_attr_mapping_record = @()
    # for ($i = 0; $i -lt $lic_attr_map_response_details.count; $i++) {
    #     $license_attr_mapping_record += $lic_attr_map_response_details.Item($i)
    # }

    # $E1_customproperty53_details = $license_attr_mapping_record | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E1_GUID) -and ('customproperty53' -eq $_.'new_name') }
    # $E1_customproperty53 = $E1_customproperty53_details.new_Value

    # $E1_customproperty65_details = $license_attr_mapping_record | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E1_GUID) -and ($_.new_name -eq 'customproperty65') }
    # $E1_customproperty65 = $E1_customproperty65_details.new_Value

    # $E1_customproperty63_details = $license_attr_mapping_record | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E1_GUID) -and ($_.new_name -eq 'customproperty63') }
    # $E1_customproperty63 = $E1_customproperty63_details.new_Value

    # $E1_attributes65_details = $license_attr_mapping_record | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E1_GUID) -and ($_.new_name -eq 'attributes65') }
    # $E1_attributes65 = $E1_attributes65_details.new_Value

    # $E5_customproperty63_details = $license_attr_mapping_record | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E5_GUID) -and ($_.new_name -eq 'customproperty63') }
    # $E5_customproperty63 = $E5_customproperty63_details.new_Value

    # $E5_customproperty53_true_details = $license_attr_mapping_record | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E5_GUID) -and ($_.new_name -eq 'customproperty53_true') }
    # $E5_customproperty53_true = $E5_customproperty53_true_details.new_Value

    # $E5_customproperty53_false_details = $license_attr_mapping_record | Where-Object { ($_.'_new_licensecategorizationid_value' -eq $E5_GUID) -and ($_.new_name -eq 'customproperty53_false') }
    # $E5_customproperty53_false = $E5_customproperty53_false_details.new_Value
# }
# catch {
    # $ex = $_.Exception.Message
    # write-log $ex
    # ScriptError -msg "Failed to get get attribute mapping details from Dataverse`n$($ex.message)" # This would fail anyway as $DataverseEnvironmentURL is gone.
# }

# Set azure context to subscription of storage account
try {
    $azcontext = Set-AzContext -Subscription $StorageAccountSubscription
}
catch {
    ScriptError('Failed to set context.')
}

if ($TestMode) {
    # If TestMode is set, use SNOW and Saviynt test environments
    $SavURL = 'https://apis-001-nonprod.bpweb.bp.com/test'
    $SavScope = 'https://api-001-nonprod.bpglobal.com/tst'
    $SnowURL = 'https://bptest.service-now.com'
    $Saviynt_Oauth_ClientID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SaviyntApi-TEST-Oauth-ClientID' -AsPlainText
    $Saviynt_Oauth_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SaviyntApi-TEST-Oauth-Secret' -AsPlainText
    $Saviynt_ClientID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SaviyntApi-TEST-ClientID' -AsPlainText
    $Saviynt_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SaviyntApi-TEST-Secret' -AsPlainText
    #$SNOW_Oauth_Token = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Oauth-Token-Test' -AsPlainText
    $sqluser   = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SQL-UserName-Licensingwrite' -asPlainText
    $sqlpass   = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SQL-Password-Licensingwrite' -asPlainText

    if($SnowURL -eq "https://bptest.service-now.com"){
        $snowclient_id = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Test-AppID' -AsPlainText
        $snowclient_secret = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Test-Secret' -AsPlainText
    }
    else {
        $snowclient_id = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Dev-AppID' -AsPlainText
        $snowclient_secret = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Dev-Secret' -AsPlainText
    }
    $SNOW_Oauth_Token = Get-SnowAcessToken
}else {
    $SavURL = 'https://apis.bpglobal.com'
    $SavScope = 'https://api-001.bpglobal.com'
    $SnowURL = 'https://bp.service-now.com'
    $Saviynt_Oauth_ClientID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SaviyntApi-Oauth-ClientID' -AsPlainText
    $Saviynt_Oauth_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SaviyntApi-Oauth-Secret' -AsPlainText
    $Saviynt_ClientID = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SaviyntApi-ClientID' -AsPlainText
    $Saviynt_Secret = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SaviyntApi-Secret' -AsPlainText
    $SNOW_Oauth_Token = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Oauth-Token' -AsPlainText
    $sqluser   = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SQL-LicensingWrite-UserName' -asPlainText
    $sqlpass   = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name 'SQL-LicensingWrite-Password' -asPlainText
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

$ms365Messages = $dbmessages | Where-Object { $_.LicenseType -eq "Microsoft365" }
Write-Log "Number of messages with LicenseType = 'Microsoft365': $($ms365Messages.count)" -Level 'INFO'

# Main loop
$ThisRunProcessed = 0

foreach ($messageString in $ms365Messages) {

    if($TestMode){
        if($SnowURL -eq "https://bptest.service-now.com"){
            $snowclient_id = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Test-AppID' -AsPlainText
            $snowclient_secret = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Test-Secret' -AsPlainText
        }
        else {
            $snowclient_id = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Dev-AppID' -AsPlainText
            $snowclient_secret = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Dev-Secret' -AsPlainText
        }
        $SNOW_Oauth_Token = Get-SnowAcessToken
    }else{
        $SNOW_Oauth_Token = Get-AzKeyVaultSecret -VaultName 'ZSCEVCSP05MGMKVT' -Name 'SNOW-Oauth-Token' -AsPlainText
    }

    # Dataverse token generation within loop - REMOVED
    # $body = @{
    #     grant_type    = 'client_credentials'
    #     client_id     = $Dataverse_AppID
    #     client_secret = $Dataverse_ClientSecret
    #     resource      = $DataverseEnvironmentURL
    # }

    # try {
    #     # Obtain the access token
    #     $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
    #     $accessToken = $tokenResponse.access_token
    # }
    # catch {
    #     $ex = $_.Exception.Message
    #     write-log $ex
    #     $body
    #     ScriptError -msg "Failed to get access token from Dataverse`n$($ex.message)"
    # }
    # # Construct the API request headers with the access token
    # $Dataverseheaders = @{
    #     Authorization      = "Bearer $accessToken"
    #     'Content-Type'     = 'application/json'
    #     'OData-MaxVersion' = '4.0'
    #     'OData-Version'    = '4.0'
    #     Accept             = 'application/json'
    # }

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
    $SaviyntTrackID = $messageString.SaviyntTrackID
    $saviyntTransactionID = $messageString.saviyntTransactionID
    $saviyntExitCode = $messageString.saviyntExitCode
    $snowTicketNumber = $messageString.snowTicketNumber

    Write-Log "User UPN : $userUPN"

    if($action -eq 'Upgrade' -and $LicenseType -eq 'MicrosoftCopilot'){
        Write-Log "Mircosoft Copilot license assignment is handled by a separate automation runbook 'License-Queue-Process'. This request will be processed accordingly."
        Write-Log '#####################################################################'
        Continue
    }

    # Capture licenseCategorizationID based on category - REMOVED as it depended on Dataverse
    # if ($action -eq 'downgrade') {    
    #     # $licenseCategory = $lic_category_response_details | Where-Object { $_.new_sub_category -eq 'E1' } # $lic_category_response_details is removed
    #     # $licenseCategorizationID = $licenseCategory.crd15_License_CategoryId
    # }

    # if ($action -eq 'upgrade') {
    #     switch ($LicenseType) {
    #         'Microsoft365' { 
    #             # $licenseCategory = $lic_category_response_details | Where-Object { $_.new_sub_category -eq 'E5' } # $lic_category_response_details is removed
    #             # $licenseCategorizationID = $licenseCategory.crd15_License_CategoryId
    #         }
    #         'MicrosoftCopilot' {
    #             # $licenseCategory = $lic_category_response_details | Where-Object { $_.new_sub_category -eq 'Copilot' } # $lic_category_response_details is removed
    #             # $licenseCategorizationID = $licenseCategory.crd15_License_CategoryId
    #         }
    #         Default {
    #             ScriptError('No valid license type found in the request message.') # This error is still valid
    #         }
    #     }
    # }

    try{
        $UserExists = $null
        $UserExists = Get-MgUser -UserId $userUPN -ErrorAction Stop
        if($UserExists){
            Write-Log "User $UserUPN is a valid user in Entra."
        }
    }
    catch{
        $msg = $_.Exception.Message
        if($msg -like '*does not exist*'){
            Write-Log "User $UserUPN is not a valid user in Entra."

            Write-Log "User $UserUPN is not a valid user in Entra. Closing the task $TaskNumber."
            try {
                $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '9' -WorkNotes "User $UserUPN is not a valid user in Entra. This request is marked as canceled."
                Write-Log "Task $TaskNumber updated - User $UserUPN is not a valid user in Entra. This request is marked as canceled."
            }
            catch {
                $ex = $_.Exception.Message
                write-log $ex
                ScriptError('Failed to update task in snow at User is not valid..')
            }

            Write-Output 'Updating DB for invalid user...'
            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 5, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Invalid user in Entra' WHERE ID = $ID;" # Changed $id to $ID
            Write-Log "DB record for ID $ID updated: Invalid user in Entra." -Level 'INFO'
            Write-Log '#####################################################################'
            continue # Ensure script continues
        }else{
            ScriptError "Error while getting user details from Entra for validating the user."
        }
    } 

    try{
        $UserEnabled = $null
        try{
            $User = Get-MgUser -UserId $userUPN -Property "AccountEnabled" -ErrorAction Stop
            $UserEnabled = $User.AccountEnabled
        }
        catch{
            $ex = $_.Exception.Message
            Write-Log $ex
            ScriptError "Error while getting user details from Entra for validating the user account."
        }
    }
    catch{
        $ex = $_.Exception.Message
        Write-Log $ex
        ScriptError "Error while getting user details from Entra for validating the user account."
    }

    if(!$UserEnabled){
        Write-Log "User $UserUPN account is not enabled in Entra."

        try {
            $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '9' -WorkNotes "User $UserUPN account is not enabled in Entra. This request is marked as canceled."
            Write-Log "Task $TaskNumber updated - User $UserUPN account is not enabled in Entra. This request is marked as canceled."
        }
        catch {
            $ex = $_.Exception.Message
            write-log $ex
            ScriptError('Failed to update task in snow at User is not enabled..')
        }

        Write-Output 'Updating DB for disabled user account...'
        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 5, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'User account not enabled in Entra' WHERE ID = $ID;" # Changed $id to $ID and comment
        Write-Log "DB record for ID $ID updated: User account not enabled in Entra." -Level 'INFO'
        Write-Log '#####################################################################'
        continue # Ensure script continues
    }
    
    Write-Log "Checking if the user $userUPN already has requested license ..."
    try {
        #Check license allocation status in Entra ID
        $LicenseAllocationStatus = Get-LicenseAllocationStatus -emailID $userUPN -action $action -LicenseType $LicenseType
    }
    catch {
        $ex = $_.Exception.Message
        write-log $ex
        Write-Log 'Failed to get license allocation status.'
    }
    $RequestCompletionStatus = $LicenseAllocationStatus
    $SaviyntStatus = 'Success'

    Write-Log "User license allocation status is : $LicenseAllocationStatus"

    if (($LicenseAllocationStatus -eq $false) -and (!([string]::IsNullOrEmpty($saviyntExitCode)))) {
        Write-Log "Checking saviynt replication status for $userUPN"
        Write-Log "Saviynt exit code : $saviyntExitCode"

        if($saviyntExitCode -like '*Success*'){
            
            if(((Get-Date) -gt (Get-Date $ProcessedTime).AddHours(6)) -and ([string]::IsNullOrEmpty($snowTicketNumber))){
                Write-Log "Saviynt replication is completed for $userUPN. License allocation status is $LicenseAllocationStatus."
                Write-Log "Saviynt exit code : $saviyntExitCode"
                Write-Log "Saviynt tracking ID : $saviyntID"
            }else{
                Write-Log "User $UserUPN license replication is not completed yet. Saviynt tracking ID : $saviyntID"
                Write-Log '#####################################################################'
                continue
            }
        }
        else {
            switch -Wildcard ($saviyntExitCode) {
                '*SaviyntNoUserRecord*' { 
                    $RequestCompletionStatus = $true 
                }
                '*SaviyntE5True*' { 
                    $RequestCompletionStatus = $true 
                }
                '*EmptyCustomproperty65*' { 
                    $RequestCompletionStatus = $true 
                }
                default { 
                    ScriptError("Unable to identify saviynt request exit code : $saviyntExitCode") 
                }
            }

            $SaviyntStatus = $saviyntExitCode
        }
    }

    #Update Dataverse if license is already allocated
    if ($RequestCompletionStatus -eq $true) {
        if($SaviyntStatus -notlike "*Success*"){
            $worknotes = "The automatic fulfilment service is unable to fulfil the M365 license allocation for the below request.The request is under investigation. Please track New ticket : $snowTicketNumber"
        }else{
            $worknotes = "M365 License assigned and replicated for the user $UserUPN. This request is marked as completed."
        }

        Write-Log $worknotes
        try {
            $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '3' -WorkNotes $worknotes
            Write-Log "Task $TaskNumber updated - $worknotes"
        }
        catch {
            $ex = $_.Exception.Message
            write-log $ex
            ScriptError('Failed to update task in snow at License assigned and replicated..')
        }

        write-log 'Updating DB: License already allocated / replication completed.'
        Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 7, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'License replicated' WHERE ID = $ID;" # Changed $id to $ID
        Write-Log "DB record for ID $ID updated: License replicated." -Level 'INFO'
        Write-Log '#####################################################################'
        continue # Ensure script continues
    }
    
    Write-Log "Processing $action for $userUPN"

    try {
        $skus = Get-MgSubscribedSku | Select-Object SkuPartNumber, @{Name="AvailableUnits"; Expression={ $_.PrepaidUnits.Enabled - $_.ConsumedUnits }}
    }
    catch {
        $ex = $_.Exception.Message
        write-log $ex
        ScriptError('Failed to get license pool details.')
    }

    if ($action -eq 'downgrade') {
        # Filter for E1 licenses
        $e1_skus = $skus | Where-Object { $_.SkuPartNumber -eq 'STANDARDPACK' }
        $availableE1Licenses = $e1_skus.AvailableUnits

        Write-Log "Available E1 licenses : $availableE1Licenses"

        $threshold = $availableE1Licenses/2
        $ProcessCutoff = $threshold/2

        if ($availableE1Licenses -gt $threshold ) {
            if($ThisRunProcessed -lt $ProcessCutoff){
                $ThisRunProcessed++

                write-log "Proceeding to downgrade license to E1 for the user : $UserUPN"

                try {
                    Invoke-DowngradeToE1 -UserUPN $userUPN
                }
                catch {
                    $ex = $_.Exception.Message
                    write-log $ex
                    ScriptError('Error during Invoke-DowngradeToE1 function call.')
                }

                if ($saviyntRequestReferenceIDs.ExitCode -match 'TASK\d+') {
                    $taskNumber = $matches[0]
                    $snowTicketNumber = $taskNumber
                    Write-Log "Extracted Task Number: $taskNumber"
                }elseif($saviyntRequestReferenceIDs.ExitCode -eq 'Success'){
                    $snowTicketNumber = $null
                    Write-Log "E1 license processed successfully."
                } else {
                    Write-Log "No task number found in the string."
                    $snowTicketNumber = "No task for E1"
                }

                write-log 'DowngradeTo-E1 Saviynt interaction complete. Updating database record...'

                try {
                    $updateComment = "DowngradeTo-E1 Saviynt request processed. Exit code: $($saviyntRequestReferenceIDs.ExitCode)."
                    if (!([string]::IsNullOrEmpty($snowTicketNumber))) {
                        $updateComment += " SnowTask: $snowTicketNumber"
                    }
                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 2, ProcessedDate = GETUTCDATE(), SaviyntTrackID = '$($saviyntRequestReferenceIDs.trackingID)', SaviyntTransactionID = '$($saviyntRequestReferenceIDs.APITransactionID)', SaviyntExitCode = '$($saviyntRequestReferenceIDs.ExitCode)', snowTicketNumber = '$snowTicketNumber', UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + '$updateComment' WHERE ID = $ID;"
                    Write-Log "DB record for ID $ID updated after DowngradeTo-E1 processing. SaviyntExitCode: $($saviyntRequestReferenceIDs.ExitCode), SnowTicketNumber: $snowTicketNumber" -Level 'INFO'
                    write-log '#####################################################################'
                }
                catch {
                    $ex = $_.Exception.Message
                    write-log $ex -Level 'ERROR'
                    ScriptError("Failed to update DB after DowngradeTo-E1 for ID $ID.") # This will use the updated ScriptError
                }
            }
            else{
                write-log "Daily processing limit has reached. This request will be processed in next run..."
                Write-Log '#####################################################################'
                continue
            } 
        }
        else {
            write-log 'E1 licenses are at capacity. Request will be processed once there are enough available licenses. Processing is on-hold...'
            Write-Log '#####################################################################'
            continue
        }
        #Write-Log 'Skipping downgrade due to license unavailability.'
        #Write-Log '#####################################################################'
    }
    elseif ($action -eq 'upgrade') {
        switch ($LicenseType) {
            'Microsoft365' {  
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
                            Write-Log 'RITM is not in open state. Skipping the request.'

                            try {
                                Write-Output 'Updating DB: RITM not in open state.'
                                Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 5, CompletionDate=GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'RITM is not in open state.' WHERE ID = $ID;" # Changed $id to $ID
                                Write-Log "DB record for ID $ID updated: RITM not in open state." -Level 'INFO'
                                Write-Log "#####################################################################"
                                continue # Ensure script continues
                            }
                            catch {
                                $ex = $_.Exception.Message
                                Write-Log $ex -Level 'ERROR'
                                Write-Log "Failed to update DB for RITM not in open state for ID $ID." -Level 'ERROR'
                                Write-Log "#####################################################################"
                                continue # Ensure script continues despite DB update failure in this specific case
                            }
                        }
                    }
                }
                catch {
                    $ex = $_.Exception.Message
                    Write-Log $ex
                    Write-Log 'Failed to retrieve ticket status.'
                }

                # Filter for E5 licenses
                $e5_skus = $skus | Where-Object { $_.SkuPartNumber -eq 'SPE_E5' }
                $availableE5Licenses = $e5_skus.AvailableUnits

                Write-Log "Available E5 licenses : $availableE5Licenses"

                $threshold = $availableE5Licenses/2
                $ProcessCutoff = $threshold/2

                if ($availableE5Licenses -gt $threshold ) {
                    if($ThisRunProcessed -lt $ProcessCutoff){
                        $ThisRunProcessed++
                        write-log "Available E5 Licenses : $availableE5Licenses"

                        write-log "Proceeding to Upgrade license to E5 for the user : $UserUPN"
                
                        try {
                            Invoke-UpgradeToE5 -userupn $userUPN
                        }
                        catch {
                            $ex = $_.Exception.Message
                            write-log $ex
                            ScriptError('Error during Invoke-UpgradeToE5 function call.')
                        }

                        if ($saviyntRequestReferenceIDs.ExitCode -match 'TASK\d+') {
                            $taskNumber = $matches[0]
                            $snowTicketNumber = $taskNumber
                            Write-Log "Extracted Task Number: $taskNumber"
                        }elseif($saviyntRequestReferenceIDs.ExitCode -eq 'Success'){
                            $snowTicketNumber = $null
                            Write-Log "E5 license processed successfully."
                        }else {
                            Write-Log "No task number found in the string."
                            $snowTicketNumber = "Error during New-SnowTask"
                        }

                        write-log 'UpgradeTo-E5 Saviynt interaction complete. Updating database record...'

                        try {
                            $updateComment = "UpgradeTo-E5 Saviynt request processed. Exit code: $($saviyntRequestReferenceIDs.ExitCode)."
                            if (!([string]::IsNullOrEmpty($snowTicketNumber))) {
                                $updateComment += " SnowTask: $snowTicketNumber"
                            }
                            Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 2, ProcessedDate = GETUTCDATE(), SaviyntTrackID = '$($saviyntRequestReferenceIDs.trackingID)', SaviyntTransactionID = '$($saviyntRequestReferenceIDs.APITransactionID)', SaviyntExitCode = '$($saviyntRequestReferenceIDs.ExitCode)', snowTicketNumber = '$snowTicketNumber', UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + '$updateComment' WHERE ID = $ID;"
                            Write-Log "DB record for ID $ID updated after UpgradeTo-E5 processing. SaviyntExitCode: $($saviyntRequestReferenceIDs.ExitCode), SnowTicketNumber: $snowTicketNumber" -Level 'INFO'
                            
                            if ($saviyntRequestReferenceIDs.ExitCode -eq 'Success') {
                                try {
                                    $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '2' -WorkNotes "Your Microsoft 365 license request has been successfully sent to Saviynt with tracking ID : $($saviyntRequestReferenceIDs.trackingID). It may take up to 6 hours or more for the changes to be reflected. `n `
                                        We appreciate your patience during this time and recommend waiting until the replication is complete. `nIf replication takes longer than expected, please contact the IT Helpdesk and request an update from Saviynt using the tracking ID provided."
                                    Write-Log "Task $TaskNumber updated - E5 license processed."
                                }
                                catch {
                                    $ex = $_.Exception.Message
                                    write-log $ex -Level 'ERROR'
                                    # Continue even if SNOW task update fails, DB is already updated.
                                    Write-Log "Failed to update SNOW task $TaskNumber after successful E5 Saviynt processing for ID $ID." -Level 'WARN'
                                }
                            }
                            else {
                                # Log if Saviynt ExitCode was not success, but DB update was still attempted.
                                Write-Log "Saviynt request for UpgradeTo-E5 for ID $ID processed, but ExitCode was not 'Success': $($saviyntRequestReferenceIDs.ExitCode). SnowTicketNumber: $snowTicketNumber" -Level 'WARN'
                            }
                            write-log '#####################################################################'
                        }
                        catch {
                            $ex = $_.Exception.Message
                            write-log $ex -Level 'ERROR'
                            ScriptError("Failed to update DB after UpgradeTo-E5 for ID $ID.") # This will use the updated ScriptError
                        }
                    }
                    else{
                        write-log "Today's processing limit has reached. This request will be processed in next run..."
                        Write-Log '#####################################################################'
                        continue
                    }   
                }
                else {
                    write-log 'Not enough E5 licenses. Processing is on-hold...'
                    try {
                        $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '-5' -WorkNotes "E5 licenses are at capacity. Request will be processed once there are enough available licenses."
                        Write-Log "Task $TaskNumber updated - E5 licenses are at capacity. Request will be processed once there are enough available licenses."
                    }
                    catch {
                        $ex = $_.Exception.Message
                        Write-Log $ex
                        Write-Log 'Failed to update ticket to Waiting List.'
                    }

                    Invoke-Sqlquery -qry "UPDATE Licensing_Dev.License_Requests SET StatusID = 4, ProcessedDate = GETUTCDATE(), UpdatedBy = 'DW-Automation', Comments = ISNULL(Comments + ' | ', '') + 'Licenses at capacity. Processing on hold.' WHERE ID = $ID;" # Changed $id to $ID
                    Write-Log "DB record for ID $ID updated: Licenses at capacity. Processing on hold." -Level 'INFO' # Added log for DB update

                    Write-Log '#####################################################################'
                    continue
                }
            }
            'MicrosoftCopilot' {
                Write-Log "Mircosoft Copilot license assignment is handled by a separate automation runbook 'License-Queue-Process'. This request will be processed accordingly."
                Write-Log '#####################################################################'
                Continue
            }
            Default {
                try {
                    $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '4' -WorkNotes 'Invalid license type received. Acceptable values are Microsoft365 (for E1 and E5) or MicrosoftCopilot (for Copilot). Please raise new request with correct details. Closing the ticket.'
                    Write-Log "Task $TaskNumber updated - Invalid license type received."
                }
                catch {
                    $ex = $_.Exception.Message
                    write-log $ex
                    ScriptError('Failed to update task in snow at Invalid license type received..') # This will call the modified ScriptError, which updates SQL
                }
                write-log "License Type -> $LicenseType is not valid." # This log is fine
                Write-Log '#####################################################################'
                Continue # This continue is part of the loop, not ScriptError
            }
        }
    }
    else { # This handles invalid $action
        try {
            $UpdateTask = Update-TaskStatus -TicketNumber $TaskNumber -State '4' -WorkNotes 'Invalid action received. Acceptable values are Upgrade or Downgrade. Please raise new request with correct details. Closing the ticket.'
            Write-Log "Task $TaskNumber updated - Invalid action received."
        }
        catch {
            $ex = $_.Exception.Message
            write-log $ex
            ScriptError('Failed to update task in snow at Invalid action received.') # This will call the modified ScriptError, which updates SQL
        }
        write-log "Action -> $action is not valid." # This log is fine
        Write-Log '#####################################################################'
        Continue # This continue is part of the loop, not ScriptError
    }
}

Disconnect-MgGraph | Out-Null
Disconnect-AzAccount -Confirm:$false | Out-Null

Write-Log '##############################################'
Write-Log 'SCRIPT ENDED'
Write-Log '##############################################'
