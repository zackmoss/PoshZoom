
#region Core Functions

function Get-ZoomOAuthCredentials {

    try {

        Write-Verbose -Message 'Retrieving Zoom API Credentials'

        if (!$Global:zoomAccountID) {

            $Global:zoomAccountID = Read-Host 'Enter Zoom Account ID (push ctrl + c to exit)'
        }

        if (!$Global:zoomClientID) {

            $Global:zoomClientID = Read-Host 'Enter Zoom Client ID (push ctrl + c to exit)'
        }

        if (!$Global:zoomClientSecret) {

            $Global:zoomClientSecret = Read-Host 'Enter Zoom Client Secret (push ctrl + c to exit)'
        }

        @{
            'AccountID'    = $Global:zoomAccountID
            'ClientID'     = $Global:zoomClientID
            'ClientSecret' = $Global:zoomClientSecret
        }

        Write-Verbose -Message 'Retrieved API Credentials'
    }
    catch {

        Write-Error -Message 'Problem getting Zoom OAuth variables'
    }
}

function New-ZoomOAuthToken {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, HelpMessage = "Enter Zoom App Account ID", Position = 0)]
        [string] $AccountID,

        [Parameter(Mandatory, ValueFromPipeline = $true, HelpMessage = "Enter Zoom App Client ID:", Position = 1)]
        [string] $ClientID,

        [Parameter(Mandatory, ValueFromPipeline = $true, HelpMessage = "Enter Zoom App Client Secret:", Position = 2)]
        [string] $ClientSecret
    )

    $uri = "https://zoom.us/oauth/token?grant_type=account_credentials&account_id={0}" -f $AccountID

    #Encoding of the client data
    $idSecret = '{0}:{1}' -f $ClientID, $ClientSecret
    $encodedIdSecret = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($idSecret))

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $encodedIdSecret")

    try {

        $response = Invoke-WebRequest -uri $uri -headers $headers -Method Post -UseBasicParsing

        #Write-Host -Object '[INFO] Zoom token acquired successfully' -ForegroundColor 'Cyan'

        $token = ($response.content | ConvertFrom-Json).access_token

        $token = ConvertTo-SecureString -String $token -AsPlainText -Force

        $token
    }
    catch {

        #Write-Host -Object ('[ERROR] {0}' -f $_.exception.Message) -ForegroundColor 'Red'
    }
}

function New-ZoomHeaders {

    Write-Verbose -Message '[INFO] Generating headers'

    $zoomOAuthCredentials = Get-ZoomOAuthCredentials

    $token = New-ZoomOAuthToken `
        -AccountID $zoomOAuthCredentials.AccountID `
        -ClientID $zoomOAuthCredentials.ClientID `
        -ClientSecret $zoomOAuthCredentials.ClientSecret

    if ($PSVersionTable.PSVersion.Major -ge 7) {

        $tokenStr = ConvertFrom-SecureString -SecureString $token -AsPlainText
    }
    else {

        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
        $tokenStr = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('content-type' , 'application/json')
    $headers.Add('authorization', "bearer $tokenStr")

    if ($PSVersionTable.PSVersion.Major -lt 7) {

        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    $headers
}

function Invoke-ZoomRestMethod {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestMethod] $Method,

        [Parameter(Mandatory)]
        [Uri] $Uri,

        [Parameter(Mandatory)]
        $Headers,

        $Body
    )

    $currentProtocol = [Net.ServicePointManager]::SecurityProtocol

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {

        if ($Body) {

            $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $Body -Method $Method
        }
        else {

            $response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method
        }
    }
    catch {

        $responseError = $_

        $errorDetails = ConvertFrom-Json -InputObject $responseError.ErrorDetails.Message

        if ($errorDetails.errors) {

            $errorDescription = $errorDetails.errors.message
        }
        else {

            $errorDescription = $errorDetails.message
        }

        [PSCustomObject]@{
            ErrorCode    = $errorDetails.code
            ErrorDetails = $errorDescription -replace '\.', ''
        }

        # Rate limiting logic
        if ($errorDetails.code -eq 429) {

            # Max retry count: 5
            if ($Script:RetryCount -lt 5) {

                Write-Warning '[Error 429] Too many requests encountered, retrying in 1 second'

                Start-Sleep -Seconds 1

                Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method

                $Script:RetryCount ++
            }
        }
    }

    $response

    [Net.ServicePointManager]::SecurityProtocol = $currentProtocol
}


#endregion

#region Helper Functions


function Get-AvailableNumbers {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int] $RangeStart,

        [Parameter(Mandatory)]
        [int] $RangeEnd,

        [Parameter(Mandatory)]
        [psobject] $UsedNumbers
    )

    begin {

        $numberRange = $RangeStart..$RangeEnd

        $numberBucket = @()
    }

    process {

        foreach ($number in $UsedNumbers) {

            $numberBucket += [convert]::ToInt32($number)
        }

        $numberRange | ForEach-Object {

            if (!$numberBucket.Contains($_)) {

                $availableNumbers = $_

                $availableNumbers
            }
        }
    }
}

function Write-Log {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [string] $Message,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Info', 'Warn', 'Error')]
        [string] $Severty = 'Info',

        [switch] $Console,

        [switch] $LogToFile
    )

    $logTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    $logObject = [PSCustomObject]@{

        Time    = $logTimestamp
        Severty = $Severty
        Message = $Message
    }

    if ($LogToFile) {

        $logObject | Export-Csv -Path ('{0}\{1}_PSLog.csv' -f $env:TEMP, (Get-Date -Format 'MMddyyy')) -NoTypeInformation -Encoding ASCII
    }

    if ($Console) {

        switch ($Severty) {

            Warn {

                Write-Host -Object ('{0} [{1}]' -f $logObject.Time, $logObject.Severty) -ForegroundColor Gray
                Write-Host -Object ('{0}' -f $logObject.Message) -ForegroundColor Yellow
            }
            Error {

                Write-Host -Object ('{0} [{1}]' -f $logObject.Time, $logObject.Severty) -ForegroundColor Gray
                Write-Host -Object ('{0}' -f $logObject.Message) -ForegroundColor Red
            }
            Default {

                Write-Host -Object ('{0} [{1}]' -f $logObject.Time, $logObject.Severty) -ForegroundColor Gray
                Write-Host -Object ('{0}' -f $logObject.Message) -ForegroundColor Cyan
            }
        }
    }
}


#endregion

#region User Functions


function Get-ZoomUserSummary {

    $headers = New-ZoomHeaders

    $uri = 'https://api.zoom.us/v2/users/summary'

    $response = Invoke-ZoomRestMethod -Uri $uri -Headers $headers -Method Get

    if ($response.ErrorCode) {

        $response
    }
    else {

        $response
    }
}

function Get-ZoomUserInfo {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders

        $returnObject = @()
    }

    process {

        foreach ($user in $UserID) {

            $uri = 'https://api.zoom.us/v2/users/{0}' -f $user

            $initialResponse = Invoke-ZoomRestMethod -Uri $uri -Headers $headers -Method Get

            if ($initialResponse.ErrorCode) {

                $initialResponse
            }
            else {

                $returnObject += $initialResponse
            }
        }
    }

    end {

        $returnObject
    }

}

function Get-ZoomUser {

    [CmdletBinding()]
    param (
        [ValidateSet('active', 'inactive', 'pending')]
        [string] $Status = 'active'
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/users/'

        $pageSize = [int] 300

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('status', $Status)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $pageToken = $initialResponse.next_page_token

            $returnObject = @()

            $returnObject += $initialResponse.users
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $returnObject += $continuedResponse.users
        }
    }

    end {

        $returnObject
    }
}

function Get-ZoomUserDelegate {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders

        $returnObject = @()
    }

    process {

        foreach ($user in $UserID) {

            $uri = 'https://api.zoom.us/v2/users/{0}/assistants' -f $UserID

            $initialResponse = Invoke-ZoomRestMethod -Uri $uri -Headers $headers -Method Get

            if ($initialResponse.ErrorCode) {

                $initialResponse
            }
            else {

                if (($initialResponse.assistants).Length -gt 0) {

                    $returnObject += $initialResponse
                }
                else {

                    Write-Host -Object ('[INFO] No delegates found for {0}' -f $UserID) -ForegroundColor 'Yellow'
                }
            }
        }
    }

    end {

        $returnObject
    }

}

function Invoke-RevokeZoomSSOToken {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        foreach ($user in $UserID) {

            $uri = ('https://api.zoom.us/v2/users/{0}/token' -f $user)

            $response = Invoke-ZoomRestMethod -Uri $uri -Headers $headers -Method Delete

            if ($response.ErrorCode) {

                $response
            }
            else {

                $response
            }
        }
    }

    end {

    }
}

function Remove-ZoomUser {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        foreach ($user in $UserID) {

            $uri = ('https://api.zoom.us/v2/users/{0}') -f $user

            $request = [System.UriBuilder] $uri
            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('action', 'delete')

            $request.Query = $query.ToString()

            $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Delete

            if ($response.ErrorCode) {

                $response
            }
            else {

                Write-Host -Object ('[INFO] User {0} removed successfully' -f $user) -ForegroundColor 'Yellow'
            }
        }
    }

    end {

    }
}


#endregion

#region Phone Functions

function Add-ZoomDeskPhoneDevice {

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string] $MACAddress,

        [Parameter(Mandatory)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string] $UserID,

        [Parameter(Mandatory)]
        [string] $Brand,

        [Parameter(Mandatory)]
        [string] $Model,

        [string] $TemplateId
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/devices'

        # Setting the display name to the default
        $phoneDisplayName = 'Desk Phone'
    }

    process {

        $rawMAC = $MacAddress -replace '(:|-|\.)'
        $convertedMAC = $RawMAC -replace '..(?!$)', '$&-'

        $requestBody = @{}

        $requestBody.Add('mac_address', $convertedMAC)
        $requestBody.Add('assigned_to', $UserID)
        $requestBody.Add('display_name', $phoneDisplayName)
        $requestBody.Add('type', $Brand)
        $requestBody.Add('model', $Model)
        $requestBody.Add('provision_template_id', $TemplateId)

        $requestBody = $requestBody | ConvertTo-Json

        $response = Invoke-ZoomRestMethod -Uri $uri -Headers $headers -Body $requestBody -Method Post

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response
        }
    }

    end {


    }
}

function Add-ZoomPhoneBlockedNumber {

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string] $PhoneNumber,

        [Parameter(Mandatory)]
        [ValidateSet('inbound', 'outbound')]
        [string] $BlockType,

        [Parameter(Mandatory)]
        [string] $Comment
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/blocked_list'
    }

    process {

        $convertedPhone = $PhoneNumber -replace '(\(|\)|-| |\.|)'

        $request = [System.UriBuilder]$uri

        $requestBody = @{
            match_type   = 'phoneNumber'
            phone_number = '+1' + $convertedPhone
            block_type   = $BlockType
            status       = 'active'
            comment      = $Comment
        }

        $requestBody = $requestBody | ConvertTo-Json

        $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Body $requestBody -Method Post

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response
        }
    }
}

function Get-ZoomCallLogs {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "If parameter is omitted, start date will be set to the last 24 hours")]
        [datetime] $StartDateTime = ((Get-Date).AddDays(-1)),

        [Parameter(HelpMessage = "If parameter is omitted, the current date time will be used")]
        [datetime] $EndDateTime = (Get-Date),

        [ValidateSet('all', 'missed')]
        [string] $Type = 'all'
    )

    begin {

        if ($StartDateTime) {

            [string]$StartDateTime = $StartDateTime.ToString('yyyy-MM-dd')
        }

        if ($EndDateTime) {

            [string]$EndDateTime = $EndDateTime.ToString('yyyy-MM-dd')
        }

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/call_logs'

        $pageSize = [int] 300

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('type', $Type)
        $query.Add('from', $StartDateTime)
        $query.Add('to', $EndDateTime)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        $initialObject = @()

        $initialObject += $initialResponse.call_logs
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('type', $Type)
            $query.Add('from', $StartDateTime)
            $query.Add('to', $EndDateTime)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.call_logs
        }
    }

    end {

        $initialObject
    }
}

function Get-ZoomCommonArea {

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/common_areas'

        $pageSize = [int] 100

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $pageToken = $initialResponse.next_page_token

            $returnObject = @()

            $returnObject += $initialResponse.common_areas
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $returnObject += $continuedResponse.common_areas
        }
    }

    end {

        $returnObject
    }
}

function Get-ZoomCommonAreaSettings {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $CommonAreaId
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = ('https://api.zoom.us/v2/phone/common_areas/{0}/settings' -f $CommonAreaId)

        $pageSize = [int] 100

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $pageToken = $initialResponse.next_page_token

            $returnObject = @()

            $returnObject += $initialResponse.desk_phones
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $returnObject += $continuedResponse.desk_phones
        }
    }

    end {

        $returnObject
    }
}

function Get-ZoomPhoneHotDeskingStatus {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string] $UserID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        $uri = ('https://api.zoom.us/v2/phone/users/{0}/settings') -f $UserID

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        $request.Query = $query.ToString()

        $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response.desk_phone.devices.policy.hot_desking
        }
    }

    end {

    }
}

function Get-ZoomPhoneNumber {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "The query response by number assignment")]
        [ValidateSet("all", "assigned", "unassigned", "byoc")]
        [string] $Type,

        [Parameter(HelpMessage = "The type of assignee to whom the number is assigned")]
        [ValidateSet("user", "callQueue", "autoReceptionist", "commonAreaPhone")]
        [string] $AssignedType,

        [Parameter(HelpMessage = "The type of phone number")]
        [ValidateSet("toll", "tollfree")]
        [string] $NumberType,

        [Parameter(HelpMessage = "The unique identifier of the site from the List Phone Sites API")]
        [string] $SiteID
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/numbers'

        $pageSize = [int] 100

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        if ($Type) {

            $query.Add('type', $Type)
        }
        if ($AssignedType) {

            $query.Add('extension_type', $AssignedType)
        }
        if ($NumberType) {

            $query.Add('number_type', $NumberType)
        }
        if ($SiteID) {

            $query.Add('site_id', $SiteID)
        }

        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        $initialObject = @()

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $initialObject += $initialResponse.phone_numbers
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.phone_numbers
        }
    }

    end {

        $initialObject
    }

}

function Get-ZoomDeskPhoneDevice {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "Device status: assigned or unassigned to list device status in Zoom account")]
        [ValidateSet("assigned", "unassigned")]
        [string] $Type,

        [Parameter(HelpMessage = "The unique identifier of the site from the List Phone Sites API")]
        [string] $SiteID
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/devices'

        # Setting the Zoom API page size. Min 30 Max 300
        $pageSize = [int] 300

        # Building the initial request
        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('type', $Type)
        $query.Add('site_id', $SiteID)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        $initialObject = @()

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $initialObject += $initialResponse.devices
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('type', $Type)
            $query.Add('site_id', $SiteID)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.devices
        }
    }

    end {

        $initialObject
    }

}

function Get-ZoomDeskPhoneProvisionTemplate {

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/provision_templates'

        # Setting the Zoom API page size. Min 30 Max 300
        $pageSize = [int] 300

        # Building the initial request
        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        $initialObject = @()

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $initialObject += $initialResponse.provision_templates
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.provision_templates
        }
    }

    end {

        $initialObject
    }

}

function Remove-ZoomPhoneBlockedNumber {

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string] $ID
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = ('https://api.zoom.us/v2/phone/blocked_list/{0}' -f $ID)
    }

    process {

        $request = [System.UriBuilder]$uri

        $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Delete

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response
        }
    }
}

function Get-ZoomPhoneSharedLineGroup {

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/shared_line_groups'

        # Setting the Zoom API page size. Min 30 Max 300
        $pageSize = [int] 300

        # Building the initial request
        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        $initialObject = @()

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $initialObject += $initialResponse.shared_line_groups
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.shared_line_groups
        }
    }

    end {

        $initialObject
    }
}

function Get-ZoomPhoneSharedLineGroupSettings {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "The unique identifier of the Shared Line Group")]
        [string] $SharedLineGroupID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        $uri = 'https://api.zoom.us/v2/phone/shared_line_groups/{0}' -f $SharedLineGroupID

        $response = Invoke-ZoomRestMethod -Uri $uri -Headers $headers -Method Get

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response
        }
    }

    end {

    }
}

function Get-ZoomPhoneUser {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "The unique identifier of the site from the List Phone Sites API")]
        [string] $SiteID,

        [Parameter(HelpMessage = "The status of the Zoom Phone user")]
        [ValidateSet("activate", "deactivate")]
        [string] $Status,

        [Parameter(HelpMessage = "The partial string of user's name, extension number or phone number e.g. test@test.com")]
        [string] $Keyword
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/users'

        # Setting the Zoom API page size. Min 30 Max 100
        $pageSize = [int] 100

        # Building the initial request
        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('site_id', $SiteID)
        $query.Add('status', $Status)
        $query.Add('keyword', $Keyword)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        $initialObject = @()

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $initialObject += $initialResponse.users
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('site_id', $SiteID)
            $query.Add('status', $Status)
            $query.Add('keyword', $Keyword)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.users
        }
    }

    end {

        $initialObject
    }

}

function Get-ZoomPhoneUserProfile {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        $uri = ('https://api.zoom.us/v2/phone/users/{0}') -f $UserID

        $request = [System.UriBuilder]$Uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        $request.Query = $query.ToString()

        $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response
        }
    }

    end {

    }
}

function Get-ZoomPhoneUserProfileSettings {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        $uri = ('https://api.zoom.us/v2/phone/users/{0}/settings') -f $UserID

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        $request.Query = $query.ToString()

        $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response
        }
    }

    end {

    }

}

function Get-ZoomDeskPhoneIPInfo {

    $headers = New-ZoomHeaders

    $uri = 'https://api.zoom.us/v2/phone/metrics/location_tracking'

    # Setting the Zoom API page size. Min 30 Max 100
    $pageSize = [int] 100

    # Building the initial request
    $request = [System.UriBuilder] $uri
    $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    $query.Add('page_size', $pageSize)
    $query.Add('type', 6)

    $request.Query = $query.ToString()

    $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

    $pageToken = $initialResponse.next_page_token

    $initialResponse.location_tracking | ForEach-Object {

        $convertedPhoneMAC = ($PSItem.device.mac_address -replace '(:|-|\.)')
        $convertedSwitchMAC = ($PSItem.network_switch.mac_address -replace '(:|-|\.)')

        [PSCustomObject]@{

            MACAddress        = $convertedPhoneMAC
            IPAddress         = $PSItem.device.private_ip
            NetworkSwitchPort = $PSItem.network_switch.port
            NetworkSwitchMAC  = $convertedSwitchMAC
            Assignee          = $PSItem.assignees.name
            AssigneeExtension = $PSItem.assignees.extension_number
        }
    }

    while ($pageToken) {

        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)
        $query.Add('type', 6)
        $query.Add('next_page_token', $pageToken)

        $request.Query = $query.ToString()

        $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $continuedResponse.next_page_token

        $continuedResponse.location_tracking | ForEach-Object {

            $convertedPhoneMAC = ($PSItem.device.mac_address -replace '(:|-|\.)')
            $convertedSwitchMAC = ($PSItem.network_switch.mac_address -replace '(:|-|\.)')

            [PSCustomObject]@{

                MACAddress        = $convertedPhoneMAC
                IPAddress         = $PSItem.device.private_ip
                NetworkSwitchPort = $PSItem.network_switch.port
                NetworkSwitchMAC  = $convertedSwitchMAC
                Assignee          = $PSItem.assignees.name
                AssigneeExtension = $PSItem.assignees.extension_number
            }
        }
    }
}

function Get-ZoomDeskPhoneSettings {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        $uri = ('https://api.zoom.us/v2/phone/users/{0}/settings') -f $UserID

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        $request.Query = $query.ToString()

        $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response.desk_phone.devices
        }
    }

    end {

    }

}

function Get-ZoomPhoneQueue {

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/call_queues'

        # Setting the Zoom API page size. Min 30 Max 300
        $pageSize = [int] 300

        # Building the initial request
        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        $initialObject = @()

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $initialObject += $initialResponse.call_queues
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.call_queues
        }
    }

    end {

        $initialObject
    }
}

function Get-ZoomPhoneQueueMembers {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "The unique identifier of the Queue")]
        [string] $QueueID
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/call_queues/{0}/members' -f $QueueID

        $pageSize = [int] 300

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $initialObject += $initialResponse.call_queue_members
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.call_queue_members
        }
    }

    end {

        $initialObject
    }
}

function Get-ZoomPhoneQueueSettings {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "The unique identifier of the Queue")]
        [string] $QueueID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        $uri = 'https://api.zoom.us/v2/phone/call_queues/{0}' -f $QueueID

        $response = Invoke-ZoomRestMethod -Uri $uri -Headers $headers -Method Get

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response
        }
    }

    end {

    }
}

function Set-ZoomAutoReceptionistNumber {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [string] $AutoReceptionistID,

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $PhoneNumber
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        $uri = 'https://api.zoom.us/v2/phone/auto_receptionists/{0}/phone_numbers' -f $AutoReceptionistID

        foreach ($number in $PhoneNumber) {

            $convertedNumber = '1{0}{1}{2}' -f $number.Substring(1, 3), $number.Substring(6, 3), $number.Substring(10, 4)

            $phoneNumberID = Get-ZoomPhoneNumbers -ApiKey $ApiKey -ApiSecret $ApiSecret | Where-Object {
                $_.Assigned -eq $false -and $_.Number -eq $convertedNumber
            } | Select-Object -ExpandProperty Id

            $request = [System.UriBuilder] $uri

            $requestBody = @{
                phone_numbers = @(
                    @{
                        id = $phoneNumberID
                    }
                )
            }

            $requestBody = $requestBody | ConvertTo-Json

            $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Body $requestBody -Method Post

            if ($response.ErrorCode) {

                $response
            }
            else {

                $response
            }
        }
    }
}

function Set-ZoomCommonAreaHotDeskStatus {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $CommonAreaId,

        [Parameter(Mandatory)]
        [ValidateSet('on', 'off')]
        [string] $Status
    )

    begin {

    }

    process {

        $uri = ('https://api.zoom.us/v2/phone/common_areas/{0}/settings/desk_phone' -f $CommonAreaId)

        $request = [System.UriBuilder] $uri

        $commonAreas = Get-ZoomCommonArea | Where-Object { $_.id -eq $CommonAreaId }

        foreach ($device in $commonAreas) {

            $headers = New-ZoomHeaders

            $requestBody = @{
                desk_phones = @(
                    @{
                        id          = $device.desk_phones.id
                        hot_desking = @{
                            status = $Status
                        }
                    }
                )
            }

            $requestBody = $requestBody | ConvertTo-Json -Depth 10

            $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Body $requestBody -Method Patch

            if ($response.ErrorCode) {

                $response
            }
            else {

                if ($Status -eq 'on') {

                    Write-Host -Object ('[INFO] Hot Desking enabled for device:{0}' -f $device.desk_phones.display_name) -ForegroundColor Cyan
                }
                else {

                    Write-Host -Object ('[INFO] Hot Desking disabled for device:{0}' -f $device.desk_phones.display_name) -ForegroundColor Cyan
                }
            }
        }
    }
}

function Set-ZoomPhoneUserHotDeskStatus {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email' , 'mail')]
        [string[]] $UserID,

        [Parameter(Mandatory)]
        [ValidateSet('on', 'off')]
        [string] $Status
    )

    begin {

    }

    process {

        $uri = ('https://api.zoom.us/v2/phone/users/{0}/settings/desk_phone' -f $UserID)

        $request = [System.UriBuilder] $uri

        $userDevices = Get-ZoomPhoneUserProfileSettings -UserID $UserID

        foreach ($device in $userDevices.desk_phone.devices) {

            $headers = New-ZoomHeaders

            $requestBody = @{
                desk_phone = @{
                    devices = @(
                        @{
                            id     = $device.id
                            policy = @{
                                hot_desking = @{
                                    status = $Status
                                }
                            }
                        }
                    )
                }
            }

            $requestBody = $requestBody | ConvertTo-Json -Depth 10

            $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Body $requestBody -Method Patch

            if ($response.ErrorCode) {

                $response
            }
            else {

                if ($Status -eq 'on') {

                    Write-Host -Object ('[INFO] Hot Desking enabled for device:{0}' -f $device.display_name) -ForegroundColor Cyan
                }
                else {

                    Write-Host -Object ('[INFO] Hot Desking disabled for device:{0}' -f $device.display_name) -ForegroundColor Cyan
                }
            }
        }
    }
}

function Update-ZoomDeskPhoneDevice {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [string] $DeviceID,

        [string] $AssignedTo,

        [string] $DisplayName,

        [Parameter(HelpMessage = "This will replace the current Device MAC Address with a new device MAC Address")]
        [string] $MACAddress,

        [Parameter(Mandatory,
            HelpMessage = "Provision template id from Get-ZoomDeskPhoneProvisionTemplate. Supported only by some devices. Empty string represents 'No value set'",
            ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string] $ProvisionTemplateID
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        $uri = 'https://api.zoom.us/v2/phone/devices/{0}' -f $DeviceID

        $request = [System.UriBuilder] $uri

        $requestBody = @{
            assigned_to           = $AssignedTo
            display_name          = $DisplayName
            mac_address           = $MACAddress
            provision_template_id = $ProvisionTemplateID
        }

        $requestBody = $requestBody | ConvertTo-Json

        $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Body $requestBody -Method Patch

        if ($response.ErrorCode) {

            $response
        }
        else {

            $response
        }
    }
}


#endregion

#regoin Room Functions


function Get-ZoomRoom {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "The name of a Zoom Room. If you do not call this parameter, the API will return all of the account's Zoom Rooms")]
        [string] $Keyword
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/rooms'

        $pageSize = [int] 100

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('query_name', $Keyword)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $pageToken = $initialResponse.next_page_token

            $returnObject = @()

            $returnObject += $initialResponse.rooms
        }
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('query_name', $Keyword)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $returnObject += $continuedResponse.rooms
        }
    }

    end {

        $returnObject
    }
}

function Get-ZoomRoomDevice {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipeline = $True,
            HelpMessage = "Unique Identifier of the Zoom Room. This can be retrieved from the response of List Zoom Rooms API")]
        [string[]] $RoomId
    )

    begin {

        $headers = New-ZoomHeaders
    }

    process {

        foreach ($room in $RoomId) {

            $uri = 'https://api.zoom.us/v2/rooms/{0}/devices' -f $room

            $response = Invoke-ZoomRestMethod -Uri $uri -Headers $headers -Method Get

            if ($response.ErrorCode) {

                $response
            }
            else {

                $response.devices
            }
        }
    }

    end {

    }
}

#endregion
