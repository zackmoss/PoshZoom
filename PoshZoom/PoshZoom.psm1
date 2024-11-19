
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

    $currentProtocol = [Net.ServicePointManager]::SecurityProtocol

    if ($currentProtocol.ToString().Split(',').Trim() -notcontains 'Tls12') {

        [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
    }

    $uri = "https://zoom.us/oauth/token?grant_type=account_credentials&account_id={0}" -f $AccountID

    #Encoding of the client data
    $idSecret = '{0}:{1}' -f $ClientID, $ClientSecret
    $encodedIdSecret = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($idSecret))

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $encodedIdSecret")

    try {

        $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post -UseBasicParsing

        $token = ($response.content | ConvertFrom-Json).access_token

        $token = ConvertTo-SecureString -String $token -AsPlainText -Force

        $token
    }
    catch {

        throw $_.Exception.Message
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

                    $returnObject += $initialResponse.assistants
                }
                else {

                    Write-Host -Object ('No delegates found for {0}' -f $UserID)
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

                Write-Host -Object ('User {0} removed successfully' -f $user)
            }
        }
    }

    end {

    }
}

function Set-ZoomUserPhoneFeature {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email' , 'mail')]
        [string[]] $UserID,

        [Parameter(Mandatory)]
        [bool] $Enabled
    )

    begin {

    }

    process {

        $uri = ('https://api.zoom.us/v2/users/{0}/settings' -f $UserID)

        $request = [System.UriBuilder] $uri

        $headers = New-ZoomHeaders

        $requestBody = @{
            feature = @{
                zoom_phone = $Enabled
            }
        }

        $requestBody = $requestBody | ConvertTo-Json

        $response = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Body $requestBody -Method Patch

        if ($response.ErrorCode) {

            $response
        }
        else {

            if ($Enabled) {

                Write-Host -Object ('Zoom Phone feature enabled for {0}' -f $UserID)
            }
            else {

                Write-Host -Object ('Zoom Phone feature disabled for {0}' -f $UserID)
            }
        }
    }
}


#endregion

#region Phone Functions


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

function Get-ZoomDeskPhoneIPInfo {

    begin {

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

        $initialObject = @()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        $pageToken = $initialResponse.next_page_token

        $initialObject += $initialResponse.location_tracking
    }

    process {

        while ($pageToken) {

            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('page_size', $pageSize)
            $query.Add('next_page_token', $pageToken)
            $query.Add('type', 6)

            $request.Query = $query.ToString()

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

            $pageToken = $continuedResponse.next_page_token

            $initialObject += $continuedResponse.location_tracking
        }
    }

    end {

        $initialObject
    }
}

function Get-ZoomDeskPhoneSetting {

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

function Add-ZoomDeskPhoneDevice {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'The MAC address of the desk phone.')]
        [string] $MACAddress,

        [Parameter(Mandatory, HelpMessage = 'User ID or email address of the user to whom this device is to be assigned.')]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string] $UserID,

        [Parameter(Mandatory, HelpMessage = 'Manufacturer (brand) name of the device.')]
        [string] $Brand,

        [Parameter(Mandatory, HelpMessage = 'Model name of the device.')]
        [string] $Model,

        [Parameter(HelpMessage = 'Display name of the desk phone.')]
        [string] $DisplayName,

        [Parameter(HelpMessage = 'Provision template id. Supported only by some devices. Empty string represents no value set')]
        [string] $TemplateId
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/devices'

        if ($DisplayName) {

            $phoneDisplayName = $DisplayName
        }
        else {

            # Setting the display name to the default
            $phoneDisplayName = 'Desk Phone'
        }
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

function Update-ZoomDeskPhoneDevice {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $DeviceID,

        [string] $AssignedTo,

        [string] $DisplayName,

        [Parameter(HelpMessage = 'This will replace the current Device MAC Address with a new device MAC Address')]
        [string] $MACAddress,

        [Parameter(Mandatory,
            HelpMessage = 'Provision template id from Get-ZoomDeskPhoneProvisionTemplate. Supported only by some devices. Empty string represents no value set',
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

function Add-ZoomPhoneBlockedNumber {

    [CmdletBinding()]
    param (
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

function Get-ZoomPhoneCallLog {

    [CmdletBinding()]
    param (

        [Parameter(HelpMessage = "If parameter is omitted, start date will be set to the last 24 hours")]
        [datetime] $StartDateTime = ((Get-Date).AddDays(-1)),

        [Parameter(HelpMessage = "If parameter is omitted, the current date time will be used")]
        [datetime] $EndDateTime = (Get-Date)
    )

    begin {

        if ($StartDateTime) {

            [string]$StartDateTime = $StartDateTime.ToString('yyyy-MM-dd')
        }

        if ($EndDateTime) {

            [string]$EndDateTime = $EndDateTime.ToString('yyyy-MM-dd')
        }

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/phone/call_history'

        $pageSize = [int] 300

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
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

function Get-ZoomPhoneCommonArea {

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

function Get-ZoomPhoneCommonAreaSetting {

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

        $pageToken = $initialResponse.next_page_token

        $returnObject = @()

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

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

            if ($response.desk_phone.devices.policy.hot_desking) {

                $response.desk_phone.devices.policy.hot_desking
            }
            else {

                Write-Host -Object ('Hot desking not enabled for {0}' -f $UserID)
            }

        }
    }

    end {

    }
}

function Get-ZoomPhoneNumber {

    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = 'The query response by number assignment')]
        [ValidateSet("all", "assigned", "unassigned", "byoc")]
        [string] $Type,

        [Parameter(HelpMessage = 'The type of assignee to whom the number is assigned')]
        [ValidateSet("user", "callQueue", "autoReceptionist", "commonAreaPhone")]
        [string] $AssignedType,

        [Parameter(HelpMessage = 'The type of phone number')]
        [ValidateSet("toll", "tollfree")]
        [string] $NumberType,

        [Parameter(HelpMessage = 'The unique identifier of the site from the List Phone Sites API')]
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
    param (
        [Parameter(Mandatory)]
        [string] $BlockedListID
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = ('https://api.zoom.us/v2/phone/blocked_list/{0}' -f $BlockedListID)
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

function Get-ZoomPhoneSharedLineGroupSetting {

    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = 'The unique identifier of the Shared Line Group')]
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
        [Parameter(HelpMessage = 'The unique identifier of the site from the List Phone Sites API')]
        [string] $SiteID,

        [Parameter(HelpMessage = 'The status of the Zoom Phone user')]
        [ValidateSet("activate", "deactivate")]
        [string] $Status,

        [Parameter(HelpMessage = 'The partial string of users name, extension number or phone number e.g. test@test.com')]
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

        switch ($PSBoundParameters.Keys) {
            SiteID { $query.Add('site_id', $SiteID) }
            Status { $query.Add('status', $Status) }
            Keyword { $query.Add('keyword', $Keyword) }
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

            $initialObject += $initialResponse.users
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

function Get-ZoomPhoneUserProfileSetting {

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

function Get-ZoomPhoneQueueMember {

    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = 'The unique identifier of the Queue')]
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

function Get-ZoomPhoneQueueSetting {

    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = 'The unique identifier of the Queue')]
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

function Set-ZoomPhoneAutoReceptionistNumber {

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

            $phoneNumberID = Get-ZoomPhoneNumber | Where-Object { $_.Assigned -eq $false -and $_.Number -eq $convertedNumber } |
            Select-Object -ExpandProperty Id

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

function Set-ZoomPhoneCommonAreaHotDeskStatus {

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

        $commonAreas = Get-ZoomPhoneCommonArea | Where-Object { $_.id -eq $CommonAreaId }

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

                    Write-Host -Object ('Hot Desking enabled for device {0}' -f $device.desk_phones.display_name)
                }
                else {

                    Write-Host -Object ('Hot Desking disabled for device {0}' -f $device.desk_phones.display_name)
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

        $userDevices = Get-ZoomPhoneUserProfileSetting -UserID $UserID

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

                    Write-Host -Object ('Hot Desking enabled for device {0}' -f $device.display_name)
                }
                else {

                    Write-Host -Object ('Hot Desking disabled for device {0}' -f $device.display_name)
                }
            }
        }
    }
}


#endregion

#region Room Functions


function Get-ZoomRoom {

    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = 'The name of a Zoom Room. If you do not call this parameter, the API will return all of the accounts Zoom Rooms')]
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

            $initialObject += $initialResponse.rooms
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

            $initialObject += $continuedResponse.rooms
        }
    }

    end {

        $initialObject
    }
}

function Get-ZoomRoomDevice {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $True,
            HelpMessage = 'Unique Identifier of the Zoom Room. This can be retrieved from the response of List Zoom Rooms API')]
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

#region Chat Functions


function Get-ZoomUserChatChannel {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email' , 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = ('https://api.zoom.us/v2/chat/users/{0}/channels' -f $UserID)

        $pageSize = [int] 50

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

            $initialObject += $initialResponse.channels
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

            $initialObject += $continuedResponse.channels
        }
    }

    end {

        $initialObject
    }
}

function Search-ZoomUserChatMessages {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email' , 'mail')]
        [string[]] $UserID,

        [Parameter(HelpMessage = 'This field allows you to query by the channel ID of a channel in which the user had chat conversations.')]
        [string] $ChannelID,

        [Parameter(HelpMessage = 'This field allows you to query by the email address, user ID, or member ID of a chat contact with whom the user communicated.')]
        [string] $ContactID,

        [datetime] $From
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = ('https://api.zoom.us/v2/chat/users/{0}/messages' -f $UserID)

        $pageSize = [int] 50

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

        switch ($PSBoundParameters.Keys) {
            ChannelID { $query.Add('to_channel', $ChannelID) }
            ContactID { $query.Add('to_contact', $ContactID) }
            From {
                $query.Add('from', $From)
                $query.Add('to', (Get-Date))
            }
        }

        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $pageToken = $initialResponse.next_page_token

            $initialObject += $initialResponse.messages
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

            $initialObject += $continuedResponse.messages
        }
    }

    end {

        $initialObject
    }
}

function Invoke-SendZoomChatMessage {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email' , 'mail')]
        [string[]] $UserID,

        [Parameter(HelpMessage = 'The channel ID of the channel where you would like to send a message.')]
        [string] $ChannelID,

        [string] $Message,

        [switch] $All
    )

    $uri = ('https://api.zoom.us/v2/chat/users/{0}/messages' -f $UserID)

    $request = [System.UriBuilder] $uri

    $headers = New-ZoomHeaders

    if ($All) {

        $requestBody = @{

            at_items   = @(
                @{
                    at_type        = 2
                    start_position = 0
                    end_position   = 3
                }
            )
            message    = ('@all {0}' -f $Message)
            to_channel = $ChannelID
        }
    }
    else {

        $requestBody = @{

            message    = $Message
            to_channel = $ChannelID
        }
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


#endregion

#region Meeting Functions


function Get-ZoomUserRecording {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email' , 'mail')]
        [string[]] $UserID,

        [string] $FromDate,

        [string] $ToDate,

        [switch] $DownloadURL
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = ('https://api.zoom.us/v2/users/{0}/recordings' -f $UserID)

        $pageSize = [int] 50

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)
        if ($FromDate) {

            $FromDate = $FromDate | Get-Date -Format 'yyyy-MM-dd'
            $query.Add('from', $FromDate)
        }
        if ($ToDate) {

            $ToDate = $ToDate | Get-Date -Format 'yyyy-MM-dd'
            $query.Add('to', $ToDate)
        }

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $pageToken = $initialResponse.next_page_token

            $initialObject += $initialResponse.meetings
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

            $initialObject += $continuedResponse.meetings
        }
    }

    end {

        if ($DownloadURL) {

            $initialObject.recording_files | ForEach-Object {

                if ($PSItem.file_type -eq 'MP4') {

                    $PSItem.download_url
                }
            }
        }
        else {

            $initialObject
        }
    }
}

function Get-ZoomMeetingRecording {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $MeetingID,

        [switch] $DownloadURL
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = ('https://api.zoom.us/v2/meetings/{0}/recordings' -f $MeetingID)

        $pageSize = [int] 50

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

            if ($DownloadURL) {

                $initialResponse.recording_files | ForEach-Object {

                    if ($PSItem.file_type -eq 'MP4') {

                        $PSItem.download_url
                    }
                }
            }
            else {

                $initialObject += $initialResponse
            }
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

            $initialObject += $continuedResponse
        }
    }

    end {

        $initialObject
    }
}

function Get-ZoomUserMeetingList {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email' , 'mail')]
        [string[]] $UserID
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = ('https://api.zoom.us/v2/users/{0}/meetings' -f $UserID)

        $pageSize = [int] 50

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)
        $query.Add('type', 'previous_meetings')

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Headers $headers -Method Get

        if ($initialResponse.ErrorCode) {

            $initialResponse
        }
        else {

            $pageToken = $initialResponse.next_page_token

            $initialObject += $initialResponse.meetings
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

            $initialObject += $continuedResponse.meetings
        }
    }

    end {

        $initialObject
    }
}


#endregion
