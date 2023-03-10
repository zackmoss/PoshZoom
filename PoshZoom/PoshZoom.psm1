
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

function Get-ZoomUser {

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

function Get-ZoomUsers {

    [CmdletBinding()]
    param (
        [ValidateSet('active', 'inactive', 'pending')]
        [string] $Status = 'active'
    )

    begin {

        $headers = New-ZoomHeaders

        $uri = 'https://api.zoom.us/v2/users/'

        # Setting the Zoom API page size. Min 30 Max 300
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

function Invoke-RevokeSSOToken {

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

                Write-Host -Object ('[INFO] SSO Token removed successfully for {0}' -f $user) -ForegroundColor 'Yellow'
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

            $response.desk_phone.devices
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

        foreach ($device in $userDevices) {

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


#endregion
