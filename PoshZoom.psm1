
#region Core Functions


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

        Write-Host -Object '[INFO] Zoom token acquired successfully' -ForegroundColor 'Cyan'

        $token = ($response.content | ConvertFrom-Json).access_token

        $token = ConvertTo-SecureString -String $token -AsPlainText -Force

        $Script:ZoomToken = $token
    }
    catch {

        Write-Host -Object ('[ERROR] {0}' -f $_.exception.Message) -ForegroundColor 'Red'
    }
}

function New-ZoomHeaders {
    param (
        [Parameter(Mandatory)]
        [securestring] $Token
    )

    Write-Verbose -Message '[INFO] Generating headers'

    if ($PSVersionTable.PSVersion.Major -ge 7) {

        $tokenStr = ConvertFrom-SecureString -SecureString $Token -AsPlainText
    }
    else {

        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
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

        [securestring] $Token = $Script:ZoomToken,

        $Body
    )

    $currentProtocol = [Net.ServicePointManager]::SecurityProtocol

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if ($null -eq $Token) {

        Write-Host -Object '[WARN] No token found, please run New-ZoomOAuthToken to continue' -ForegroundColor 'Yellow'
    }
    else {

        $headers = (New-ZoomHeaders -Token $Token)
    }

    try {

        if ($Body) {

            $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Body $Body -Method $Method
        }
        else {

            $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method
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

        #Rate limiting logic
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


#endregion

#region User Functions


function Get-UserSummary {

    $uri = 'https://api.zoom.us/v2/users/summary'

    $response = Invoke-ZoomRestMethod -Uri $uri -Method Get

    if ($initialResponse.ErrorCode) {

        $response
    }
    else {

        $response
    }
}

function Get-User {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress', 'Email', 'mail')]
        [string[]] $UserID
    )

    begin {

        $returnObject = @()
    }

    process {

        foreach ($user in $UserID) {

            $uri = 'https://api.zoom.us/v2/users/{0}' -f $user

            $initialResponse = Invoke-ZoomRestMethod -Uri $uri -Method Get

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

function Get-Users {

    [CmdletBinding()]
    param (
        [ValidateSet('active', 'inactive', 'pending')]
        [string] $Status = 'active'
    )

    begin {

        $uri = 'https://api.zoom.us/v2/users/'

        # Setting the Zoom API page size. Min 30 Max 300
        $pageSize = [int] 300

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('status', $Status)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Method Get

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

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Method Get

            $pageToken = $continuedResponse.next_page_token

            $returnObject += $continuedResponse.users
        }
    }

    end {

        $returnObject
    }
}

function Get-UserDelegates {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('EmailAddress')]
        [string[]] $UserID
    )

    begin {

        $returnObject = @()
    }

    process {

        foreach ($user in $UserID) {

            $uri = 'https://api.zoom.us/v2/users/{0}/assistants' -f $UserID

            $initialResponse = Invoke-ZoomRestMethod -Uri $uri -Method Get

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

    }

    process {

        foreach ($user in $UserID) {

            $uri = ('https://api.zoom.us/v2/users/{0}/token' -f $user)

            $response = Invoke-ZoomRestMethod -Uri $uri -Method Delete

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

    }

    process {

        foreach ($user in $UserID) {

            $uri = ('https://api.zoom.us/v2/users/{0}') -f $user

            $request = [System.UriBuilder] $uri
            $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
            $query.Add('action', 'delete')

            $request.Query = $query.ToString()

            $response = Invoke-ZoomRestMethod -Uri $request.Uri -Method Delete

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


function Get-CommonAreas {

    begin {

        $uri = 'https://api.zoom.us/v2/phone/common_areas'

        $pageSize = [int] 100

        $request = [System.UriBuilder] $uri
        $query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $query.Add('page_size', $pageSize)

        $request.Query = $query.ToString()

        $initialResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Method Get

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

            $continuedResponse = Invoke-ZoomRestMethod -Uri $request.Uri -Method Get

            $pageToken = $continuedResponse.next_page_token

            $returnObject += $continuedResponse.common_areas
        }
    }

    end {

        $returnObject
    }
}


#endregion
