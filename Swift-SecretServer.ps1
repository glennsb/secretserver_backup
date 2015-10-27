#Requires -Version 3.0
<#
Copyright (c) 2015, Stuart Glenn, Oklahoma Medical Research Foundation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of atm nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

<#
.SYNOPSIS
Swift Backup with TempURL
.DESCRIPTION
Using TempURL for Openstack Swift to backup files
#>

$DEF_ATM_ENDPOINT = "http://SOMEHOST.COM"
$DEADMAN_CHECK_URI = ""

$api_key = ""
$api_secret = ""
$api_secret=ConvertTo-SecureString $api_secret
$api_secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($api_secret))

function Get-HMAC {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$message,

        [Parameter(Mandatory=$True)]
        [string]$secret
    )
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($secret)
    $signature = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
    return [Convert]::ToBase64String($signature)
}

function MD5-String($string) {
    $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider   
    return [System.BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($string))).Replace("-","")
}


Function Request-TempUrl {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Account,

        [Parameter(Mandatory=$True)]
        [string]$Container,

        [Parameter(Mandatory=$True)]
        [string]$Object,

        [Parameter(Mandatory=$True)]
        [ValidateSet('Get','Post','Put','Delete')]
        [string]$Method,

        [Parameter(Mandatory=$True)]
        [string]$ApiKey,

        [Parameter(Mandatory=$True)]
        [string]$ApiSecret,

        [string]$Atm = $DEF_ATM_ENDPOINT
    )
    $ENDPOINT = "/v1/urls"
    $uri = $Atm + $ENDPOINT

    $body = ConvertTo-Json @{
      account = $Account
      container = $Container
      object = $Object
      method = $Method.ToUpper()
    }

    $header = @{
      "content-type" = "application/json"
      "x-nonce" = [GUID]::NewGuid()
      "x-timestamp" = ((get-date).ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ssZ")
      "content-md5" = MD5-String $body
    }

    $msg = "POST`n"+$ENDPOINT+"`n"+$header["content-md5"]+"`n"+ $header["content-type"] +"`n"+$header["x-timestamp"]+"`n"+$header["x-nonce"]+"`n"+$api_key

    $signature = Get-HMAC -message $msg -secret $api_secret
    $header["Authorization"] = "ATM_Auth ${api_key}:${signature}"

    try {
        $r = Invoke-WebRequest -DisableKeepAlive -UseBasicParsing -Method POST -Uri $uri -Body $body -Header $header -ErrorAction Stop -TimeoutSec 10 -MaximumRedirection 0
    }
    catch {
        $r = $_.Exception.Response
        Write-Warning "Error getting TempURL: $($r.StatusCode.value__) - $($r.StatusDescription)"
        return @{
            Location = ""
            Status = $r.StatusCode
        }
    }
    return @{
        Location = $r.Headers.Location
        Status = $r.StatusCode
    }
}


Function Get-Files ([string]$Path,  [string]$Pattern=".*") {
    return Get-ChildItem ${Path}\* -Include *.zip, *.bak | where-object {$_.Name -match $Pattern}
}

Function Backup-File {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [string[]]$Path,

#        [Parameter(ParameterSetName = 'LiteralPath', Mandatory = $True, ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $True)]
#        [Alias('PSPath')][string[]]$LiteralPath),

        [Parameter(Mandatory=$True, ValueFromPipeline=$False)]
        [string]$Account,

        [Parameter(Mandatory=$True, ValueFromPipeline=$False)]
        [string]$Container
    )
    Begin {
        $num_done = 0
        $prefix = $((Get-Date).ToString("yyyyMMdd"))
    }
    Process {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $file = Get-Item $Path
        } else {
            $file = Get-Item -LiteralPath $LiteralPath
        }
     
        Write-Output "Backing up $($file.Name)"

        $uri = Request-TempUrl -Account $Account -Container $Container -Object $($prefix + "/" + $file.Name) -Method Put -ApiKey $api_key -ApiSecret $api_secret
        if (201 -eq $uri.Status) {
            $headers = @{
                "x-delete-at" = [int][double]::Parse($(Get-Date -date ([DateTime]::Now.AddDays(31)).ToUniversalTime()-uformat %s))
            }
            try {
              $r = Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $uri.Location -Method Put -InFile $file -ErrorAction Stop
            } catch {
              $r = $_.Exception.Response
              Write-Warning "Error putting to TempURL: $($r.StatusCode.value__) - $($r.StatusDescription)"
            }
            Write-Output $r.StatusCode
            if (201 -eq $r.StatusCode) {
                Remove-Item $file
                $num_done = $num_done + 1
            }
        } else {
            Write-output $uri.Status
        }
    }

    End {
        return $num_done
    }
}


$d = $(Get-Date -Format YYYYMMDD)

if ( $(Get-Files -Path "C:\backup\secretserver\" -Pattern "SecretServer${$d}.*" | Backup-File -Account "LDAP_glenns" -Container "test") -eq 2 ) {
   Write-Output "Clean backup"
   $r = Invoke-WebRequest -UseBasicParsing -Uri $DEADMAN_CHECK_URI -Method Get
} else {
    Write-Error "Failed on one or more files"
}
