# Define the accepted parameters
Param(
    [switch] $preCheck,
    [ValidateSet('all', 'enforcement', 'ipv6')]
    [string] $skipPreCheck,
    [switch] $noInstall,
    [string] $logFile,
    [string] $proxy = "",
    [switch] $noProxy,
    [switch] $help,
    [switch] $version,
    [string] $sensorVersion,
    [switch] $ls,
    [string] $file,
    [string] $save,
    [switch] $new,
    [switch] $reinstall,
    [switch] $npcap,
    [switch] $forceUpgrade,
    [switch] $upgradeLocal,
    [string] $upgradeByUUID,
    [switch] $visibility
)

$scriptVersion="3.5.1.1-PATCH-3.5.1.2"
$minPowershellVersion=4
$installerLog="msi_installer.log"
$tmpLog = [System.IO.Path]::GetTempFileName()
$tmpBackupFolder = ""
$TetFolder = "C:\\Program Files\\Cisco Tetration"
# Sensor type is chosen by users on UI
$SensorType="enforcer"
# Powershell uses .NET Framework 4.5, which does not include TLS 1.2 as an available protocol.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
# We override the default validation, it will apply to all https requests for the remainder of this session lifetime.
# This callback function performs Issuer, authorityKeyIdentifer and validity period check for self-signed cert.  
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback=@"
    using System;
    using System.Text;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        private static byte[] GetIdentifier(X509Certificate2 cert, string oidName)
        {
            for (int i = 0; i < cert.Extensions.Count; i++)
            {
                if (string.Equals(cert.Extensions[i].Oid.Value, oidName))
                    return cert.Extensions[i].RawData;
            }
            return null;
        }
        private static bool ByteArrayCompare(byte[] b1, byte[] b2)
        {
            if (b1.Length == 0 || b2.Length == 0)
                return false;
            int j = b2.Length - 1;
            for (int i = b1.Length - 1; i > 0; i--)
            {
                if (b1[i] != b2[j])
                    return false;
                j--;
            }
            return true;
        }
        public static void Validate()
        {
            if (ServicePointManager.ServerCertificateValidationCallback == null)
            {
                ServicePointManager.ServerCertificateValidationCallback +=
                    delegate
                    (
                        Object obj,
                        X509Certificate certificate,
                        X509Chain chain,
                        SslPolicyErrors errors
                    )
                    {
                        string taSensorCApem = @"
-----BEGIN CERTIFICATE-----
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
yr+MwqxJbJISjLozmUIjl6QHz8Ru
-----END CERTIFICATE-----

";
                        byte[] taSensorCApemByte = Encoding.UTF8.GetBytes(taSensorCApem);
                        X509Certificate2 cert1 = new X509Certificate2(taSensorCApemByte);
                        X509Certificate2 cert2 = new X509Certificate2(certificate);
                        return (string.Equals(cert1.Subject, cert2.Issuer) && cert2.NotAfter >= DateTime.Now && cert2.NotBefore <= DateTime.Now && cert1.NotAfter >= DateTime.Now && cert1.NotBefore <= DateTime.Now && ByteArrayCompare(GetIdentifier(cert1, "2.5.29.14"), GetIdentifier(cert2, "2.5.29.35")));
                    };
            }
        }
    }
"@   
    Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Validate()

# Write text to log file if defined
function Log-Write-Host ($message) {
    if ($logFile -eq "") {
        Write-Host $message
    } else {
        Add-Content -Path $logFile -Value $message
    }
    Add-Content -Path $tmpLog -Value $message
}

# Write warning to log file if defined
function Log-Write-Warning ($message) {
    if ($logFile -eq "") {
        Write-Warning $message
    } else {
        Add-Content -Path $logFile -Value ("WARNING: " + $message)
    }
    Add-Content -Path $tmpLog -Value ("WARNING: " + $message)
}

# Create a temp folder
function NewTemporaryDirectory {
    for ($cnt = 0; $cnt -lt 3; $cnt = $cnt + 1) {
        $baseDir = [System.IO.Path]::GetTempPath()
        $dir = [System.IO.Path]::GetRandomFileName()
        $tempDir = Join-Path $basedir $dir
        if (New-Item -ItemType Directory -Path $tempDir -ErrorAction SilentlyContinue){
            Log-Write-Host ("Temp folder " + $tempDir + " created")
            return $tempDir
        }
    }
    return ""
}

# Move tmp log to sensor folder if exist
function Move-Tmplog {
    $endTime = Get-Date
    Log-Write-Host "#### Installer script run ends @ $endTime"
    if (Test-Path $tmpLog) {
        # Check if sensor log folder exists
        if (Test-Path ($TetFolder + "\\logs") -PathType Container) {
            Get-Content $tmpLog | Add-Content ($TetFolder + "\\logs\\tet-installer.log")
        }
        Remove-Item $tmpLog
    }
}

# Check if the user has Administrator rights
function Test-Administrator {
    $user=[Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Calculates the HMAC SHA 256 for a given message and secret,
# then encode to Base64 string.
function Calculate-Hmac ($message, $secret) {
    $hmacsha=New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.key=[Text.Encoding]::ASCII.GetBytes($secret)
    $signature=$hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($message))
    $signature=[Convert]::ToBase64String($signature)

    return $signature
}

# Extracts the platform string from the system.
function Extract-OsPlatform {
    # Get platform and does proper formatting
    $os_platform=Get-WmiObject Win32_OperatingSystem | Select-Object Caption
    $platform=$os_platform.Caption.Replace(" KN", "").Replace(" K", "").Replace(" N","")
    $platform=$platform.Replace(" ", "")
    $platform=$platform.Replace("Microsoftr", "")
    $platform=$platform.Replace("Microsoft", "")
    $platform=$platform.Replace("WindowsServerr", "Server")
    $platform=$platform.Replace("WindowsServer", "Server")
    $platform=$platform.Replace("Evaluation", "")
    $platform=$platform.Replace("Professional", "Pro")
    $platform="MS" + $platform

# Remove special characters from platform string
    $platform = $platform -replace '[^a-zA-Z0-9.]', ''

    return $platform
}

# Validates that the file has been signed properly, and the cert issuer is
# trusted by us. Currently we only trust "Symantec" or "Cisco".
function Check-ValidSignature ($checkValid, $filename) {
    # Currently accept only Cisco (self-signed) or Symantec (prod).
    $validIssuers=@("Cisco", "Symantec")
    $validIssuersRegex=[string]::Join('|', $validIssuers)
    # Get digital signature of the file and validate.
    $sig=Get-AuthenticodeSignature -FilePath "$filename"
    # Fail if this file is not signed.
    if ($sig.SignerCertificate -eq $null) {
        return $false
    }
    # Failed if the status is "Invalid".
    if ($checkValid -And $sig.Status -ne "Valid") {
        return $false
    }
    # Check the issuer of this certificate and make sure it matches.
    $issuer=$sig.SignerCertificate.Issuer.split(',') | ConvertFrom-StringData
    if ($issuer.CN -match $validIssuersRegex) {
        return $true
    }
    return $false
}

# Print version
function Print-Version {
    Write-Host ("Installation script for Cisco Tetration Agent (Version: " + $scriptVersion + ").")
    Write-Host ("Copyright (c) 2018-2021 Cisco Systems, Inc. All Rights Reserved.")
}

# Print usage
function Print-Usage {
    Write-Host ("Usage: " + $MyInvocation.MyCommand.Name + " [-preCheck] [-skipPreCheck <Option>] [-noInstall] [-logFile <FileName>] [-proxy <ProxyString>] [-noProxy] [-help] [-version] [-sensorVersion <VersionInfo>] [-ls] [-file <FileName>] [-save <FileName>] [-new] [-reinstall] [-npcap] [-forceUpgrade] [-upgradeLocal] [-upgradeByUUID <FileName>] [-visibility]")
    Write-Host ("  -preCheck: run pre-check only")
    Write-Host ("  -skipPreCheck <Option>: skip pre-installation check by given option; Valid options include 'all', 'ipv6' and 'enforcement'; e.g.: '-skipPreCheck all' will skip all pre-installation checks; All pre-checks will be performed by default")
    Write-Host ("  -noInstall: will not download and install sensor package onto the system")
    Write-Host ("  -logFile <FileName>: write the log to the file specified by <FileName>")
    Write-Host ("  -proxy <ProxyString>: set the value of HTTPS_PROXY, the string should be formatted as http://<proxy>:<port>")
    Write-Host ("  -noProxy: bypass system wide proxy; this flag will be ignored if -proxy flag was provided")
    Write-Host ("  -help: print this usage")
    Write-Host ("  -version: print current script's version")
    Write-Host ("  -sensorVersion <VersionInfo>: select sensor's version; e.g.: '-sensorVersion 3.4.1.0.win64'; will download the latest version by default if this flag was not provided")
    Write-Host ("  -ls: list all available sensor versions for your system (will not list pre-3.1 packages); will not download any package")
    Write-Host ("  -file <FileName>: provide local zip file to install sensor instead of downloading it from cluster")
    Write-Host ("  -save <FileName>: downloaded and save zip file as <FileName>")
    Write-Host ("  -new: remove any previous installed sensor; previous sensor identity has to be removed from cluster in order for the new registration to succeed")
    Write-Host ("  -reinstall: reinstall sensor and retain the same identity with cluster; this flag has higher priority than -new")
    Write-Host ("  -npcap: overwrite existing npcap")
    Write-Host ("  -forceUpgrade: force sensor upgrade to version given by -sensorVersion flag; e.g.: '-sensorVersion 3.4.1.0.win64 -forceUpgrade'; apply the latest version by default if -sensorVersion flag was not provided")
    Write-Host ("  -upgradeLocal: trigger local sensor upgrade to version given by -sensorVersion flag; e.g.: '-sensorVersion 3.4.1.0.win64 -upgradeLocal'; apply the latest version by default if -sensorVersion flag was not provided")
    Write-Host ("  -upgradeByUUID <FileName>: trigger sensor whose uuid is listed in <FileName> upgrade to version given by -sensorVersion flag; e.g.: '-sensorVersion 3.4.1.0.win64 -upgradeByUUID ""C:\\Program Files\\Cisco Tetration\\sensor_id""'; apply the latest version by default if -sensorVersion flag was not provided")
    Write-Host ("  -visibility: install deep visibility agent only; -reinstall would overwrite this flag if previous installed agent type was enforcer")
}


# Validate Firewall profile settings
function Validate_fw_profile_settings($profileregkey, $fwprofile, $curProfile, $profileName) {
    $addDescr=""
    if (-not $curProfile) {
        $addDescr= " when profile is active"
    }
    $mayFail = $false
    $RegKeys=(Get-ItemProperty -Path $profileregkey -ErrorAction SilentlyContinue)
    if (($RegKeys -ne $null) -and ($RegKeys.Length -ne 0)) {
        # Firewall must not be disabled
        if (($RegKeys.EnableFirewall -ne $null) -and ($RegKeys.EnableFirewall -eq 0)) {
            $warnMesg="GPO Firewall for "+$fwprofile + " is off, WAF mode enforcement may fail" +  $addDescr
            Log-Write-Warning $warnMesg
            $mayFail = $true
        } elseif ($RegKeys.EnableFirewall -eq $null) {
            $localSetting=Get-NetFirewallProfile -Name $profileName|Select-Object Enabled
            if ($localSetting.Enabled -eq 'False') {
                $warnMesg="GPO Firewall for "+$fwprofile + " is off, WAF mode enforcement may fail" +  $addDescr
                Log-Write-Warning $warnMesg
                $mayFail = $true
            } 
        }
        # DefaultInboundAction must not be defined
        if ($RegKeys.DefaultInboundAction -ne $null) {
            $warnMesg="DefaultInboundAction for  "+$fwprofile + " is not null, WAF mode enforcement may fail" + $addDescr
            Log-Write-Warning $warnMesg
            $mayFail = $true
        }
        # DefaultOutboundAction must not be defined
        if ($RegKeys.DefaultOutboundAction -ne $null) {
            $warnMesg="DefaultOutboundAction for " + $fwprofile +" is not null, WAF mode enforcement may fail" + $addDescr
            Log-Write-Warning $warnMesg
            $mayFail = $true
        }
        return $mayFail
    }
    # This is non-GPO mode or profile is "not configured" in GPO mode
    $localSetting=Get-NetFirewallProfile -Name $profileName|Select-Object Enabled
    if ($localSetting.Enabled -eq 'False') {
        $warnMesg="Firewall for "+$fwprofile + " is off, WAF mode enforcement may fail" +  $addDescr
        Log-Write-Warning $warnMesg
        $mayFail = $true
    } 
    return $mayFail
}

# Run pre-installation checks
function Pre-Check {
    if ($skipPreCheck -eq "all") {
        Log-Write-Host "Skip all pre-checks"
        return $true
    }
    # Assert that the path that it must contains "c:\windows\system32"
    Log-Write-Host "Checking system path contains c:\windows\system32..."
    if (-Not ($Env:Path).ToLower().Contains("c:\windows\system32")) {
        Log-Write-Warning "c:\windows\system32, agent installation and registration may fail"
        return $false
    }
    Log-Write-Host "Passed"

    # Reject installation on platforms prior to win2008r2
    Log-Write-Host "Checking for platform version..."
    # win7 has the same osversion as win2008r2
    $UnsupportedPlatforms = "MSWindows7Enterprise", "MSWindows7HomePremium", "MSWindows7Pro"  
    $Platform=Extract-OsPlatform
    if (($UnsupportedPlatforms.Contains($Platform)) -or ([Environment]::OSVersion.Version -lt (new-object 'Version' 6,1))) {
        Log-Write-Warning ("Platform " + $Platform + " is not supported")
        return $false
    }
    Log-Write-Host "Passed"

    $fwConfigMayFail = $false
    if (($SensorType -eq "enforcer") -and ($skipPreCheck -ne "enforcement")) {
        Log-Write-Host "Checking for enforcement readiness..."
        # Check if netsh exists
        Log-Write-Host "Checking existence for netsh..."
        if ($netshExists = (Get-Command -Name netsh)) {
            Log-Write-Host "Passed"
        } else {
            Log-Write-Warning "netsh not found"
            return $false
        }
        # Check whether GPO environment
        $FwPath="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
            
        $fwProfiles = @{'Domain*'='DomainProfile';'Public*'='PublicProfile';'Private*'='PrivateProfile'}
        # Check active network profile setting
        $curProfileList = netsh advfirewall show currentprofile

        Log-Write-Host "Checking Winodws Firewall State for WAF mode..."
        foreach($k in $fwProfiles.keys) {
            $isCurProfile=$curProfileList -like $k
            if ($isCurProfile) {
                $mesg="Checking settings for active Profile " + $fwProfiles[$k] + "..."
            } else {
                $mesg="Checking settings for " + $fwProfiles[$k] + "..."
            }
            Log-Write-Host $mesg
            $ProfileRegKey= join-path $FwPath -ChildPath $fwProfiles[$k]
            if (Validate_fw_profile_settings $ProfileRegKey $fwProfiles[$k] $isCurProfile $k) {
                $fwConfigMayFail = $true
            }
        }
        if ($skipPreCheck -ne "ipv6") {
            Log-Write-Host "Checking for IPv6 support..."
            if (-Not $([System.Net.Sockets.Socket]::OSSupportsIPv6)) {
                Log-Write-Host "IPv6 is not supported."
                return $false
            }
        }
    }

    if ($fwConfigMayFail) {
        Log-Write-Host "Pre-check all passed with warnings."
    } else {
        Log-Write-Host "Pre-check all passed."
    }
    return $true
}

# Unzip the file, the method depends on powershell version 4.0 or 5.0
function Unzip-Archive ($zipFile, $expandedFolder) {
    if ($PSVersionTable.PSVersion.Major -eq $minPowershellVersion) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $expandedFolder)
    } else {
        Expand-Archive -Path $zipFile -DestinationPath $expandedFolder -Force
    }
}

# Get the absolute path for 'file' and 'save'
function Full-Name ($fileName) {
    return ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($fileName))
}

function List-Available-Version {
    # Check whether this is a production sensor
    $InternalCluster=$false
    $IsProdSensor=($InternalCluster -ne $true)

    # Set platform and architect for list-available-version query
    $Platform=Extract-OsPlatform
    $Arch="x86_64"

    # set package type info
    $PkgType="sensor_w_cfg"

    $Method="GET"
    $Uri="/openapi/v1/sw_assets/download?pkg_type=$PkgType`&platform=$Platform`&arch=$Arch`&sensor_version=$sensorVersion`&list_version=$ls"
    $ChkSum=""
    $ContentType=""
    $Ts=Get-Date -UFormat "%Y-%m-%dT%H:%M:%S+0000"

    $ApiServer="https://64.100.1.197"
    $ApiKey="38395083092640938193976694ac6833"
    $ApiSecret="b4cdae3c0037eb4c5ddac8ccac56ae5a8e866c82"
    $Url=$ApiServer + $Uri

    # Calculate the signature based on the params
    # <httpMethod>\n<requestURI>\n<chksumOfBody>\n<ContentType>\n<TimestampHeader>
    $Msg="$Method`n$Uri`n$ChkSum`n$ContentType`n$Ts`n"
    $Signature=(Calculate-Hmac -message $Msg -secret $ApiSecret)
    $success = $true
    # Invoke web request to list avaible sensor versions
    try {
        $webclient = New-Object System.Net.WebClient
        $webclient.Headers.Add("Timestamp",$Ts)
        $webclient.Headers.Add("Id",$ApiKey)
        $webclient.Headers.Add("Authorization",$Signature)
        if ($proxy.Length -ne 0) {
            $webproxy = New-Object System.Net.WebProxy($proxy,$true)
            $webclient.Proxy = $webproxy
        } elseif ($noProxy) {
            $webclient.Proxy = $null
        }
        $resp = $webclient.DownloadString($Url)
        Log-Write-Host "available versions:"
        Log-Write-Host $resp
    }
    catch {
        # Check the return code
        Log-Write-Warning "Error found while connecting to the server"
        # network issue
        if (!($resp)) {
            Log-Write-Warning ($_.Exception.Message)
            Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
        } else {
            Log-Write-Warning ("StatusCode:" + $_.Exception.Response.StatusCode.value__)
            Log-Write-Warning ("StatusDescription:" + $_.Exception.Response.StatusDescription)
            Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
        }
        $success = $false
    }
    return $success
}


# Run certifcate checks for MSI installer and NPCAP 
function VerifyCert ($npcap) {
    Log-Write-Host "Checking MSI certificate...."

    $certStore  = "Cert:\LocalMachine\Root"
    $msiRootCert = 'VeriSign Universal Root Certification Authority'
    # check for MSI validation certificate
    $certDetails = Get-ChildItem -Path $certStore | Where-Object  {$_.Subject -like "*$msiRootCert*"} 
    if ( $certDetails -eq $null )
    {
        Log-Write-Warning ($msiRootCert  + " does not exist in cert store " + $certStore)
        Log-Write-Warning "Windows Sensor Upgrade will fail if auto root certificate update is disabled."
    }

    # check npcap installed
    $npcapPath = (Get-ItemProperty $npcapReg -ErrorAction SilentlyContinue).'(default)'
    if (($npcapPath -ne $null) -and ($npcapPath.Length -ne 0)) {
       write-host "npcap already installed, do not check NPCAP certificate"
       if ($npcap -eq $false) { 
           Log-Write-Host "npcap already installed, do not check NPCAP certificate"
           return
       }
    }

    Log-Write-Host "Checking NPCAP certificate...."
 
    $rootCerts = @()

    ## check for OS
    $prodName=(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
    if ($prodName -imatch " 2008 R2 ") 
    {
        $os = "2008 R2"
        $rootCerts = $rootCerts + 'DigiCert High Assurance EV Root CA'
        $rootCerts = $rootCerts + 'DigiCert Assured ID Root CA'
    } Elseif (($prodName -imatch " 2016 ")  -or ($prodName -imatch " 2019 ")  -or ($prodName -imatch " 10 "))
    {
        $os = "windows 10 based OS"
        $rootCerts = $rootCerts + 'Microsoft Root Certificate Authority 2010'
    } else {
        $os = "other"
        $rootCerts = $rootCerts + 'COMODO RSA Certification Authority'
        $rootCerts = $rootCerts + 'DigiCert Assured ID Root CA'
    }

    foreach($certName in $rootCerts)
    {
        $certDetails = Get-ChildItem -Path $certStore | Where-Object  {$_.Subject -like "*$certName*"} 

        if ( $certDetails -eq $null )
        {
            Log-Write-Warning ($certName  + " does not exist in Trusted Root store " )
            Log-Write-Warning "NPCAP installation may fail if auto root certificate update is disabled."
        }
    }
    Log-Write-Host "VerifyCert Done..."
}

function Install-Package {
    if (!$save) {
        $isAdmin = Test-Administrator
        if (-not $isAdmin) {
            Log-Write-Warning "This script needs Administrator rights to run with defined options, try again"
            return $false
        }
    }

    # Check if Cisco binaries already exist
    $TetFolder = "C:\\Program Files\\Cisco Tetration"

    if ($new -or $reinstall) {
        if ($reinstall) {
            if ((Test-Path ($TetFolder + "\\cert\\client.cert")) -and (Test-Path ($TetFolder + "\\cert\\client.key"))) {
                $oldClientCert = Get-Content ($TetFolder + "\\cert\\client.cert") -Raw
                $oldClientKey = Get-Content ($TetFolder + "\\cert\\client.key") -Raw
                if (Test-Path -Path (Join-Path $TetFolder "backup")) {
                    $tmpBackupFolder = (NewTemporaryDirectory)
                    if ($tmpBackupFolder -eq "") {
                        Log-Write-Warning ("Failed to create tmp backup folder")
                    } else {
                        Copy-Item -Path (Join-Path $TetFolder "backup\\*") -Destination ($tmpBackupFolder) -Recurse
                    }
                }
            } else {
                Log-Write-Warning ("Failed to locate client cert and key")
                return $false
            }
        }
        Log-Write-Host "Cleaning up before installation"
        if (Test-Path ($TetFolder + "\\UninstallAll.lnk")) {
            Start-Process -FilePath ($TetFolder + "\\UninstallAll.lnk") -Wait
            if (Test-Path ($TetFolder)) {
                Remove-Item $TetFolder -Recurse
            }
        } else {
            $app = Get-WmiObject -Class Win32_Product | Where-Object {
                $_.Name -match "Cisco Tetration Agent"
            }
            if ($app) {
                $uninstallStatus = $app.Uninstall()
                if (Test-Path ($TetFolder)) {
                    Remove-Item $TetFolder -Recurse
                }
            }
        }
    }

    if ((Test-Path ($TetFolder + "\\TetSen.exe")) -or (Test-Path ($TetFolder + "\\WindowsSensor.exe"))) {
        if (!$save) {
            Log-Write-Warning ("Tetration agent binaries exist, it seems sensor is already installed. Please clean up and retry")
            return $false
        }
    }

    if (!$save) {
        # Validate Npcap installation state if Npcap is installed
        $npcapInvalid = 0
        $npcapReg = 'hklm:\Software\Wow6432Node\Npcap'
        Log-Write-Host("Validate Npcap installation state if Npcap is installed")
        $npcapDll = "c:\\windows\\system32\\npcap\\packet.dll"
        if (Test-Path -path $npcapReg) {
            if (!(Test-Path $npcapDll)) {
                Log-Write-Host("Npcap packet.dll missing")
                $npcapInvalid = 1
            }
        }
        if ($npcapInvalid -eq 1) {
            $npcapPath = (Get-ItemProperty $npcapReg).'(default)'
            if (($npcapPath -ne $null) -and ($npcapPath.Length -ne 0)) {
                # Check uninstall.exe and npfinstall.exe exist
                $npcapUninstall = Join-Path $npcapPath "uninstall.exe"
                $npcapInstall = Join-Path $npcapPath "NPFInstall.exe"
                if ((Test-Path ($npcapUninstall)) -and (Test-Path ($npcapInstall))) {
                    Log-Write-Host("Try to uninstall Npcap")

                    Start-Process $npcapInstall -ArgumentList "-kill_proc" -Wait 
                    Start-Process $npcapUninstall -ArgumentList "/S" -Wait
                    if (Test-Path -path $npcapReg) {
                        Log-Write-Warning("Failed to uninstall npcap")
                    } else {
                        $npcapInvalid = 0
                        Log-Write-Host("Npcap uninstalled successfully !!!!")
                    }
                }
            }
        }

        if ($npcapInvalid -eq 1) {
            Log-Write-Warning("Npcap in invalid State : Please uninstall Npcap before installing Sensor")
            return $false
        }
    }

    # Validate Certificate
    VerifyCert($npcap)

    # Check whether this is a production sensor
    $InternalCluster=$false
    $IsProdSensor=($InternalCluster -ne $true)

    # Get activation key from cluster
    $ActivationKey="1e033dbe40030dad1d909fbab2ba5df3a4ff9e25"
    $InstallationID="jason_lunde_20210409153515"
    Log-Write-Host "Content of user.cfg file would be:"
    Log-Write-Host "ACTIVATION_KEY=$ActivationKey"
    Log-Write-Host "HTTPS_PROXY=$proxy"
    Log-Write-Host "INSTALLATION_ID=$InstallationID"

    # Set platform and architect for download query
    $Platform=Extract-OsPlatform
    Log-Write-Host ("Platform: " + $Platform)
    $Arch="x86_64"
    Log-Write-Host ("Architecture: " + $Arch)

    # Download the package with config files
    $PkgType="sensor_w_cfg"

    $Method="GET"
    $Uri="/openapi/v1/sw_assets/download?pkg_type=$PkgType`&platform=$Platform`&arch=$Arch`&sensor_version=$sensorVersion`&list_version=$ls"
    $ChkSum=""
    $ContentType=""
    $Ts=Get-Date -UFormat "%Y-%m-%dT%H:%M:%S+0000"
    Log-Write-Host ("Uri: " + $Uri)
    Log-Write-Host ("Timestamp: " + $Ts)
    $DownloadedFolder="tet-sensor-downloaded"
    $ZipFile=$DownloadedFolder + ".zip"
    $ApiServer="https://64.100.1.197"
    $ApiKey="38395083092640938193976694ac6833"
    $ApiSecret="b4cdae3c0037eb4c5ddac8ccac56ae5a8e866c82"
    $Url=$ApiServer + $Uri
    Log-Write-Host ("URL: " + $Url)
    Log-Write-Host ("Server: " + $ApiServer)
    Log-Write-Host ("Key: " + $ApiKey)
    Log-Write-Host ("Secret: " + $ApiSecret)
    Log-Write-Host ("Filename: " + $ZipFile)

    # Calculate the signature based on the params
    # <httpMethod>\n<requestURI>\n<chksumOfBody>\n<ContentType>\n<TimestampHeader>
    $Msg="$Method`n$Uri`n$ChkSum`n$ContentType`n$Ts`n"
    $Signature=(Calculate-Hmac -message $Msg -secret $ApiSecret)
    Log-Write-Host ("Signature: " + $Signature)

    # Create a map to store all <key,value> for the headers
    $MyHeaders=@{
        Timestamp=$Ts
        Id=$ApiKey
        Authorization=$Signature
    }
    Log-Write-Host ($MyHeaders | Out-String)

    # Cleanup old files
    if (Test-Path $ZipFile) {
        Remove-Item -Force $ZipFile
    }

    if (Test-Path $DownloadedFolder) {
        Remove-Item -Recurse -Force $DownloadedFolder
    }

    if (($file) -AND !(Test-Path ($file))) {
        Log-Write-Host ($file + " does not exist")
        return $false
    }
    if (!($file)) {
        $success = $false
        $count = 0
        do {
            # Invoke web request to download the file
            try {
                $webclient = New-Object System.Net.WebClient
                $webclient.Headers.Add("Timestamp",$Ts)
                $webclient.Headers.Add("Id",$ApiKey)
                $webclient.Headers.Add("Authorization",$Signature)
                if ($proxy.Length -ne 0) {
                    $webproxy = New-Object System.Net.WebProxy($proxy,$true)
                    $webclient.Proxy = $webproxy
                } elseif ($noProxy) {
                    $webclient.Proxy = $null
                }
                $resp = $webclient.DownloadFile($Url,(Full-Name $ZipFile))
            } catch {
                # Check the return code
                Log-Write-Warning "Error found while connecting to the server"
                # network issue
                if (!($resp)) {
                    Log-Write-Warning ($_.Exception.Message)
                    Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
                } else {
                    Log-Write-Warning ("StatusCode:" + $_.Exception.Response.StatusCode.value__)
                    Log-Write-Warning ("StatusDescription:" + $_.Exception.Response.StatusDescription)
                    Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
                }
                Log-Write-Warning ("Retry in 15 seconds...")
                Start-Sleep -Seconds 15
                $count++
                continue
            }

            Log-Write-Host "Sensor package has been downloaded, checking for content..."

            # Check if file is downloaded successfully
            if (!(Test-Path $ZipFile)) {
                Log-Write-Warning "$ZipFile absent, download failed"
                Log-Write-Warning ("Retry in 15 seconds...")
                Start-Sleep -Seconds 15
                $count++
                continue
            }
            $success = $true
        } Until ($success -or $count -eq 3)

        if (!$success) {
            Log-Write-Warning ("Failed to download package")
            return $false
        }
    } else {
        Copy-Item $file -Destination $ZipFile -Force
    }

    $CurrentFolder=(Get-Item -Path ".\\").FullName
    Log-Write-Host ("Expanding the archive " + $ZipFile)
    Unzip-Archive -zipFile ($CurrentFolder + "\\" + $ZipFile) -expandedFolder ($CurrentFolder + "\\" + $DownloadedFolder)
    $ExpandedFolder=$DownloadedFolder + "\\update"

    if (!(Test-Path $ExpandedFolder)) {
        Log-Write-Warning "$ZipFolder absent, uncompress failed"
        return $false
    }

    Push-Location -Path $ExpandedFolder

    # Overwrite the user.cfg file with new content
    $lineEnd = "`r`n"
    "ACTIVATION_KEY=$ActivationKey" + $lineEnd | Out-File -filepath "user.cfg" -Force -Encoding ASCII
    "HTTPS_PROXY=$proxy" + $lineEnd | Out-File -filepath "user.cfg" -Append -Force -Encoding ASCII
    "INSTALLATION_ID=$InstallationID" + $lineEnd | Out-File -filepath "user.cfg" -Append -Force -Encoding ASCII

    $InstallerFile="TetrationAgentInstaller.msi"
    $InstallerFileFullPath=$ExpandedFolder + "\\" + $InstallerFile
    if (!(Test-Path $InstallerFile)) {
        Log-Write-Warning "$InstallerFile absent, cannot install sensor"
        Pop-Location
        return $false
    }

    # Validate the signature for the installation msi file.
    $IsValidImage=(Check-ValidSignature -checkValid $IsProdSensor -filename $InstallerFile)
    if (-Not $IsValidImage) {
        Log-Write-Warning "$InstallerFile is not signed properly, aborting..."
        Pop-Location
        return $false
    }

    # Save zip file after signature check
    if ($save) {
        Pop-Location
        Copy-Item $ZipFile -Destination $save -Force
        if (Test-Path $DownloadedFolder) {
            Remove-Item -Recurse -Force $DownloadedFolder
        }
        if (Test-Path $ZipFile) {
            Remove-Item -Force $ZipFile
        }
        return $true
    } 

    Log-Write-Host "Installation file is ready, processing..."

    # Create sub-folders
    Log-Write-Host "Creating folder $TetFolder"
    New-Item -Path $TetFolder -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path ($TetFolder + "\\conf") -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path ($TetFolder + "\\cert") -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path ($TetFolder + "\\logs") -ItemType Directory -ErrorAction SilentlyContinue
    New-Item -Path ($TetFolder + "\\proto") -ItemType Directory -ErrorAction SilentlyContinue

    if ($reinstall) {
        # Save old client cert and key. Save fw setup in backup.
        $oldClientCert | Out-File ($TetFolder + "\\cert\\client.cert") -Force -Encoding ASCII
        $oldClientKey | Out-File ($TetFolder + "\\cert\\client.key") -Force -Encoding ASCII
        if ($tmpBackupFolder -ne "") {
            Copy-Item -Path (Join-Path $tmpBackupFolder "*") -Destination (New-Item -ItemType Directory -Force -Path (Join-Path $TetFolder "backup")) -Recurse
            Remove-Item ($tmpBackupFolder) -Recurse
        }
    }

    # Copy all the config files
    Log-Write-Host
    Log-Write-Host "Installing Tetration Agent..."
    Copy-Item "sensor_config" -Destination $TetFolder -Force
    Copy-Item "enforcer.cfg" -Destination ($TetFolder + "\\conf") -Force
    Copy-Item "site.cfg" -Destination $TetFolder -Force

    # Write the ca.cert file
    Copy-Item "ca.cert" -Destination ($TetFolder + "\\cert\\ca.cert") -Force

    # Write the sensor_type
    $SensorType | Out-File -filepath ($TetFolder + "\\sensor_type") -Encoding ASCII

    # Copy the user.cfg file if not already existed
    if (!(Test-Path ($TetFolder + "\\user.cfg"))) {
        Copy-Item "user.cfg" -Destination ($TetFolder + "\\user.cfg") -Force
    }

    Pop-Location

    # Check whether another MSI installation in progress
    # max wait 180 sec
    $maxcnt = 18
    $sleepInterval = 10
    for ($cnt = 0; $cnt -lt $maxcnt; $cnt = $cnt + 1) {
        $retval = 0
        $prevListMsi = Get-Process -Name msiexec -ErrorAction SilentlyContinue|Select Id,SessionId,Starttime|Where SessionId -ne 0
        if ($prevListMsi -eq $null) {
            break
        }
        else {
            Log-Write-Host("Process using MSI" + $prevListMsi.Id)
            $retval = 1
            Sleep($sleepInterval)
        }
    }
    if ($retval -eq 1) {
        Log-Write-Warning("Could not proceed with installation due to another blocking MSI")
        if (Test-Path $DownloadedFolder) {
            Remove-Item -Recurse -Force $DownloadedFolder
            Remove-Item -Force $ZipFile
        }
        return $false
    }

    # Check if user wants to overwrite existing npcap
    $overwrite = ""
    if ($npcap) {
        $overwrite = "overwriteNpcap=yes"
    }

    # Finally invoke the msi
    $MsiState = Start-Process -PassThru -FilePath "$env:systemroot\\system32\\msiexec.exe" -ArgumentList "/i $InstallerFileFullPath /quiet /norestart /l*v $installerLog AgentType=$SensorType $overwrite " -Wait -WorkingDirectory $pwd

    # Copy the log file to destination
    Copy-Item $installerLog -Destination ($TetFolder + "\\logs\\" + $installerLog) -Force

    # Cleanup new files
    if (Test-Path $DownloadedFolder) {
        Remove-Item -Recurse -Force $DownloadedFolder
        Remove-Item -Force $ZipFile
    }

    if ($MsiState.ExitCode -eq 0) {
        Log-Write-Host "Installation is done."
        return $true
    }

    Log-Write-Warning ("MSI installation failed, please check " + $installerLog + " for more info.")
    return $false
}

function ForceUpgrade {
    $zipFile = "conf_update.zip"
    $save = $TetFolder + "\\" + $zipFile
    $donotDownload = $TetFolder + "\\DONOT_DOWNLOAD"
    $versionFile = $TetFolder + "\\conf\\version"
    $checkConfUpdate = $TetFolder + "\\check_conf_update.cmd"
    $checkConfErrLog = $TetFolder + "\\logs\\upgrade_err.log"
    $isDownloadOK = (Install-Package)
    if (-not $isDownloadOK) {
        Log-Write-Warning "Failed to download package."
        return $false
    }
    if (!(Test-Path ($donotDownload))) {
        New-Item -Path $donotDownload -ItemType "file" -Force
    }
    $currentVersion = (Get-Content $versionFile -First 1)

    $tetSensorPresent = "no"
    if (Get-Service TetSensor -ErrorAction SilentlyContinue) {
      Log-Write-Host "Stopping TetSensor"
      Stop-Service TetSensor
      $tetSensorPresent = "yes"
    }
    if (Get-Service WindowsTetEngine -ErrorAction SilentlyContinue) {
      Log-Write-Host "Stopping WindowsTetEngine if present"
      Stop-Service WindowsTetEngine
    }

    Push-Location $TetFolder
    Log-Write-Host "Triggering force-upgrade..."
    $detailedErr = cmd /c $checkConfUpdate 2>&1
    $upgradeState = $LASTEXITCODE
    Pop-Location
    Remove-Item -Force $checkConfErrLog -ErrorAction Ignore
    Remove-Item -Force $donotDownload -ErrorAction Ignore
    if ($upgradeState -eq 0){
        Log-Write-Host "Force upgrade succeeded."
        $newVersion = (Get-Content $versionFile -First 1)
        Log-Write-Host "Local agent upgraded from $currentVersion to $newVersion."
        Log-Write-Host "Please wait for backend to synchronize."
        return $true
    }
    Log-Write-Host "Force upgrade failed."
    Log-Write-Host $detailedErr
    Remove-Item -Force $save -ErrorAction Ignore
    if ($tetSensorPresent -eq "yes") {
      Log-Write-Host "Start TetSensor after upgrade failure."
      Start-Service TetSensor
    } else {
      Log-Write-Host "Start WindowsTetEngine after upgrade failure."
      Start-Service WindowsTetEngine
    }
    return $false
}

function Upgrade {
    if (!(Test-Path ($upgradeByUUID))){
        Log-Write-Host ($upgradeByUUID + " does not exist")
        return $false
    }
    $uuid = (Get-Content $upgradeByUUID -First 1)
    $Method = "POST"
    $Uri = "/sensor_config/upgrade/" + $uuid + "?sensor_version=" + $sensorVersion
    $ChkSum = ""
    $ContentType = ""
    $Ts = Get-Date -UFormat "%Y-%m-%dT%H:%M:%S+0000"

    $ApiServer = "https://64.100.1.197"
    $ApiKey = "38395083092640938193976694ac6833"
    $ApiSecret = "b4cdae3c0037eb4c5ddac8ccac56ae5a8e866c82"
    $Url = $ApiServer + $Uri

    # Calculate the signature based on the params
    # <httpMethod>\n<requestURI>\n<chksumOfBody>\n<ContentType>\n<TimestampHeader>
    $Msg="$Method`n$Uri`n$ChkSum`n$ContentType`n$Ts`n"
    $Signature=(Calculate-Hmac -message $Msg -secret $ApiSecret)

    $success = $true
    # Invoke web request to update sensor versions
    try {
        $webclient = New-Object System.Net.WebClient
        $webclient.Headers.Add("Timestamp",$Ts)
        $webclient.Headers.Add("Id",$ApiKey)
        $webclient.Headers.Add("Authorization",$Signature)
        if ($proxy.Length -ne 0) {
            $webproxy = New-Object System.Net.WebProxy($proxy,$true)
            $webclient.Proxy = $webproxy
        } elseif ($noProxy) {
            $webclient.Proxy = $null
        }
        $resp = $webclient.UploadString($Url,"")
        Log-Write-Host "Upgrade triggered"
    } catch {
        # Check the return code
        Log-Write-Warning "Error found while connecting to the server"
        # network issue
        if (!($resp)) {
            Log-Write-Warning ($_.Exception.Message)
            Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
        } else {
            Log-Write-Warning ("StatusCode:" + $_.Exception.Response.StatusCode.value__)
            Log-Write-Warning ("StatusDescription:" + $_.Exception.Response.StatusDescription)
            Log-Write-Warning ("Error details:" + $_.ErrorDetails.Message)
        }
        $success = $false
    }
    return $success
}

if ($help -eq $true) {
    Print-Version
    Write-Host
    Print-Usage
    Exit
}

# Print time, script name, and parameters
$startTime = Get-Date
$scriptName = $MyInvocation.MyCommand.Name
$params = ''
$PSBoundParameters.Keys | % {
    $params += " -$_="
    $params += $PSBoundParameters[$_]
}
Log-Write-Host "#### Installer script run starts @ $startTime : $scriptName$params"

if ($visibility) {
    $SensorType = "sensor"
}

if ($preCheck -eq $true) {
    $isPrecheckOK = (Pre-Check)
    if (-not $isPrecheckOK) {
        Log-Write-Warning "Pre-check steps failed, please check errors before retry"
        Exit 1
    }
    Exit
}

if ($version -eq $true) {
    Print-Version
    Exit
}

# Make sure minimum Powershell version is met
if ($PSVersionTable.PSVersion.Major -lt $minPowershellVersion) {
    Log-Write-Warning ("This script requires minimum Powershell " + $minPowershellVersion + ", please upgrade and retry")
    Exit 1
}

if ($proxy -like "https:*") {
    Log-Write-Warning "Only http protocol is supported toward the proxy"
    Exit 1
}

## check admin privileges for options
if ($forceUpgrade -or $new -or $reinstall) {
    $isAdmin = Test-Administrator
    if (-not $isAdmin) {
        Log-Write-Warning "This script needs Administrator rights to run with defined options, try again"
        Exit 1
    }
}

# Overwrite SensorType for -reinstall
if ($reinstall) {
    if (Test-Path ($TetFolder + "\\sensor_type")) {
        $NewSensorType = Get-Content ($TetFolder + "\\sensor_type") -Raw
        if ($SensorType -ne $NewSensorType) {
            $SensorType = $NewSensorType
        }
    } else {
        Log-Write-Host("Failed to locate sensor_type for installed agent")
    }
}

if ($ls -eq $true) {
    $isListAvailableVersionOK = (List-Available-Version)
    if (-not $isListAvailableVersionOK) {
        Log-Write-Warning "Failed to list all available versions"
        Exit 1
    }
    Exit
}


if ($save) {
    $save = (Full-Name $save)
    $isInstallOK = (Install-Package)
    if (-not $isInstallOK) {
        Log-Write-Warning "Failed to save zip file, please check errors before retry"
        Exit 1
    }
    Exit
}

# Make sure pre-check returns true before proceeding
$isPrecheckOK = (Pre-Check)
if (-not $isPrecheckOK) {
    Log-Write-Warning "Pre-check steps failed, please check errors before retry"
    Exit 1
}

if ($forceUpgrade -or $upgradeByUUID -or $upgradeLocal) {
    $Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Tetration\'
    if (!(Test-Path ($Path))) {
        Log-Write-Host("Failed to find Tetration agent path, please make sure sensor is properly installed.")
        Exit 1
    }
    $TetFolder = (Get-ItemProperty -Path $Path).SensorPath
    if (!(Test-Path ($TetFolder + "\\TetSen.exe")) -and !(Test-Path ($TetFolder + "\\WindowsSensor.exe"))) {
        Log-Write-Warning ("Failed to find Tetration agent binaries, please make sure sensor is properly installed.")
        Exit 1
    }
    if ($sensorVersion) {
        Log-Write-Host("Upgrading to the provided version: " + $sensorVersion)
    } else {
        Log-Write-Host("Upgrading to the latest version")
    }
    # Download package and force upgrade
    if ($forceUpgrade) {
        $isUpgradeOK = (ForceUpgrade)
    # Trigger sensor upgrade in backend
    } else {
        if ($upgradeLocal) {
            $upgradeByUUID = "C:\\Program Files\\Cisco Tetration\\sensor_id"
        } 
        $upgradeByUUID = (Full-Name $upgradeByUUID)
        $isUpgradeOK = (Upgrade)
    }
    if (-not $isUpgradeOK) {
        Log-Write-Warning "Upgrade failed, please check errors before retry"
        Move-Tmplog
        Exit 1
    }
    Move-Tmplog
    Exit
}

if (-not $noInstall) {
    if ($file) {
        $file = (Full-Name $file) 
    }
    $isInstallOK = (Install-Package)
    if (-not $isInstallOK) {
        Log-Write-Warning "Installation failed, please check errors before retry"
        Move-Tmplog
        Exit 1
    }
}
Move-Tmplog
Log-Write-Host "All tasks are done."
