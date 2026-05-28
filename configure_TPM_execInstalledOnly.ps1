param(
    [Parameter(Mandatory)]
    [string]$vCenter,

    [Parameter()]
    [string]$targetType,

    [Parameter()]
    [string]$clusterName,

    [Parameter()]
    [string]$hostName,

    [Parameter()]
    [switch]$remediate
)

if ($clusterName -and $hostName) {
    Write-Error "Cannot define both ESXi host name and vSphere Cluster name."
    Exit
}
if ($targetType -match "Host") {
    if(!$hostName) {
        Write-Error "Host name cannot be null when target type is set to Host"
        Exit
    }
} elseif ($targetType -match "Cluster") {
    if (!$clusterName) {
        Write-Error "Cluster name cannot be null when target type is set to Cluster"
        Exit
    }
} else {
    Write-Error "Invalid target type"
    Exit
}

$powerCLI = Get-Module -Name VMware.PowerCLI
if (!$powerCLI) {
    Import-Module VMware.PowerCLI -ErrorAction Stop | Out-Null
}
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

$credential = Get-Credential -Message "Enter credentials for $vCenter"
$vcenterCheck = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction SilentlyContinue

if ($vcenterCheck.IsConnected -eq $true) {
    Write-Host "Successfully connected to vCenter Server $vCenter"
} else {
    Write-Error "Error connecting to vCenter Server $vCenter. Please validate FQDN/IP and credentials."
    $vcenterBroke = $true
    Exit
}

try {
    if ($targetType -match "Host") {
        $vmhosts = Get-VMHost -Name $hostName
    } elseif ($targetType -match "Cluster") {
        $vmhosts = Get-Cluster -Name $clusterName | Get-VMHost | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    }

    foreach ($vmhost in $vmhosts) {
        $hostView = Get-View -Id $vmhost.Id -ErrorAction Stop

        if (!$hostview.Capability.TpmVersion) {
            $tpmVersion = "N/A"
        } else {
            $tpmVersion = $hostview.Capability.TpmVersion
        }
        $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
        
        $arguments = $null
        $arguments = $esxcli.system.settings.kernel.list.CreateArgs()
        $arguments.option = "execInstalledOnly"
                    
        $execInstalledOnly = $esxcli.system.settings.kernel.list.Invoke($arguments)

        Write-Host "[$($vmhost.Name)] TPM supported - $($hostView.Capability.TpmSupported)"
        Write-Host "[$($vmhost.Name)] TPM version supported - $tpmVersion"
        Write-Host "[$($vmhost.Name)] UEFI SecureBoot supported - $($hostView.Capability.UefiSecureBoot)"
        Write-Host "[$($vmhost.Name)] execInstalledOnly policy configured - $($execInstalledOnly.Configured)"
        Write-Host "[$($vmhost.Name)] execInstalledOnly policy runtime configuration - $($execInstalledOnly.Runtime)"

        if ($remediate -eq $true) {
            if ($execInstalledOnly.Configured -eq $true ) {
                Write-Host "[$($vmhost.Name)] execInstalledOnly policy already configured. Skipping..."
            } else {
                $arguments = $null
                $arguments = $esxcli.system.settings.kernel.set.CreateArgs()
                $arguments.setting = "execInstalledOnly"
                $arguments.value   = "TRUE"

                $esxcli.system.settings.kernel.set.Invoke($arguments) | Out-Null

                $esxcli = Get-EsxCli -VMhost $vmhost -V2 -ErrorAction Stop

                $arguments = $null
                $arguments = $esxcli.system.settings.kernel.list.CreateArgs()
                $arguments.setting = "execInstalledOnly"

                $checkExecInstalledOnly = $esxcli.system.settings.kernel.list.Invoke($arguments)

                if ($checkExecInstalledOnly.configured -eq $true) {
                    Write-Host "[$($vmhost.Name)] execInstalledOnly configured to TRUE. Reboot required for runtime enforcement."
                }
            }
            
            if (($tpmVersion -eq "N/A") -or ($tpmVersion -lt "2.0")) {
                Write-Host "[$($vmhost.Name)] TPM 2.0+ not supported. This is required for UEFI Secure Boot enforcement."
            } else {
                $arguments = $null
                $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
                $arguments.mode = "TPM"
                $arguments.requiresecureboot = $true
                $arguments.requireexecinstalledonly = $true

                $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null

                $esxcli = Get-EsxCli -VMhost $vmhost -V2 -ErrorAction Stop
                $checkSecureBoot = $esxcli.system.settings.encryption.get.Invoke() | Out-Null

                if ($checkSecureBoot.mode -eq "TPM") {
                    Write-Host "[$($vmhost.Name)] TPM 2.0 mode configured successfully"
                } else {
                    Write-Host "[$($vmhost.Name)] TPM 2.0 mode not configured successfully"
                }

                if ($checkSecureBoot.requireexecinstalledonly -eq $true) {
                    Write-Host "[$($vmhost.Name)] Require execInstalledOnly configured successfully"
                } else {
                    Write-Host "[$($vmhost.Name)] Require execInstalledOnly not configured successfully"
                } 

                if ($checkSecureBoot.requiresecureboot -eq $true) {
                    Write-Host "[$($vmhost.Name)] Require UEFI Secure Boot configured successfully"
                } else {
                    Write-Host "[$($vmhost.Name)] Require UEFI Secure Boot not configured successfully"
                }
            }
        }
        Write-Host ""
    }
} finally {
    if (!$vcenterBroke) {
        Disconnect-VIServer -Server * -Confirm:$false | Out-Null
    }
}