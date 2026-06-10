param(
    [Parameter(Mandatory)]
    [string]$vCenter,

    [Parameter()]
    [string]$targetType,

    [Parameter()]
    [string]$clusterName,

    [Parameter()]
    [string]$hostName
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
    Import-Module VMware.PowerCLI -ErrorAction Stop
}
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

$vcenterCredential = Get-Credential -Message "Enter credentials for $vCenter"
$vcenterCheck = Connect-VIServer -Server $vCenter -Credential $vcenterCredential -ErrorAction SilentlyContinue

if ($vcenterCheck.IsConnected -eq $true) {
    Write-Output "Successfully connected to vCenter Server $vCenter"
} else {
    Write-Error "Error connecting to vCenter Server $vCenter. Please validate FQDN/IP and credentials."
    $vcenterBroke = $true
    Exit
}
$sshCredential = Get-Credential -Message "Enter ESXi host admin credentials for SSH"


$poshSSH = Get-Module -Name Posh-SSH
if (!$poshSSH) {
    $checkPoshSSH = Get-InstalledModule | Where-Object {$_.Name -eq "Posh-SSH"}
    if ($checkPoshSSH) {
        Write-Warning "Required module Posh-SSH is installed but not loaded. Loading now."
        Import-Module Posh-SSH -ErrorAction Stop
    } else {
        Write-Error "Required module Posh-SSH is not installed. Please install, then try again."
        Exit     
    }
}

try {
    if ($targetType -match "Host") {
        $vmhosts = Get-VMHost -Name $hostName
    } elseif ($targetType -match "Cluster") {
        $vmhosts = Get-Cluster -Name $clusterName | Get-VMHost | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    }

    foreach ($vmhost in $vmhosts) {
        #Check for Lockdown Mode
        $lockdownMode = $vmhost.ExtensionData.Config.AdminDisabled
        if ($lockdownMode -eq $true) {
            ($vmhost | Get-View).ExitLockdownMode()
            Write-Output "[$($vmhost.Name)] Lockdown Mode disabled."
        }    
        #Start SSH service on $vmhost
        $sshService = Get-VMHost $vmhost | Get-VMHostService | Where-Object {$_.Key -eq "TSM-SSH"}
        if ($sshService.Running -eq $false) {
            $sshService | Start-VMHostService -Confirm:$false | Out-Null
            Write-Output "[$($vmhost.Name)] SSH service is now running"
        } elseif ($sshService.Running -eq $true) {
            Write-Output "[$($vmhost.Name)] SSH service is already running. Skipping"
        }

        #Create SSH session to $vmhost
        $sshSession = New-SSHSession -ComputerName ($vmhost.NetworkInfo.VirtualNic | Where-Object {$_.ManagementTrafficEnabled -eq $true}).IP -Credential $sshCredential -Force -WarningAction SilentlyContinue
        if($sshSession) {
            Write-Output "[$($vmhost.Name)] SSH session has started"
        } else {
            Write-Error "[$($vmhost.Name)] SSH session has failed"
            Exit
        }
        
        #Enable vpxuser shell access
        Invoke-SSHCommand -SSHSession $sshSession -Command "esxcli system account set -i vpxuser -s true" | Out-Null
        Write-Output "[$($vmhost.Name)] Executing ESXCLI command to enable vpxuser shell access"
        
        #Close SSH session
        Remove-SSHSession -SSHSession $sshSession | Out-Null
        Write-Output "[$($vmhost.Name)] Closing SSH session"

        #Test vpxuser
        $esxcli = Get-EsxCli -VMhost $vmhost -V2
        $checkVpxUser = $esxcli.System.Account.List.Invoke() | Where-Object {$_.UserID -eq "vpxuser"}
        if ($checkVpxUser.Shellaccess -eq $true) {
            Write-Output "[$($vmhost.Name)] vpxuser shell access was successfully enabled"
        } else {
            Write-Error "[$($vmhost.Name)] vpxuser shell access was not successfully enabled"
        }

        #Stop SSH service on $vmhost
        $sshServiceStop = Get-VMHost $vmhost | Get-VMHostService | Where-Object {$_.Key -eq "TSM-SSH"}
        if ($sshServiceStop.Running -eq $true) {
            $sshServiceStop | Stop-VMHostService -Confirm:$false | Out-Null
            Write-Output "[$($vmhost.Name)] SSH service stopped"
        }

        if ($lockdownMode -eq $true) {
            ($vmhost | Get-View).EnterLockdownMode()
            Write-Output "[$($vmhost.Name)] Lockdown Mode enabled."
        }
        Write-Output ""
    }
} finally {
    if (!$vcenterBroke) {
        Disconnect-VIServer -Server * -Confirm:$false | Out-Null
    }
}