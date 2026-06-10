param(
    [Parameter(Mandatory)]
    [string]$vCenter,

    [Parameter()]
    [string]$targetType,

    [Parameter()]
    [string]$clusterName,

    [Parameter()]
    [string]$hostName,

    [Parameter(Mandatory)]
    [string]$breakGlassUser
)

Start-Transcript -Path "undo_disable_root_vpxuser_$(get-date -f MM-dd-yyyy-HHmmss)" -Append

if ($clusterName -and $hostName) {
    Write-Error "Cannot define both ESXi host name and vSphere Cluster name."
    Exit
}
if ($targetType -match "Host") {
    if (!$hostName) {
        Write-Error "Host name cannot be null when target type is set to Host"
        Exit
    }
}
elseif ($targetType -match "Cluster") {
    if (!$clusterName) {
        Write-Error "Cluster name cannot be null when target type is set to Cluster"
        Exit
    }
}
else {
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
}
else {
    Write-Error "Error connecting to vCenter Server $vCenter. Please validate FQDN/IP and credentials."
    $vcenterBroke = $true
    Exit
}

Write-Host "The vpxuser account needs to be configured to have shell access before you start. Log in to the shell of your ESXi host and run 'esxcli system account set -i vpxuser -s true'."

try {
    if ($targetType -match "Host") {
        $vmhosts = Get-VMHost -Name $hostName
    }
    elseif ($targetType -match "Cluster") {
        $vmhosts = Get-Cluster -Name $clusterName | Get-VMHost | Where-Object { $_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance" }
    }

    foreach ($vmhost in $vmhosts) {
        #Check for Lockdown Mode
        $lockdownMode = $vmhost.ExtensionData.Config.AdminDisabled
        if ($lockdownMode -eq $true) {
            ($vmhost | Get-View).ExitLockdownMode()
            Write-Output "[$($vmhost.Name)] Lockdown Mode disabled."
        }

        #Check root account config
        $esxcli = Get-EsxCli -VMhost $vmhost -V2

        $rootAccountAdmin = $esxcli.system.permission.list.Invoke() | Where-Object { $_.Principal -eq "root" }
        if ($rootAccountAdmin.Role -ne "Admin") {
            $arguments = $null
            $arguments = $esxcli.system.permission.set.CreateArgs()
            $arguments.id = 'root'
            $arguments.role = 'Admin'

            $esxcli.system.permission.set.Invoke($arguments) | Out-Null


            $esxcli = Get-EsxCli -VMhost $vmhost -V2
            $checkRootAccountAdmin = $esxcli.system.permission.list.Invoke() | Where-Object { $_.Principal -eq "root" }
            if ($checkrootAccountAdmin.Role -eq "Admin") {
                Write-Host "[$($vmhost.Name)] Root permissions have been successfully set to Admin."
            } else {
                Write-Host "[$($vmhost.Name)] Root permissions were not successfully set to Admin. Exiting."
                Exit
            }
        } else {
            Write-Host "[$($vmhost.Name)] Root permissions are already set to Admin. Skipping."            
        }

        #Check to see if the account still exists
        $accountAdmin = $esxcli.system.account.list.Invoke() | Where-Object { $_.UserID -eq $breakGlassUser }
        
        #If the account exists, remove it
        if ($accountAdmin) {
            $arguments = $null
            $arguments = $esxcli.system.account.remove.CreateArgs()
            $arguments.id = $breakGlassUser

            $esxcli.system.account.remove.Invoke($arguments) | Out-Null

            $esxcli = Get-EsxCli -VMhost $vmhost -V2
            $checkesxAccounts = $esxcli.system.account.list.Invoke()
            $checknewAccount = $checkesxAccounts | Where-Object { $_.UserID -eq $breakGlassUser }
            if (!$checkNewAccount) {
                Write-Host "[$($vmhost.Name)] User $breakGlassUser has been successfully removed."
            } else {
                Write-Host "[$($vmhost.Name)] User $breakGlassUser was not successfully removed."
            }
        } else {
            Write-Host "[$($vmhost.Name)] User $breakGlassUser does not exist. Skipping."
        }

        if ($lockdownMode -eq $true) {
            ($vmhost | Get-View).EnterLockdownMode()
            Write-Output "[$($vmhost.Name)] Lockdown Mode enabled."
        }
        
        Write-Output ""
    }
}
finally {
    if (!$vcenterBroke) {
        Disconnect-VIServer -Server * -Confirm:$false | Out-Null
    }
}

Stop-Transcript