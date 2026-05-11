param(
    [Parameter(Mandatory)]
    [string]$vCenter,

    [Parameter(Mandatory)]
    [string]$clusterName,

    [Parameter()]
    [switch]$enableBreakGlassUser,

    [Parameter()]
    [string]$breakGlassUser,

    [Parameter()]
    [string]$breakGlassPassword,

    [Parameter()]
    [switch]$disableRoot,

    [Parameter()]
    [switch]$disableVpxuser
)

$powerCLI = Get-Module -Name VMware.PowerCLI
if (!$powerCLI) {
    Import-Module VMware.PowerCLI -ErrorAction Stop
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
    $vmhosts = Get-Cluster -Name $clusterName | Get-VMHost

    foreach ($vmhost in $vmhosts) {
        $esxcli = Get-EsxCli -VMhost $vmhost -V2

        if ($enableBreakGlassUser -eq $true) {
            #Check to see if the account already exists
            $esxAccounts = $esxcli.system.account.list.Invoke()
            $newAccount = $esxAccounts | Where-Object {$_.UserID -eq $breakGlassUser}

            #If the account doesn't exist, create it
            if (!$newAccount) {
                $arguments = $null
                $arguments = $esxcli.system.account.add.CreateArgs()
                $arguments.id = $breakGlassUser
                $arguments.password = $breakGlassPassword
                $arguments.passwordconfirmation = $breakGlassPassword
                $arguments.description = $breakGlassUser
                $arguments.shellaccess = $true

                $esxcli.system.account.add.Invoke($arguments) | Out-Null

                $getAccounts = $esxcli.system.account.list.Invoke()
                $checkNewAccount = $getAccounts | Where-Object {$_.UserID -eq $breakGlassUser}
                if (($checkNewAccount) -and ($checkNewAccount.shellaccess -eq $true)) {
                    Write-Host "[$($vmhost.Name)] $breakGlassUser was created and configured successfully."
                } else {
                    Write-Host "[$($vmhost.Name)] $breakGlassUser was not created and configured successfully. Exiting."
                    Exit
                }
            } else {
                Write-Host "[$($vmhost.Name)] Account $breakGlassUser already exists. Skipping account creation."

                #Check the configuration of the account
                $accountConfig = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $breakGlassUser}
                if ($accountConfig.shellaccess -ne $true) {
                    Write-Host "[$($vmhost.Name)] $breakGlassUser exists, but it does not have shell access. Resolving."
                    $arguments = $null
                    $arguments = $esxcli.system.account.set.CreateArgs()
                    $arguments.id = $breakGlassUser
                    $arguments.shellaccess = $true

                    $esxcli.system.account.set.Invoke($arguments) | Out-Null

                    $getAccounts = $esxcli.system.account.list.Invoke()
                    $checkNewAccount = $getAccounts | Where-Object {$_.UserID -eq $breakGlassUser}
                    if (($checkNewAccount) -and ($checkNewAccount.shellaccess -eq $true)) {
                        Write-Host "[$($vmhost.Name)] $breakGlassUser was configured successfully."
                    } else {
                        Write-Host "[$($vmhost.Name)] $breakGlassUser was not configured successfully. Exiting."
                        Exit
                    }
                }
            }
        }
        

        #Make $breakGlassUser an admin account
        $accountAdmin = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $breakGlassUser}
        if ($accountAdmin.Role -eq "Admin") {
            Write-Host "[$($vmhost.Name)] $breakGlassUser is already an admin. Skipping."
        } else {
            $arguments = $null
            $arguments = $esxcli.system.permission.set.CreateArgs()
            $arguments.id = $breakGlassUser
            $arguments.role = 'Admin'

            $esxcli.system.permission.set.Invoke($arguments) | Out-Null

            $checkAccountAdmin = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $breakGlassUser}
            if ($checkaccountAdmin.Role -eq "Admin") {
                Write-Host "[$($vmhost.Name)] $breakGlassUser was successfully configured with Admin permissions."
            } else {
                Write-Host "[$($vmhost.Name)] $breakGlassUser was not successfully configured with Admin permissions. Exiting."
                Exit
            }
        }
    
        #Check root account config
        if ($disableRoot -eq $true) {
            $rootAccountAdmin = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq "root"}    
            if ($rootAccountAdmin.Role -eq "NoAccess") {
                Write-Host "[$($vmhost.Name)] Root permissions are already set to NoAccess. Skipping."            
            } else {
                $arguments = $null
                $arguments = $esxcli.system.permission.set.CreateArgs()
                $arguments.id = 'root'
                $arguments.role = 'NoAccess'

                $esxcli.system.permission.set.Invoke($arguments) | Out-Null

                $checkRootAccountAdmin = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq "root"}
                if ($checkRootAccountAdmin.Role -eq "NoAccess") {
                    Write-Host "[$($vmhost.Name)] Root permissions have been successfully set to NoAccess."
                } else {
                    Write-Host "[$($vmhost.Name)] Root permissions were not successfully set to NoAccess. Exiting."
                    Exit
                }
            }
        }
        
        if ($disableVpxuser -eq $true) {
            $shellAccess = $null
            $shellAccess = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq "vpxuser"}

            #check to see if $account already has shell access disabled
            if ($shellaccess.shellaccess -eq $false) {
                "[$($vmhost.Name)] ESXi shell access for user vpxuser is already disabled. Skipping."
            } else {
                $arguments = $null
                $arguments = $esxcli.system.account.set.CreateArgs()
                $arguments.id = "vpxuser"
                $arguments.shellaccess = $false

                $esxcli.system.account.set.Invoke($arguments) | Out-Null
                
                $checkShellAccess = $null
                $checkShellAccess = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq "vpxuser"}
                if ($checkShellAccess.shellaccess -eq $false) {
                    "[$($vmhost.Name)] ESXi shell access for user vpxuser was successfully disabled."
                } else {
                    "[$($vmhost.Name)] ESXi shell access for user vpxuser was not successfully disabled."
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