function Compare-SecureString {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [System.Security.SecureString]$secureString1,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [System.Security.SecureString]$secureString2
    )

    try {
        $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString1)
        $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString2)
        $length1 = [Runtime.InteropServices.Marshal]::ReadInt32($bstr1, -4)
        $length2 = [Runtime.InteropServices.Marshal]::ReadInt32($bstr2, -4)
        if ( $length1 -ne $length2 ) {
            return $false
        }
        for ( $i = 0; $i -lt $length1; ++$i ) {
            $b1 = [Runtime.InteropServices.Marshal]::ReadByte($bstr1, $i)
            $b2 = [Runtime.InteropServices.Marshal]::ReadByte($bstr2, $i)
            if ( $b1 -ne $b2 ) {
                return $false
            }
        }
        return $true
    }
    finally {
        if ( $bstr1 -ne [IntPtr]::Zero ) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
        }
        if ( $bstr2 -ne [IntPtr]::Zero ) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
        }
    }
}

Function Get-LockdownMode {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost
    
    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'LockdownMode' -NotePropertyValue ($vmhost.ExtensionData.Config.LockdownMode).ToString()

    $output
} Export-ModuleMember -Function Get-LockdownMode

Function Set-LockdownMode {
Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateSet("lockdownDisabled", "lockdownNormal", "lockdownStrict")] [String] $lockdownLevel
    )

    $currentLevel = (Get-LockdownMode -ESXiHost $ESXiHost).LockdownMode

    if ($currentLevel -eq $lockdownLevel) {
        Write-Output "[$ESXiHost] Lockdown Mode level already set to $lockdownLevel. Skipping."
    } else {
        $vmhost = Get-VMhost -Name $ESXiHost
        $lockdownMode = Get-View (Get-View -ViewType HostSystem -Filter @{"Name"="$VMhost"}).ConfigManager.HostAccessManager
        $lockdownMode.ChangeLockdownMode($lockdownLevel)

        $validateLevel = (Get-LockdownMode -ESXiHost $ESXiHost).LockdownMode
        if ($validateLevel -eq $lockdownLevel) {
            Write-Output "[$ESXiHost] Lockdown Mode level set to $lockdownLevel successfully."
        } else {
            Write-Output "[$ESXiHost] Lockdown Mode level was not set to $lockdownLevel successfully."
            Write-Output "[$ESXiHost] Current value: $validateLevel"
        }
    }
} Export-ModuleMember -Function Set-LockdownMode

Function New-EsxiUser {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $newUserName
    )

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

    #Check to see if the account already exists
    $esxAccounts = $esxcli.system.account.list.Invoke()
    $newAccount = $esxAccounts | Where-Object {$_.UserID -eq $newUserName}

    #If the account doesn't exist, create it
    if (!$newAccount) {
        do {
            $getCredentialA = Read-Host "Enter the password for $newUserName" -AsSecureString
            $getCredentialB = Read-Host "Confirm the password for $newUserName" -AsSecureString

            $compareCredentials = Compare-SecureString -SecureString1 $getCredentialA -SecureString2 $getCredentialB
            if ($compareCredentials -eq $false) {
                Write-Warning "Passwords do not match. Re-enter the password for $newUserName"
            }
        } until ($compareCredentials -eq $true)

        $newUserCreds = New-Object System.Management.Automation.PSCredential($newUserName, $getCredentialA)

        $arguments = $esxcli.system.account.add.CreateArgs()
        $arguments.id = $newUserName
        $arguments.password = "$($newUserCreds.GetNetworkCredential().Password)"
        $arguments.passwordconfirmation = "$($newUserCreds.GetNetworkCredential().Password)"
        $arguments.description = $newUserName
        $arguments.shellaccess = $true

        $esxcli.system.account.add.Invoke($arguments) | Out-Null

        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2
        $getAccounts = $esxcli.system.account.list.Invoke()
        $checkNewAccount = $getAccounts | Where-Object { $_.UserID -eq $newUserName }
        if (($checkNewAccount) -and ($checkNewAccount.shellaccess -eq $true)) {
            Write-Output "[$ESXiHost] $newUserName was created and configured successfully."
        } else {
            Write-Output "[$ESXiHost] $newUserName was not created and configured successfully."
        }
    } else {
        Write-Output "[$ESXiHost] $newUserName already exists. Skipping."
    }
}
Export-ModuleMember -Function New-EsxiUser

Function Get-EsxiUser {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

    #Check to see if the account already exists
    $esxAccounts = $esxcli.system.account.list.Invoke()
    $accountInfo = $esxAccounts | Where-Object {$_.UserID -eq $userName}

    if ($accountInfo) {
        $accountInfo | Format-List
    } else {
        Write-Output "[$ESXiHost] User $userName does not exist."
    }
} Export-ModuleMember -Function Get-EsxiUser

Function Set-EsxiUser {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName,
        [Parameter(Mandatory = $false)] [String] $shellAccess,
        [Parameter(Mandatory = $false)] [ValidateSet("Admin", "ReadOnly", "NoAccess")] [String] $role
    )

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

    #Check to see if the account exists
    $esxAccounts = $esxcli.system.account.list.Invoke()
    $accountInfo = $esxAccounts | Where-Object { $_.UserID -eq $userName }

    if ($accountInfo) {
        if ($shellAccess -match "true") {
            if ($accountInfo.shellaccess -eq $true) { 
                Write-Output "[$ESXiHost] User $userName already has shell access. Skipping."
            } elseif ($accountInfo.shellaccess -eq $false) {
                $arguments = $esxcli.system.account.set.CreateArgs()
                $arguments.id = $userName
                $arguments.shellaccess = $true

                $esxcli.system.account.set.Invoke($arguments) | Out-Null

                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

                $checkShellAccess = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $userName}
                if ($checkShellAccess.shellaccess -eq $true) {
                    "[$ESXiHost] ESXi shell access for user $userName was successfully enabled."
                } else {
                    "[$ESXiHost] ESXi shell access for user $userName was not successfully enabled."
                }
            }
        } elseif ($shellAccess -match "false") {
            if ($accountInfo.shellaccess -eq $false) {
                Write-Output "[$ESXiHost] User $userName does not have shell access. Skipping."
            } elseif ($accountInfo.shellaccess -eq $true) {
                $arguments = $esxcli.system.account.set.CreateArgs()
                $arguments.id = $userName
                $arguments.shellaccess = $false

                $esxcli.system.account.set.Invoke($arguments) | Out-Null

                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

                $checkShellAccess = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $userName}
                if ($checkShellAccess.shellaccess -eq $false) {
                    Write-Output "[$ESXiHost] ESXi shell access for user $userName was successfully disabled."
                } else {
                    Write-Output "[$ESXiHost] ESXi shell access for user $userName was not successfully disabled."
                }
            }
        } 

        if ($role) {
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

            $checkRole = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $userName}

            if ($checkRole.Role -eq $role) {
                Write-Output "[$ESXiHost] User $userName permissions already set to $role. Skipping."
            } else {
                $arguments = $esxcli.system.permission.set.CreateArgs()
                $arguments.id = $userName
                $arguments.role = $role

                $esxcli.system.permission.set.Invoke($arguments) | Out-Null

                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2
                $checkNewRole = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $userName}
                if ($checkNewRole.Role -eq $role) {
                    Write-Output "[$ESXiHost] $userName was successfully assigned the role $role."
                } else {
                    Write-Output "[$ESXiHost] $userName was not successfully assigned the role $role."
                }
            }
        }
    }
    else {
        Write-Output "[$ESXiHost] User $userName does not exist."
    }
} Export-ModuleMember -Function Set-EsxiUser

Function Get-TPM {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost
    $hostview = Get-View -Id $vmhost.Id -ErrorAction Stop
    $tpmVersionSupported = $hostview.Capability.TpmVersion

    if (!$tpmVersionSupported) {
        $tpmVersionSupported = "N/A"
    }

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2
    $tpmMode = ($esxcli.system.settings.encryption.get.Invoke()).Mode
    if ($tpmMode -eq "TPM") {
        $tpmEnabled = $true
    } else {
        $tpmEnabled = $false
    }
   
    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'TPMVersionSupported' -NotePropertyValue $tpmVersionSupported
    $output | Add-Member -NotePropertyName 'TPMEnabled' -NotePropertyValue $tpmEnabled

    $output

} Export-ModuleMember -Function Get-TPM

Function Enable-TPM {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $currentTpmState = (Get-TPM -ESXiHost $ESXiHost).tpmEnabled

    if ($currentTpmState -eq $true) {
        Write-Host "[$ESXiHost] TPM is already enabled. Skipping."
    } else {
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

        $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
        $arguments.mode = "TPM"

        $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

        $checkTpm = (Get-TPM -ESXiHost $ESXiHost).TPMEnabled
        if ($checkTpm -eq $true) {
            Write-Host "[$ESXiHost] TPM enabled successfully."
        } else {
            Write-Host "[$ESXiHost] TPM was not enabled successfully."
        }
    }
} Export-ModuleMember -Function Enable-TPM

Function Get-SecureBoot {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost
    $hostview = Get-View -Id $vmhost.Id -ErrorAction Stop

    $secureBootSupported = $hostview.Capability.UefiSecureBoot

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2
    $secureBootEnforced = ($esxcli.system.settings.encryption.get.Invoke()).requiresecureboot
    if ($secureBootEnforced -match "true") {
        $secureBootEnforced = $true
    } elseif ($secureBootEnforced -match "false") {
        $secureBootEnforced = $false
    }

    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'SecureBootSupported' -NotePropertyValue $secureBootSupported
    $output | Add-Member -NotePropertyName 'SecureBootEnforced' -NotePropertyValue $secureBootEnforced

    $output

} Export-ModuleMember -Function Get-SecureBoot

Function Set-SecureBoot {

} Export-ModuleMember -Function Set-SecureBoot

Function Get-ExecInstalledOnlyKernel {

} Export-ModuleMember -Function Get-ExecInstalledOnlyKernel

Function Set-ExecInstalledOnlyKernel {

} Export-ModuleMember -Function Set-ExecInstalledOnlyKernel

Function Get-ExecInstalledOnlyPolicy {

} Export-ModuleMember -Function Get-ExecInstalledOnlyPolicy

Function Set-ExecInstalledOnlyPolicy {

} Export-ModuleMember -Function Set-ExecInstalledOnlyPolicy