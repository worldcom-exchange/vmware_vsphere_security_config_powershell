function Compare-SecureString {
    #Adapted from code by @pspete
    #https://www.powershellgallery.com/packages/IdentityCommand/0.3.61

    <#
    .SYNOPSIS
    Comparison of two secure string objects and return either $true or $false

    .DESCRIPTION
    The Compare-SecureString compares two secure string objects and returns either $true or $false

    .EXAMPLE
    Compare-SecureString -secureString1 $secureString1 -secureString2 $secureString2

    .PARAMETER secureString1
    The first secure string object

    .PARAMETER secureString2
    The second secure string object
    #>

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
    <#
    .SYNOPSIS
    Get the current state of an ESXi host Lockdown Mode configuration.

    .DESCRIPTION
    The Get-LockdownMode cmdlet queries the vCenter Server and returns the LockdownMode value for a specified ESXi host.

    .EXAMPLE
    Get-LockdownMode -ESXiHost esx-01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host targeted for LockdownMode configuration
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    
    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'LockdownMode' -NotePropertyValue ($vmhost.ExtensionData.Config.LockdownMode).ToString()

    $output
} Export-ModuleMember -Function Get-LockdownMode

Function Set-LockdownMode {
    <#
    .SYNOPSIS
    Set Lockdown Mode configuration on a specified ESXi host

    .DESCRIPTION
    The Set-LockdownMode cmdlet sets the LockdownMode configuration for a specified ESXi host

    .EXAMPLE
    Set-LockdownMode -ESXiHost esx-01.sddc.lab -lockdownLevel lockdownDisabled

    .PARAMETER ESXiHost
    The ESXi host targeted for LockdownMode configuration

    .PARAMETER lockdownLevel
    The Lockdown Mode configuration to be applied to the specified ESXi host
    #>

Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateSet("lockdownDisabled", "lockdownNormal")] [String] $lockdownLevel
    )

    $currentLevel = (Get-LockdownMode -ESXiHost $ESXiHost).LockdownMode

    if ($currentLevel -eq $lockdownLevel) {
        Write-Error "[$ESXiHost] Lockdown Mode level is already set to $lockdownLevel."
    } else {
        $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
        $lockdownMode = Get-View (Get-View -ViewType HostSystem -Filter @{"Name"="$VMhost"}).ConfigManager.HostAccessManager
        $lockdownMode.ChangeLockdownMode($lockdownLevel)

        $validateLevel = (Get-LockdownMode -ESXiHost $ESXiHost).LockdownMode
        if ($validateLevel -eq $lockdownLevel) {
            Write-Output "[$ESXiHost] Lockdown Mode level set to $lockdownLevel successfully."
        } else {
            Write-Error "[$ESXiHost] Lockdown Mode level was not set to $lockdownLevel successfully."
        }
    }
} Export-ModuleMember -Function Set-LockdownMode

Function Get-LockdownModeExceptionUsers {
    <#
    .SYNOPSIS
    Get Lockdown Mode exception users on a specified ESXi host

    .DESCRIPTION
    The Get-LockdownModeExceptionUsers cmdlet gets the LockdownMode exception users for a specified ESXi host

    .EXAMPLE
    Get-LockdownModeExceptionUsers -ESXiHost esx-01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host targeted for LockdownMode configuration
    #>
    
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $getView = Get-View -Id $vmhost.ExtensionData.ConfigManager.HostAccessManager

    $currentLockdownUsers = $getView.QueryLockdownExceptions()
    $currentLockdownUsers

} Export-ModuleMember -Function Get-LockdownModeExceptionUsers

Function Add-LockdownModeExceptionUser {
    <#
    .SYNOPSIS
    Add a local user to the Lockdown Mode exception users list on a specified ESXi host

    .DESCRIPTION
    The Add-LockdownModeExceptionUser cmdlet adds a local user to the LockdownMode exception users list for a specified ESXi host

    .EXAMPLE
    Add-LockdownModeExceptionUser -ESXiHost esx-01.sddc.lab -userName vcfadmin

    .PARAMETER ESXiHost
    The ESXi host targeted for LockdownMode configuration

    .PARAMETER userName
    The user to be added to the LockdownMode exception users list
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $getView = Get-View -Id $vmhost.ExtensionData.ConfigManager.HostAccessManager

    $currentExceptionUsers = Get-LockdownModeExceptionUsers -ESXiHost $ESXiHost
    $expandedList = $currentExceptionUsers + $userName

    $getView.UpdateLockdownExceptions($expandedList)

    $checkExceptionUsers = Get-LockdownModeExceptionUsers -ESXiHost $ESXiHost
    if ($checkExceptionUsers -contains $userName) {
        Write-Output "[$ESXiHost] User $userName successfully added to the exception user list."
    } else {
        Write-Error "[$ESXiHost] User $userName was not successfully added to the exception user list."
    }
} Export-ModuleMember -Function Add-LockdownModeExceptionUser

Function Remove-LockdownModeExceptionUser {
    <#
    .SYNOPSIS
    Removes a local user from the Lockdown Mode exception users list on a specified ESXi host

    .DESCRIPTION
    The Remove-LockdownModeExceptionUser cmdlet removes a local user from the LockdownMode exception users list for a specified ESXi host

    .EXAMPLE
    Remove-LockdownModeExceptionUser -ESXiHost esx-01.sddc.lab -userName vcfadmin

    .PARAMETER ESXiHost
    The ESXi host targeted for LockdownMode configuration

    .PARAMETER userName
    The user to be removed from the LockdownMode exception users list
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $getView = Get-View -Id $vmhost.ExtensionData.ConfigManager.HostAccessManager

    $currentExceptionUsers = Get-LockdownModeExceptionUsers -ESXiHost $ESXiHost

    $newLockdownUsers = $currentExceptionUsers.Split(" ") -ne $userName

    $getView.UpdateLockdownExceptions($newLockdownUsers)

    $checkExceptionUsers = Get-LockdownModeExceptionUsers -ESXiHost $ESXiHost
    if ($checkExceptionUsers -notcontains $userName) {
        Write-Output "[$ESXiHost] User $userName successfully removed to the exception user list."
    } else {
        Write-Error "[$ESXiHost] User $userName was not successfully removed to the exception user list."
    }
} Export-ModuleMember -Function Remove-LockdownModeExceptionUser

Function New-EsxiUser {
    <#
    .SYNOPSIS
    Create a local user on a specified ESXi host

    .DESCRIPTION
    The New-ESXiUser cmdlet creates a local user on a specified ESXi host

    .EXAMPLE
    New-ESXiUser -ESXiHost esx-01.sddc.lab -userName vcfadmin

    .PARAMETER ESXiHost
    The ESXi host targeted for new user creation

    .PARAMETER userName
    The user to be created
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

    #Check to see if the account already exists
    $esxAccounts = $esxcli.system.account.list.Invoke()
    $newAccount = $esxAccounts | Where-Object {$_.UserID -eq $userName}

    #If the account doesn't exist, create it
    if (!$newAccount) {
        do {
            $getCredentialA = Read-Host "Enter the password for $userName" -AsSecureString
            $getCredentialB = Read-Host "Confirm the password for $userName" -AsSecureString

            $compareCredentials = Compare-SecureString -SecureString1 $getCredentialA -SecureString2 $getCredentialB
            if ($compareCredentials -eq $false) {
                Write-Warning "Passwords do not match. Re-enter the password for $userName"
            }
        } until ($compareCredentials -eq $true)

        $newUserCreds = New-Object System.Management.Automation.PSCredential($userName, $getCredentialA)

        $arguments = $esxcli.system.account.add.CreateArgs()
        $arguments.id = $userName
        $arguments.password = "$($newUserCreds.GetNetworkCredential().Password)"
        $arguments.passwordconfirmation = "$($newUserCreds.GetNetworkCredential().Password)"
        $arguments.description = $userName
        $arguments.shellaccess = $true

        $esxcli.system.account.add.Invoke($arguments) | Out-Null

        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
        $getAccounts = $esxcli.system.account.list.Invoke()
        $checkNewAccount = $getAccounts | Where-Object { $_.UserID -eq $userName }
        if (($checkNewAccount) -and ($checkNewAccount.shellaccess -eq $true)) {
            Write-Output "[$ESXiHost] $userName was created and configured successfully."
            $output = Get-EsxiUser -ESXiHost $ESXiHost -userName $userName
            $output
        } else {
            Write-Error "[$ESXiHost] $userName was not created and configured successfully."
        }
    } else {
        Write-Error "[$ESXiHost] $userName already exists. Skipping."
    }
}
Export-ModuleMember -Function New-EsxiUser

Function Get-EsxiUser {
    <#
    .SYNOPSIS
    Retrieves all users or a specified user on an ESXi host

    .DESCRIPTION
    The Get-ESXiUser cmdlet retrieves all users or a specified user on an ESXi host

    .EXAMPLE
    Get-ESXiUser -ESXiHost esx-01.sddc.lab -userName vcfadmin

    .PARAMETER ESXiHost
    The ESXi host queried for local users

    .PARAMETER userName
    The user to be returned (Optional)
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

    if (!$userName) {
        $outputs = @()
        $esxAccounts = $esxcli.system.account.list.Invoke()
        foreach ($esxAccount in $esxAccounts) {
            $role = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $esxAccount.UserID}
            
            $output = New-Object -TypeName PSCustomObject
            $output | Add-Member -NotePropertyName 'UserID' -NotePropertyValue $esxAccount.UserID
            $output | Add-Member -NotePropertyName 'ShellAccess' -NotePropertyValue $esxAccount.ShellAccess
            $output | Add-Member -NotePropertyName 'Role' -NotePropertyValue $role.Role
            $output | Add-Member -NotePropertyName 'Description' -NotePropertyValue $esxAccount.Description

            $outputs += $output
        }
        return $outputs
    } else {
        $role = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -match $userName}
        $esxAccount = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -match $userName}
        
        if (!$esxAccount) {
            Write-Output "[$ESXiHost] User $userName does not exist."
        } else {
            $output = New-Object -TypeName PSCustomObject
            $output | Add-Member -NotePropertyName 'UserID' -NotePropertyValue $esxAccount.UserID
            $output | Add-Member -NotePropertyName 'ShellAccess' -NotePropertyValue $esxAccount.ShellAccess
            $output | Add-Member -NotePropertyName 'Role' -NotePropertyValue $role.Role
            $output | Add-Member -NotePropertyName 'Description' -NotePropertyValue $esxAccount.Description

            $output
        }
    }
} Export-ModuleMember -Function Get-EsxiUser

Function Set-EsxiUser {
    <#
    .SYNOPSIS
    Sets one or more values for a specified user on an ESXi host

    .DESCRIPTION
    The Set-ESXiUser cmdlet sets one or more values for a specified user on an ESXi host

    .EXAMPLE
    Set-ESXiUser -ESXiHost esx-01.sddc.lab -userName vcfadmin -shellAccess True -role Admin

    .PARAMETER ESXiHost
    The ESXi targeted for local user configuration

    .PARAMETER userName
    The user to be configured

    .PARAMETER shellAccess
    Configuration of shell access for the targeted user

    .PARAMETER role
    The role to be assigned to the targeted user
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName,
        [Parameter(Mandatory = $false)] [String] $shellAccess,
        [Parameter(Mandatory = $false)] [ValidateSet("Admin", "ReadOnly", "NoAccess")] [String] $role
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

    #Check to see if the account exists
    $esxAccounts = $esxcli.system.account.list.Invoke()
    $accountInfo = $esxAccounts | Where-Object { $_.UserID -eq $userName }

    if ($accountInfo) {
        if ($shellAccess -match "true") {
            if ($accountInfo.shellaccess -eq $true) { 
                Write-Error "[$ESXiHost] User $userName already has shell access."
            } elseif ($accountInfo.shellaccess -eq $false) {
                $arguments = $esxcli.system.account.set.CreateArgs()
                $arguments.id = $userName
                $arguments.shellaccess = $true

                $esxcli.system.account.set.Invoke($arguments) | Out-Null

                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

                $checkShellAccess = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $userName}
                if ($checkShellAccess.shellaccess -eq $true) {
                    Write-Output "[$ESXiHost] ESXi shell access for user $userName was successfully enabled."
                } else {
                    Write-Error "[$ESXiHost] ESXi shell access for user $userName was not successfully enabled."
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

                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

                $checkShellAccess = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $userName}
                if ($checkShellAccess.shellaccess -eq $false) {
                    Write-Output "[$ESXiHost] ESXi shell access for user $userName was successfully disabled."
                } else {
                    Write-Error "[$ESXiHost] ESXi shell access for user $userName was not successfully disabled."
                }
            }
        } 

        if ($role) {
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

            $checkRole = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $userName}

            if ($checkRole.Role -eq $role) {
                Write-Output "[$ESXiHost] User $userName permissions already set to $role. Skipping."
            } else {
                $arguments = $esxcli.system.permission.set.CreateArgs()
                $arguments.id = $userName
                $arguments.role = $role

                $esxcli.system.permission.set.Invoke($arguments) | Out-Null

                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
                $checkNewRole = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $userName}
                if ($checkNewRole.Role -eq $role) {
                    Write-Output "[$ESXiHost] $userName was successfully assigned the role $role."
                } else {
                    Write-Error "[$ESXiHost] $userName was not successfully assigned the role $role."
                }
            }
        }
    }
    else {
        Write-Error "[$ESXiHost] User $userName does not exist."
    }
} Export-ModuleMember -Function Set-EsxiUser

Function Remove-EsxiUser {
    <#
    .SYNOPSIS
    Removes a specified user on an ESXi host

    .DESCRIPTION
    The Remove-ESXiUser cmdlet removes a specified user on an ESXi host

    .EXAMPLE
    Remove-ESXiUser -ESXiHost esx-01.sddc.lab -userName vcfadmin

    .PARAMETER ESXiHost
    The ESXi targeted for local user removal

    .PARAMETER userName
    The user to be removed
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    #Check to see if the account already exists
    $accountExists = Get-EsxiUser -ESXiHost $ESXiHost -userName $userName

    #If the account exists, remove it
    if ($accountExists.UserID -eq $userName) {
        $getConfirmation = Read-Host "Are you sure you want to remove the user $($userName)? (Y/N)"

        if ($getConfirmation -eq "Y") {
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
            $arguments = $esxcli.system.account.remove.CreateArgs()
            $arguments.id = $userName

            $arguments = $esxcli.system.account.remove.Invoke($arguments) | Out-Null

            $checkAccountRemoved = Get-ESXiUser -ESXiHost $ESXiHost -userName $userName
            if ($checkAccountRemoved -match "User $userName does not exist") {
                Write-Output "[$ESXiHost] User $userName was removed successfully."
            } else {
                Write-Error "[$ESXiHost] User $userName was not removed successfully."
            }
        } elseif ($getConfirmation -eq "F") {
            Write-Output "[$ESXiHost] User $userName was not removed."
        } else {
            Write-Error "[$ESXiHost] Invalid input. User $userName was not removed."
        }
    } else {
        Write-Error "[$ESXiHost] User $userName does not exist."
    }
}
Export-ModuleMember -Function Remove-EsxiUser

Function Reset-EsxiUserPassword {
    <#
    .SYNOPSIS
    Reset the password for a local user on a specified ESXi host

    .DESCRIPTION
    The Reset-EsxiUserPassword cmdlet resets the password for a local user on a specified ESXi host

    .EXAMPLE
    Reset-EsxiUserPassword -ESXiHost esx-01.sddc.lab -userName vcfadmin

    .PARAMETER ESXiHost
    The ESXi host targeted for new user creation

    .PARAMETER userName
    The user to have their password reset
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

    #Check to see if the account already exists
    $checkAccountExists = Get-EsxiUser -ESXiHost $vmhost.Name -userName $userName

    #If the account doesn't exist, create it
    if ($checkAccountExists.UserID -eq $userName) {
        do {
            $getCredentialA = Read-Host "Enter the new password for $userName" -AsSecureString
            $getCredentialB = Read-Host "Confirm the new password for $userName" -AsSecureString

            $compareCredentials = Compare-SecureString -SecureString1 $getCredentialA -SecureString2 $getCredentialB
            if ($compareCredentials -eq $false) {
                Write-Warning "Passwords do not match. Re-enter the new password for $userName"
            }
        } until ($compareCredentials -eq $true)

        $newUserCreds = New-Object System.Management.Automation.PSCredential($userName, $getCredentialA)

        $arguments = $esxcli.system.account.set.CreateArgs()
        $arguments.id = $userName
        $arguments.password = "$($newUserCreds.GetNetworkCredential().Password)"
        $arguments.passwordconfirmation = "$($newUserCreds.GetNetworkCredential().Password)"

        $invokePasswordReset = $esxcli.system.account.set.Invoke($arguments)

        if ($invokePasswordReset -eq $true) {
            Write-Output "[$ESXiHost] $userName password was successfully reset."
        } else {
            Write-Error "[$ESXiHost] $userName password was not reset successfully."
        }
    } else {
        Write-Error "[$ESXiHost] $userName does not exist. Skipping."
    }
}
Export-ModuleMember -Function Reset-EsxiUserPassword

Function Get-TPM {
    <#
    .SYNOPSIS
    Gets the TPM configuration for an ESXi host

    .DESCRIPTION
    The Get-TPM cmdlet gets the TPM configuration for an ESXi host

    .EXAMPLE
    Get-TPM -ESXiHost esx-01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host to be queried for its TPM configuration 
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $hostview = Get-View -Id $vmhost.Id -ErrorAction Stop
    $tpmVersionSupported = $hostview.Capability.TpmVersion

    if (!$tpmVersionSupported) {
        $tpmVersionSupported = "N/A"
    }

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
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
    <#
    .SYNOPSIS
    Enables TPM mode on an ESXi host

    .DESCRIPTION
    The Enable-TPM cmdlet enables TPM mode on an ESXi host

    .EXAMPLE
    Enable-TPM -ESXiHost esx-01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host to be configured for TPM mode
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $checkLockdownMode = Get-LockdownMode -ESXiHost $ESXiHost
    if ($checkLockdownMode.LockdownMode -eq "lockdownNormal" -or $checkLockdownMode.LockdownMode -eq "lockdownStrict") {
        Write-Output "[$ESXiHost]  Lockdown Mode is set to $($checkLockdownMode.LockdownMode). Please disable Lockdown Mode and try again."
        Break
    } elseif ($checkLockdownMode.LockdownMode -eq "lockdownDisabled") {
        $currentTpmState = (Get-TPM -ESXiHost $ESXiHost).tpmEnabled

        if ($currentTpmState -eq $true) {
            Write-Host "[$ESXiHost] TPM is already enabled. Skipping."
        } else {
            $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
            $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

            $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
            $arguments.mode = "TPM"

            $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

            $checkTpm = (Get-TPM -ESXiHost $ESXiHost).TPMEnabled
            if ($checkTpm -eq $true) {
                Write-Host "[$ESXiHost] TPM enabled successfully."
            } else {
                Write-Error "[$ESXiHost] TPM was not enabled successfully."
            }
        }
    }
} Export-ModuleMember -Function Enable-TPM

Function Get-SecureBoot {
    <#
    .SYNOPSIS
    Gets the SecureBoot configuration for an ESXi host

    .DESCRIPTION
    The Get-SecureBoot cmdlet gets the SecureBoot configuration for an ESXi host

    .EXAMPLE
    Get-SecureBoot -ESXiHost esx-01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host to be queried for its SecureBoot configuration 
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $hostview = Get-View -Id $vmhost.Id -ErrorAction Stop

    $secureBootSupported = $hostview.Capability.UefiSecureBoot

    $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop
    $secureBootEnforced = ($esxcli.system.settings.encryption.get.Invoke()).requiresecureboot

    $secureBootSupportedBool = [System.Convert]::ToBoolean($secureBootSupported)
    $secureBootEnforcedBool = [System.Convert]::ToBoolean($secureBootEnforced)

    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'SecureBootSupported' -NotePropertyValue $secureBootSupportedBool
    $output | Add-Member -NotePropertyName 'SecureBootEnforced' -NotePropertyValue $secureBootEnforcedBool

    $output

} Export-ModuleMember -Function Get-SecureBoot

Function Set-SecureBoot {
    <#
    .SYNOPSIS
    Sets the SecureBoot configuration (enabled/disabled) for an ESXi host

    .DESCRIPTION
    The Set-SecureBoot cmdlet sets the SecureBoot configuration (enabled/disabled) for an ESXi host

    .EXAMPLE
    Set-SecureBoot -ESXiHost esx-01.sddc.lab -Enforced True

    .PARAMETER ESXiHost
    The ESXi host to be queried for its TPM configuration 

    .PARAMETER Enforced
    Specifies whether the SecureBoot configuration should be enabled
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Enforced
    )

    $checkLockdownMode = Get-LockdownMode -ESXiHost $ESXiHost
    if ($checkLockdownMode.LockdownMode -eq "lockdownNormal" -or $checkLockdownMode.LockdownMode -eq "lockdownStrict") {
        Write-Error "[$ESXiHost]  Lockdown Mode is set to $($checkLockdownMode.LockdownMode). Please disable Lockdown Mode and try again."
    } elseif ($checkLockdownMode.LockdownMode -eq "lockdownDisabled") {
        $secureBoot = Get-SecureBoot -ESXiHost $ESXiHost
        
        if ($secureBoot.SecureBootSupported -eq $true) {
            if ($Enforced -match "True"  -and $secureBoot.SecureBootEnforced -eq $true) {
                Write-Output "[$ESXiHost] SecureBoot policy already set to enforced. Skipping."
            } elseif ($Enforced -match "True" -and $secureBoot.SecureBootEnforced -eq $false){
                $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
                $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

                $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
                $arguments.requiresecureboot = $true

                $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null

                $checkSecureBoot = Get-SecureBoot -ESXiHost $ESXiHost
                if ($checkSecureBoot.SecureBootEnforced -eq $true) {
                    Write-Output "[$ESXiHost] SecureBoot policy successfully set to enforced."
                } else {
                    Write-Error "[$ESXiHost] SecureBoot policy was not successfully set to enforced."
                }
            } elseif ($Enforced -match "False" -and $secureBoot.SecureBootEnforced -eq $false) {
                Write-Output "[$ESXiHost] SecureBoot policy already set to unenforced. Skipping."
            } elseif ($Enforced -match "False" -and $secureBoot.SecureBootEnforced -eq $true) {
                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

                $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
                $arguments.requiresecureboot = $false

                $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null

                $checkSecureBoot = Get-SecureBoot -ESXiHost $ESXiHost
                if ($checkSecureBoot.SecureBootEnforced -eq $false) {
                    Write-Output "[$ESXiHost] SecureBoot policy successfully set to disabled."
                } else {
                    Write-Error "[$ESXiHost] SecureBoot policy was not successfully set to disabled."
                }
            }
        } elseif ($secureBoot.SecureBootSupported -eq $false) {
            Write-Error "[$ESXiHost] SecureBoot is not supported on this ESXi host."
        }
    }
} Export-ModuleMember -Function Set-SecureBoot

Function Get-ExecInstalledOnlyKernel {
    <#
    .SYNOPSIS
    Gets the execInstalledOnly kernel module configuration for an ESXi host

    .DESCRIPTION
    The Get-ExecInstalledOnlyKernel cmdlet gets the execInstalledOnly kernel module configuration for an ESXi host

    .EXAMPLE
    Get-ExecInstalledOnlyKernel -ESXiHost esx-01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host to be queried for its execInstalledOnly kernel module configuration 
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

    $arguments = $esxcli.system.settings.kernel.list.CreateArgs()
    $arguments.option = "execInstalledOnly"     
    $execInstalledOnly = $esxcli.system.settings.kernel.list.Invoke($arguments)

    $execInstalledOnlyConfiguredBool = [System.Convert]::ToBoolean($execInstalledOnly.Configured)
    $execInstalledOnlyRuntimeBool = [System.Convert]::ToBoolean($execInstalledOnly.Runtime)

    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'ExecInstalledOnlyKernelConfigured' -NotePropertyValue $execInstalledOnlyConfiguredBool
    $output | Add-Member -NotePropertyName 'ExecInstalledOnlyKernelRuntime' -NotePropertyValue $execInstalledOnlyRuntimeBool

    $output
} Export-ModuleMember -Function Get-ExecInstalledOnlyKernel

Function Set-ExecInstalledOnlyKernel {
    <#
    .SYNOPSIS
    Sets the execInstalledOnly kernel module configuration for an ESXi host

    .DESCRIPTION
    The Set-ExecInstalledOnlyKernel cmdlet sets the execInstalledOnly kernel module configuration for an ESXi host

    .EXAMPLE
    Set-ExecInstalledOnlyKernel -ESXiHost esx-01.sddc.lab -Enabled True

    .PARAMETER ESXiHost
    The ESXi host to be queried for its execInstalledOnly kernel module configuration 

    .PARAMETER Enabled
    Specifies whether the execInstalledOnly kernel module should be enabled
    #>

        Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Enabled
    )

    $checkLockdownMode = Get-LockdownMode -ESXiHost $ESXiHost
    if ($checkLockdownMode.LockdownMode -eq "lockdownNormal" -or $checkLockdownMode.LockdownMode -eq "lockdownStrict") {
        Write-Error "[$ESXiHost]  Lockdown Mode is set to $($checkLockdownMode.LockdownMode). Please disable Lockdown Mode and try again."
    } elseif ($checkLockdownMode.LockdownMode -eq "lockdownDisabled") {
        $execInstalledOnlyKernel = Get-ExecInstalledOnlyKernel -ESXiHost $ESXiHost
        if (!$execInstalledOnlyKernel -or !$execInstalledOnlyKernel.ESXiHost) {
            Write-Error "[$ESXiHost] ESXi host was not found."
        } else {
            if ($Enabled -match "True" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $true) {
                if ($execInstalledOnlyKernel.ExecInstalledOnlyKernelRuntime -eq $true) {
                    Write-Output "[$ESXiHost] ExecInstalledOnly has already been enabled and the runtime value is set to True. Skipping."
                } else {
                    Write-Warning "[$ESXiHost] ExecInstalledOnly has already been enabled but the runtime value is set to False. Please reboot the ESXi host."
                }
            } elseif ($Enabled -match "True" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $false) {
                $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
                $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

                $arguments = $esxcli.system.settings.kernel.set.CreateArgs()
                $arguments.setting = "execInstalledOnly"
                $arguments.value   = $true

                $esxcli.system.settings.kernel.set.Invoke($arguments) | Out-Null
                
                $checkExecInstalledOnlyKernel = Get-ExecInstalledOnlyKernel -ESXiHost $ESXiHost
                if ($checkExecInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $true) {
                    Write-Output "[$ESXiHost] ExecInstalledOnly has been successfully enabled. Please reboot the ESXi host."
                } else {
                    Write-Error "[$ESXiHost] ExecInstalledOnly has not been successfully enabled."
                }
            } elseif ($Enabled -match "False" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $false) {
                if ($execInstalledOnlyKernel.ExecInstalledOnlyKernelRuntime -eq $false) {
                    Write-Output "[$ESXiHost] ExecInstalledOnly has already been disabled and the runtime value is set to False. Skipping."
                } else {
                    Write-Warning "[$ESXiHost] ExecInstalledOnly has already been disabled but the runtime value is set to True. Please reboot the ESXi host."
                } 
            } elseif ($Enabled -match "False" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $true) {
                $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
                $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

                $arguments = $esxcli.system.settings.kernel.set.CreateArgs()
                $arguments.setting = "execInstalledOnly"
                $arguments.value   = $false

                $esxcli.system.settings.kernel.set.Invoke($arguments) | Out-Null
                
                $checkExecInstalledOnlyKernel = Get-ExecInstalledOnlyKernel -ESXiHost $ESXiHost
                if ($checkExecInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $false) {
                    Write-Output "[$ESXiHost] ExecInstalledOnly has been successfully disabled. Please reboot the ESXi host."
                } else {
                    Write-Error "[$ESXiHost] ExecInstalledOnly has not been successfully disabled."
                }        
            }
        }
    }
} Export-ModuleMember -Function Set-ExecInstalledOnlyKernel

Function Get-ExecInstalledOnlyPolicy {
    <#
    .SYNOPSIS
    Gets the execInstalledOnly policy configuration for an ESXi host

    .DESCRIPTION
    The Get-ExecInstalledOnlyPolicy cmdlet gets the execInstalledOnly policy configuration for an ESXi host

    .EXAMPLE
    Get-ExecInstalledOnlyPolicy -ESXiHost esx-01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host to be queried for its execInstalledOnly policy configuration 
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

    $execInstalledOnlyPolicy = $esxcli.system.settings.encryption.get.Invoke()

    $execInstalledOnlyPolicydBool = [System.Convert]::ToBoolean($execInstalledOnlyPolicy.RequireExecutablesOnlyFromInstalledVIBs)

    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'ExecInstalledOnlyPolicy' -NotePropertyValue $execInstalledOnlyPolicydBool

    $output
} Export-ModuleMember -Function Get-ExecInstalledOnlyPolicy

Function Set-ExecInstalledOnlyPolicy {
    <#
    .SYNOPSIS
    Sets the execInstalledOnly policy configuration for an ESXi host

    .DESCRIPTION
    The Set-ExecInstalledOnlyPolicy cmdlet sets the execInstalledOnly policy configuration for an ESXi host

    .EXAMPLE
    Set-ExecInstalledOnlyPolicy -ESXiHost esx-01.sddc.lab -Enabled True

    .PARAMETER ESXiHost
    The ESXi host to be queried for its execInstalledOnly policy configuration 

    .PARAMETER Enabled
    Specifies whether the execInstalledOnly policy should be enabled
    #>

        Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Enabled
    )

    $checkLockdownMode = Get-LockdownMode -ESXiHost $ESXiHost
    if ($checkLockdownMode.LockdownMode -eq "lockdownNormal" -or $checkLockdownMode.LockdownMode -eq "lockdownStrict") {
        Write-Error "[$ESXiHost]  Lockdown Mode is set to $($checkLockdownMode.LockdownMode). Please disable Lockdown Mode and try again."
    } elseif ($checkLockdownMode.LockdownMode -eq "lockdownDisabled") {
        $execInstalledOnlyPolicy = Get-ExecInstalledOnlyPolicy -ESXiHost $ESXiHost
        if (!$execInstalledOnlyPolicy -or !$execInstalledOnlyPolicy.ESXiHost) {
            Write-Error "[$ESXiHost] ESXi host was not found."
        } else {
            if ($Enabled -match "True" -and $execInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $true) {
                    Write-Error "[$ESXiHost] ExecInstalledOnly policy has already been enabled."
            } elseif ($Enabled -match "True" -and $execInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $false) {
                $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
                $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop

                $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
                $arguments.requireexecinstalledonly = $true

                $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
                
                $checkExecInstalledOnlyPolicy = Get-ExecInstalledOnlyPolicy -ESXiHost $ESXiHost
                if ($checkExecInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $true) {
                    Write-Output "[$ESXiHost] ExecInstalledOnly policy has been successfully enabled. Please reboot the ESXi host."
                } else {
                    Write-Error "[$ESXiHost] ExecInstalledOnly policy has not been successfully enabled."
                }
            } elseif ($Enabled -match "False" -and $execInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $false) {
                    Write-Error "[$ESXiHost] ExecInstalledOnly policy has already been disabled."
            } elseif ($Enabled -match "False" -and $execInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $true) {
                $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
                $esxcli = Get-EsxCli -VMhost $vmhost.Name -V2 -ErrorAction Stop
                
                $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
                $arguments.requireexecinstalledonly = $false

                $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
                
                $checkExecInstalledOnlyPolicy = Get-ExecInstalledOnlyPolicy -ESXiHost $ESXiHost
                if ($checkExecInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $false) {
                    Write-Output "[$ESXiHost] ExecInstalledOnly policy has been successfully disabled. Please reboot the ESXi host."
                } else {
                    Write-Error "[$ESXiHost] ExecInstalledOnly policy has not been successfully disabled."
                }        
            }
        }
    }
} Export-ModuleMember -Function Set-ExecInstalledOnlyPolicy

Function Get-ESXiHostRecoveryKey {
    <#
    .SYNOPSIS
    Gets the TPM recovery key for an ESXi host

    .DESCRIPTION
    The Get-ESXiHostRecoveryKey cmdlet gets the TPM recovery key for an ESXi host

    .EXAMPLE
    Get-ESXiHostRecoveryKey -ESXiHost esx-01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host to be queried for its TPM recovery key 
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    if ($vmhost) {
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

        $getRecoveryKey = $esxcli.system.settings.encryption.recovery.list.Invoke()

        $output = New-Object -TypeName PSCustomObject
        $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
        $output | Add-Member -NotePropertyName 'RecoveryID' -NotePropertyValue $getRecoveryKey.RecoveryID
        $output | Add-Member -NotePropertyName 'RecoveryKey' -NotePropertyValue $getRecoveryKey.Key

        $output
    } else {
        Write-Error "[$ESXiHost] ESXi host is unavailable or does not exist."
    }

} Export-ModuleMember -Function Get-ESXiHostRecoveryKey

Function Get-VCSAFirewallConfig {
    <#
    .SYNOPSIS
    Gets the firewall configuration of a vCenter Server virtual appliance

    .DESCRIPTION
    The Get-VCSAFirewallConfig cmdlet gets the firewall configuration of a vCenter Server virtual appliance

    .EXAMPLE
    Get-VCSAFirewallConfig -Server vcsa01.sddc.lab

    .PARAMETER Server
    The vCenter Server virtual appliance to be queried for its firewall configuration
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Server
    )

    if ($Server -match $global:DefaultVIServers) {
        $firewall = Invoke-GetNetworkingFirewallInbound

        $firewall
    } else {
        Write-Error "[$Server] Not connected to vCenter Server virtual appliance."
    }

} Export-ModuleMember -Function Get-VCSAFirewallConfig

Function Set-VCSAFirewallConfig {
    <#
    .SYNOPSIS
    Sets the firewall configuration of a vCenter Server virtual appliance

    .DESCRIPTION
    The Set-VCSAFirewallConfig cmdlet sets the firewall configuration of a vCenter Server virtual appliance

    .EXAMPLE
    Set-VCSAFirewallConfig -Server vcsa01.sddc.lab -csvInput .\vcsa_firewall.csv

    .PARAMETER Server
    The vCenter Server virtual appliance to be have its firewall configuration set
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Location,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $csvInput
    )

    if ($Server -match $global:DefaultVIServer.Name) {
        $rules = @()

        Import-Csv -Path $csvInput -PipelineVariable row |
        ForEach-Object -Process {
            $rules += Initialize-NetworkingFirewallInboundRule -Address $row.'ip address' -Prefix $row.'subnet prefix' -Policy $row.action.ToUpper() -InterfaceName 'nic0' | Where-Object {$row.site -match $Location -or $row.site -match "all"}
        }

        foreach ($rule in $rules) {
            if ($rule.address -match "0.0.0.0" -and $rule.policy -notmatch "accept") {
                if ($rule -ne $rules[-1]) {
                    Write-Error "[$Server] Input has 0.0.0.0/0 rule with $($rule.policy) as its policy. This is only permitted at the last row."
                }
            }
        }

        $body = Initialize-NetworkingFirewallInboundSetRequestBody -Rules $rules
        Invoke-SetNetworkingFirewallInbound -NetworkingFirewallInboundSetRequestBody $body

        $validateFirewall = Get-VCSAFirewallConfig -Server $Server
        if ($validateFirewall) {
            $validateFirewall
        } else {
            Write-Error "[$Server] Unable to validate vCenter Server virtual appliance firewall configuration."
        }
    } else {
        Write-Error "[$Server] Not connected to vCenter Server virtual appliance."
    }

} Export-ModuleMember -Function Set-VCSAFirewallConfig

Function Get-ESXiHostFirewall {
    <#
    .SYNOPSIS
    Gets the firewall configuration of an ESXi host

    .DESCRIPTION
    The Get-ESXiHostFirewall cmdlet gets the firewall configuration of an ESXi host

    .EXAMPLE
    Get-ESXiHostFirewall -ESXiHost esx01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host to be queried for its firewall configuration
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
)

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    if ($vmhost) {
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
        $getFirewallConfig = $esxcli.network.firewall.get.invoke()

        $firewallEnabled = [System.Convert]::ToBoolean($getFirewallConfig.Enabled)
        $firewallLoaded = [System.Convert]::ToBoolean($getFirewallConfig.Loaded)

        $output = New-Object -TypeName PSCustomObject
        $output | Add-Member -NotePropertyName 'Enabled' -NotePropertyValue $firewallEnabled
        $output | Add-Member -NotePropertyName 'Loaded' -NotePropertyValue $firewallLoaded
        $output | Add-Member -NotePropertyName 'DefaultAction' -NotePropertyValue $getFirewallConfig.DefaultAction

        $output
    } else {
        Write-Error "[$ESXiHost] ESXi host is unavailable or does not exist. Skipping."
    }

} Export-ModuleMember -Function Get-ESXiHostFirewall

Function Set-ESXiHostFirewall {
    <#
    .SYNOPSIS
    Gets the firewall configuration of an ESXi host

    .DESCRIPTION
    The Get-ESXiHostFirewall cmdlet gets the firewall configuration of an ESXi host

    .EXAMPLE
    Get-ESXiHostFirewall -ESXiHost esx01.sddc.lab

    .PARAMETER ESXiHost
    The ESXi host to be queried for its firewall configuration

    .PARAMETER Enabled
    Defining whether the ESXi firewall should be enabled

    .PARAMETER DefaultAction
    Defining the default action for the ESXi firewall
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $false)] [ValidateSet($true, $false)] [string] $Enabled,
        [Parameter(Mandatory = $false)] [ValidateSet("DROP", "PASS")] [String] $DefaultAction
)

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    if ($vmhost) {
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
        $getFirewallConfig = Get-ESXiHostFirewall -ESXiHost $ESXiHost

        if ($getFirewallConfig) {
            if ($Enabled) {
                if ($Enabled -eq $false -and $getFirewallConfig.Enabled -eq $true) {
                    $arguments = $esxcli.network.firewall.set.CreateArgs()
                    $arguments.enabled = $false

                    $esxcli.network.firewall.set.Invoke($arguments) | Out-Null

                    $getFirewallEnabled = Get-ESXiHostFirewall -ESXiHost $ESXiHost
                    if ($getFirewallEnabled.Enabled -eq $false) {
                        Write-Output "[$ESXiHost] ESXi host firewall was successfully disabled."
                        
                        $getFirewallEnabled
                    } else {
                        Write-Error "[$ESXiHost] ESXi host firewall was not successfully disabled."
                    }
                } elseif ($Enabled -eq $true -and $getFirewallConfig.Enabled -eq $false) {
                    $arguments = $esxcli.network.firewall.set.CreateArgs()
                    $arguments.enabled = $true

                    $esxcli.network.firewall.set.Invoke($arguments) | Out-Null

                    $getFirewallEnabled = Get-ESXiHostFirewall -ESXiHost $ESXiHost
                    if ($getFirewallEnabled.Enabled -eq $true) {
                        Write-Output "[$ESXiHost] ESXi host firewall was successfully enabled."

                        $getFirewallEnabled
                    } else {
                        Write-Error "[$ESXiHost] ESXi host firewall was not successfully enabled."
                    }                
                } elseif ($Enabled -eq $true -and $getFirewallConfig.Enabled -eq $true) {
                    Write-Error "[$ESXiHost] ESXi host firewall is already enabled."
                } elseif ($Enabled -eq $false -and $getFirewallConfig.Enabled -eq $false) {
                    Write-Error "[$ESXiHost] ESXi host firewall is already disabled."
                }
            }
            if ($DefaultAction) {
                if ($DefaultAction -eq "PASS" -and $getFirewallConfig.DefaultAction -eq "DROP") {
                    $arguments = $esxcli.network.firewall.set.CreateArgs()
                    $arguments.defaultaction = $true

                    $esxcli.network.firewall.set.Invoke($arguments) | Out-Null

                    $getFirewallDefaultAction = Get-ESXiHostFirewall -ESXiHost $ESXiHost
                    if ($getFirewallDefaultAction.DefaultAction -eq "PASS") {
                        Write-Output "[$ESXiHost] ESXi host firewall default action was successfully set to $DefaultAction."
                
                        $getFirewallDefaultAction
                    } else {
                        Write-Error "[$ESXiHost] ESXi host firewall default action was not successfully set to $DefaultAction."
                    }                
                } elseif ($DefaultAction -eq "DROP" -and $getFirewallConfig.DefaultAction -eq "PASS") {
                    $arguments = $esxcli.network.firewall.set.CreateArgs()
                    $arguments.defaultaction = $false

                    $esxcli.network.firewall.set.Invoke($arguments) | Out-Null

                    $getFirewallDefaultAction = Get-ESXiHostFirewall -ESXiHost $ESXiHost
                    if ($getFirewallDefaultAction.DefaultAction -eq "DROP") {
                        Write-Output "[$ESXiHost] ESXi host firewall default action was successfully set to $DefaultAction."
                        
                        $getFirewallDefaultAction
                    } else {
                        Write-Error "[$ESXiHost] ESXi host firewall default action was not successfully set to $DefaultAction."
                    }    
                } elseif ($DefaultAction -eq "PASS" -and $getFirewallConfig.DefaultAction -eq "PASS") {
                    Write-Error "[$ESXiHost] ESXi host firewall default action is already set to PASS."
                } elseif ($DefaultAction -eq "DROP" -and $getFirewallConfig.DefaultAction -eq "DROP") {
                    Write-Error "[$ESXiHost] ESXi host firewall default action is already set to DROP."
                }
            }
        }
    } else {
        Write-Error "[$ESXiHost] ESXi host is unavailable or does not exist."
    }

} Export-ModuleMember -Function Set-ESXiHostFirewall

Function Get-ESXiHostFirewallRuleset {
    <#
    .SYNOPSIS
    Gets the configuration of an ESXi host firewall ruleset

    .DESCRIPTION
    The Get-ESXiHostFirewallRuleset cmdlet gets the configuration of an ESXi host firewall ruleset

    .EXAMPLE
    Get-ESXiHostFirewallRuleset -ESXiHost esx01.sddc.lab

    .EXAMPLE
    Get-ESXiHostFirewallRuleset -ESXiHost esx01.sddc.lab -Ruleset sshServer

    .PARAMETER ESXiHost
    The ESXi host to be queried for its firewall configuration

    .PARAMETER Ruleset
    The ruleset to be queried for its firewall configuration
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $Ruleset
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    if ($vmhost) {
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
        if ($Ruleset) {
            $getFirewallRuleset = $esxcli.network.firewall.ruleset.rule.list.invoke() | Where-Object {$_.Ruleset -match $Ruleset}
            $getFirewallRulesetAllowedIP = $esxcli.network.firewall.ruleset.allowedip.list.invoke() | Where-Object {$_.Ruleset -match $Ruleset}

            $output = New-Object -TypeName PSCustomObject
            $output | Add-Member -NotePropertyName 'Ruleset' -NotePropertyValue $getFirewallRuleset.Ruleset
            $output | Add-Member -NotePropertyName 'AllowedIPAddresses' -NotePropertyValue ($getFirewallRulesetAllowedIP.AllowedIPAddresses -Join ",")
            $output | Add-Member -NotePropertyName 'Direction' -NotePropertyValue $getFirewallRuleset.Direction
            $output | Add-Member -NotePropertyName 'PortType' -NotePropertyValue $getFirewallRuleset.PortType
            $output | Add-Member -NotePropertyName 'Protocol' -NotePropertyValue $getFirewallRuleset.Protocol
            $output | Add-Member -NotePropertyName 'PortBegin' -NotePropertyValue $getFirewallRuleset.PortBegin
            $output | Add-Member -NotePropertyName 'PortEnd' -NotePropertyValue $getFirewallRuleset.PortEnd

            $output

        } else {
            $getFirewall = $esxcli.network.firewall.ruleset.list.Invoke()
            $getFirewall | Select-Object Name,Enabled,AllowedIPconfigurable,EnableDisableconfigurable
        }
    } else {
        Write-Error "[$ESXiHost] ESXi host is unavailable or does not exist. Skipping."
    }
} Export-ModuleMember -Function Get-ESXiHostFirewallRuleset

Function Set-ESXiHostFirewallRuleset {
    <#
    .SYNOPSIS
    Sets the firewall configuration of an ESXi host

    .DESCRIPTION
    The Set-ESXiHostFirewallRuleset cmdlet sets the firewall configuration of an ESXi host

    .EXAMPLE
    Set-ESXiHostFirewallRuleset -ESXiHost esx01.sddc.lab -Ruleset sshServer -AddSubnet 192.168.0.0/16

    .EXAMPLE
    Set-ESXiHostFirewallRuleset -ESXiHost esx01.sddc.lab -Ruleset sshServer -RemoveSubnet 192.168.0.0/16    

    .PARAMETER ESXiHost
    The ESXi host to be queried for its firewall configuration

    .PARAMETER Ruleset
    The ESXi host firewall ruleset to be configured

    .PARAMETER AddSubnet
    The IP subnet to add to the defined ESXi host firewall ruleset  

    .PARAMETER RemoveSubnet
    The IP subnet to remove from the defined ESXi host firewall ruleset  
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Ruleset,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $AddSubnet,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $RemoveSubnet
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop | Where-Object {$_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}
    if ($vmhost) {
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

        $getFirewallRuleset = Get-ESXiHostFirewallRuleset -ESXiHost $ESXiHost -Ruleset $Ruleset
        $getFirewallConfig = Get-ESXiHostFirewall -ESXiHost $ESXiHost
        if ($getFirewallRuleset.Ruleset -eq $Ruleset) {
            if ($getFirewallConfig.Enabled -eq $true) {
                Set-ESXiHostFirewall -ESXiHost $ESXiHost -Enabled $false | Out-Null

                $checkFirewallConfig = Get-ESXiHostFirewall -ESXiHost $ESXiHost
                if ($checkFirewallConfig.Enabled -eq $false) {
                    if ($getFirewallRuleset.AllowedIPAddresses -match "all") {
                        $arguments = $esxcli.network.firewall.ruleset.set.CreateArgs()
                        $arguments.allowedall = $false
                        $arguments.rulesetid = $Ruleset
                        
                        $esxcli.network.firewall.rulset.set.Invoke($arguments) | Out-Null

                        $getFirewallRulesetConfig = Get-ESXiHostFirewallRuleset -ESXiHost $ESXiHost -Ruleset $Ruleset
                        if ($getFirewallRulesetConfig.AllowedIPAddresses -match "all") {
                            Write-Error "[$ESXiHost] Unable to verify ESXi host firewall was disabled to continue configuration."
                        }
                    }
                }
            }
            if ($AddSubnet) {
                $checkSubnetPresent = Get-ESXiHostFirewallRuleset -ESXiHost $ESXiHost -Ruleset $Ruleset

                if ($checkSubnetPresent.AllowedIPAddresses -match $AddSubnet) {
                    Write-Error "[$ESXiHost] ESXi host firewall ruleset $Ruleset already contains the subnet $AddSubnet."
                } else {
                    $arguments = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
                    $arguments.ipaddress = $AddSubnet
                    $arguments.rulesetid = $Ruleset

                    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments) | Out-Null

                    $getFirewallRulesetAllowedIPAddresses = Get-ESXiHostFirewallRuleset -ESXiHost $ESXiHost -Ruleset $Ruleset
                    if ($getFirewallRulesetAllowedIPAddresses.AllowedIPAddresses -match $AddSubnet) {
                        Write-Output "[$ESXiHost] Subnet $AddSubnet has been successfully added to the ESXi host firewall ruleset $Ruleset."

                        $getFirewallRulesetAllowedIPAddresses
                    } else {
                        Write-Error "[$ESXiHost] Firewall ruleset $Ruleset has not been successfully updated."
                    }
                }
            }
            if ($RemoveSubnet) {
                $checkSubnetPresent = Get-ESXiHostFirewallRuleset -ESXiHost $ESXiHost -Ruleset $Ruleset

                if ($checkSubnetPresent.AllowedIPAddresses -notmatch $RemoveSubnet) {
                    Write-Error "[$ESXiHost] ESXi host firewall ruleset $Ruleset does not contain the subnet $RemoveSubnet."
                } else {
                    $arguments = $esxcli.network.firewall.ruleset.allowedip.remove.CreateArgs()
                    $arguments.ipaddress = $RemoveSubnet
                    $arguments.rulesetid = $Ruleset

                    $esxcli.network.firewall.ruleset.allowedip.remove.Invoke($arguments) | Out-Null

                    $getFirewallRulesetAllowedIPAddresses = Get-ESXiHostFirewallRuleset -ESXiHost $ESXiHost -Ruleset $Ruleset
                    if ($getFirewallRulesetAllowedIPAddresses.AllowedIPAddresses -notmatch $RemoveSubnet) {
                        Write-Output "Subnet $RemoveSubnet has been successfully removed from the ESXi host firewall ruleset $Ruleset"

                        $getFirewallRulesetAllowedIPAddresses
                    } else {
                        Write-Error "[$ESXiHost] Firewall ruleset $Ruleset has not been successfully updated."
                    }
                }
            }
            if ($getFirewallConfig.Enabled -eq $true) {
                Set-ESXiHostFirewall -ESXiHost $ESXiHost -Enabled $true | Out-Null

                $checkFirewallConfigAgain = Get-ESXiHostFirewall $ESXiHost
                if ($checkFirewallConfigAgain.Enabled -eq $false) {
                    Write-Error "[$ESXiHost] Unable to validate ESXi host $ESXiHost firewall was re-enabled."
                }
            }
        } else {
            Write-Output "[$ESXiHost] ESXi host firewall ruleset does not exist. Skipping."
        }
    } else {
        Write-Error "[$ESXiHost] ESXi host is unavailable or does not exist."
    }
} Export-ModuleMember -Function Set-ESXiHostFirewallRuleset