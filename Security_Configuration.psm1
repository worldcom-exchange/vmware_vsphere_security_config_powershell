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

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop
    
    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'LockdownMode' -NotePropertyValue ($vmhost.ExtensionData.Config.LockdownMode).ToString()

    $output
} Export-ModuleMember -Function Get-LockdownMode

Function Set-LockdownMode {
Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateSet("lockdownDisabled", "lockdownNormal")] [String] $lockdownLevel
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
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

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
        } else {
            Write-Output "[$ESXiHost] $userName was not created and configured successfully."
        }
    } else {
        Write-Output "[$ESXiHost] $userName already exists. Skipping."
    }
}
Export-ModuleMember -Function New-EsxiUser

Function Get-EsxiUser {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $userName
    )

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

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
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $userName,
        [Parameter(Mandatory = $false)] [String] $shellAccess,
        [Parameter(Mandatory = $false)] [ValidateSet("Admin", "ReadOnly", "NoAccess")] [String] $role
    )

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

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

                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

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

                $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

                $checkShellAccess = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $userName}
                if ($checkShellAccess.shellaccess -eq $false) {
                    Write-Output "[$ESXiHost] ESXi shell access for user $userName was successfully disabled."
                } else {
                    Write-Output "[$ESXiHost] ESXi shell access for user $userName was not successfully disabled."
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
                    Write-Output "[$ESXiHost] $userName was not successfully assigned the role $role."
                }
            }
        }
    }
    else {
        Write-Output "[$ESXiHost] User $userName does not exist."
    }
} Export-ModuleMember -Function Set-EsxiUser

Function Remove-EsxiUser {
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
                Write-Output "[$ESXiHost] User $userName was not removed successfully."
            }
        } elseif ($getConfirmation -eq "F") {
            Write-Output "[$ESXiHost] User $userName was not removed."
        } else {
            Write-Output "[$ESXiHost] Invalid input. User $userName was not removed."
        }
    } else {
        Write-Output "[$ESXiHost] User $userName does not exist."
    }
}
Export-ModuleMember -Function Remove-EsxiUser

Function Get-TPM {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop
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
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $currentTpmState = (Get-TPM -ESXiHost $ESXiHost).tpmEnabled

    if ($currentTpmState -eq $true) {
        Write-Host "[$ESXiHost] TPM is already enabled. Skipping."
    } else {
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

        $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
        $arguments.mode = "TPM"

        $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
        $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

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

    $vmhost = Get-VMhost -Name $ESXiHost -ErrorAction Stop
    $hostview = Get-View -Id $vmhost.Id -ErrorAction Stop

    $secureBootSupported = $hostview.Capability.UefiSecureBoot

    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
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
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Enforced
    )

    $secureBoot = Get-SecureBoot -ESXiHost $ESXiHost
    
    if ($secureBoot.SecureBootSupported -eq $true) {
        if ($Enforced -match "True"  -and $secureBoot.SecureBootEnforced -eq $true) {
            Write-Output "[$ESXiHost] SecureBoot policy already set to enforced. Skipping."
        } elseif ($Enforced -match "True" -and $secureBoot.SecureBootEnforced -eq $false){
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2

            $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
            $arguments.requiresecureboot = $true

            $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null

            $checkSecureBoot = Get-SecureBoot -ESXiHost $ESXiHost
            if ($checkSecureBoot.SecureBootEnforced -eq $true) {
                Write-Output "[$ESXiHost] SecureBoot policy successfully set to enforced."
            } else {
                Write-Output "[$ESXiHost] SecureBoot policy was not successfully set to enforced."
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
                Write-Output "[$ESXiHost] SecureBoot policy was not successfully set to disabled."
            }
        }
    } elseif ($secureBoot.SecureBootSupported -eq $false) {
        Write-Output "[$ESXiHost] SecureBoot is not supported on this ESXi host. Skipping."
    }
} Export-ModuleMember -Function Set-SecureBoot

Function Get-ExecInstalledOnlyKernel {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMHost -Name $ESXiHost -ErrorAction Stop
    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

    $arguments = $esxcli.system.settings.kernel.list.CreateArgs()
    $arguments.option = "execInstalledOnly"     
    $execInstalledOnly = $esxcli.system.settings.kernel.list.Invoke($arguments)

    if ($execInstalledOnly.Configured -eq "TRUE") {
        $execInstalledOnlyConfigured = $true
    } elseif ($execInstalledOnly.Configured -eq "FALSE") {
        $execInstalledOnlyConfigured = $false
    }

    if ($execInstalledOnly.Runtime -eq "TRUE") {
        $execInstalledOnlyRuntime = $true
    } elseif ($execInstalledOnly.Runtime -eq "FALSE") {
        $execInstalledOnlyRuntime = $false
    }

    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'ExecInstalledOnlyKernelConfigured' -NotePropertyValue $execInstalledOnlyConfigured
    $output | Add-Member -NotePropertyName 'ExecInstalledOnlyKernelRuntime' -NotePropertyValue $execInstalledOnlyRuntime

    $output
} Export-ModuleMember -Function Get-ExecInstalledOnlyKernel

Function Set-ExecInstalledOnlyKernel {
        Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Enabled
    )

    $execInstalledOnlyKernel = Get-ExecInstalledOnlyKernel -ESXiHost $ESXiHost
    if (!$execInstalledOnlyKernel -or !$execInstalledOnlyKernel.ESXiHost) {
        Write-Output "[$ESXiHost] ESXi host was not found. Skipping."
    } else {
        if ($Enabled -match "True" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $true) {
            if ($execInstalledOnlyKernel.ExecInstalledOnlyKernelRuntime -eq $true) {
                Write-Output "[$ESXiHost] ExecInstalledOnly has already been enabled and the runtime value is set to True. Skipping."
            } else {
                Write-Output "[$ESXiHost] ExecInstalledOnly has already been enabled but the runtime value is set to False. Please reboot the ESXi host."
            }
        } elseif ($Enabled -match "True" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $false) {
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
            $arguments = $esxcli.system.settings.kernel.set.CreateArgs()
            $arguments.setting = "execInstalledOnly"
            $arguments.value   = $true

            $esxcli.system.settings.kernel.set.Invoke($arguments) | Out-Null
            
            $checkExecInstalledOnlyKernel = Get-ExecInstalledOnlyKernel -ESXiHost $ESXiHost
            if ($checkExecInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $true) {
                Write-Output "[$ESXiHost] ExecInstalledOnly has been successfully enabled. Please reboot the ESXi host."
            } else {
                Write-Output "[$ESXiHost] ExecInstalledOnly has not been successfully enabled."
            }
        } elseif ($Enabled -match "False" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $false) {
            if ($execInstalledOnlyKernel.ExecInstalledOnlyKernelRuntime -eq $false) {
                Write-Output "[$ESXiHost] ExecInstalledOnly has already been disabled and the runtime value is set to False. Skipping."
            } else {
                Write-Output "[$ESXiHost] ExecInstalledOnly has already been disabled but the runtime value is set to True. Please reboot the ESXi host."
            } 
        } elseif ($Enabled -match "False" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $true) {
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
            $arguments = $esxcli.system.settings.kernel.set.CreateArgs()
            $arguments.setting = "execInstalledOnly"
            $arguments.value   = $false

            $esxcli.system.settings.kernel.set.Invoke($arguments) | Out-Null
            
            $checkExecInstalledOnlyKernel = Get-ExecInstalledOnlyKernel -ESXiHost $ESXiHost
            if ($checkExecInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $false) {
                Write-Output "[$ESXiHost] ExecInstalledOnly has been successfully disabled. Please reboot the ESXi host."
            } else {
                Write-Output "[$ESXiHost] ExecInstalledOnly has not been successfully disabled."
            }        
        }
    }
} Export-ModuleMember -Function Set-ExecInstalledOnlyKernel

Function Get-ExecInstalledOnlyPolicy {
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost
    )

    $vmhost = Get-VMHost -Name $ESXiHost -ErrorAction Stop
    $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop

    $execInstalledOnlyPolicy = $esxcli.system.settings.encryption.get.Invoke()

    if ($execInstalledOnlyPolicy.RequireExecutablesOnlyFromInstalledVIBs -match "true") {
        $execInstalledOnlyPolicyOutput = $true
    } elseif ($execInstalledOnlyPolicy.RequireExecutablesOnlyFromInstalledVIBs -match "false") {
        $execInstalledOnlyPolicyOutput = $false
    }
    
    Write-Output "$execInstalledOnlyPolicy.RequireExecutablesOnlyFromInstalledVIBs: $($execInstalledOnlyPolicy.RequireExecutablesOnlyFromInstalledVIBs)"
    Write-Output "The variable execInstalledOnlyPolicyOutput is set to $execInstalledOnlyPolicyOutput"

    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -NotePropertyName 'ESXiHost' -NotePropertyValue $vmhost.Name
    $output | Add-Member -NotePropertyName 'ExecInstalledOnlyPolicy' -NotePropertyValue $execInstalledOnlyPolicyOutput

    $output
} Export-ModuleMember -Function Get-ExecInstalledOnlyPolicy

Function Set-ExecInstalledOnlyPolicy {
        Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $ESXiHost,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Enabled
    )

    $execInstalledOnlyPolicy = Get-ExecInstalledOnlyPolicy -ESXiHost $ESXiHost
    if (!$execInstalledOnlyPolicy -or !$execInstalledOnlyPolicy.ESXiHost) {
        Write-Output "[$ESXiHost] ESXi host was not found. Skipping."
    } else {
        if ($Enabled -match "True" -and $execInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $true) {
                Write-Output "[$ESXiHost] ExecInstalledOnly policy has already been enabled. Skipping."
        } elseif ($Enabled -match "True" -and $execInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $false) {
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
            $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
            $arguments.requireexecinstalledonly = $true

            $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
            
            $checkExecInstalledOnlyPolicy = Get-ExecInstalledOnlyPolicy -ESXiHost $ESXiHost
            if ($checkExecInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $true) {
                Write-Output "[$ESXiHost] ExecInstalledOnly policy has been successfully enabled. Please reboot the ESXi host."
            } else {
                Write-Output "[$ESXiHost] ExecInstalledOnly policy has not been successfully enabled."
            }
        } elseif ($Enabled -match "False" -and $execInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $false) {
                Write-Output "[$ESXiHost] ExecInstalledOnly policy has already been disabled. Skipping."
        } elseif ($Enabled -match "False" -and $execInstalledOnlyKernel.ExecInstalledOnlyKernelConfigured -eq $true) {
            $esxcli = Get-EsxCli -VMhost $ESXiHost -V2 -ErrorAction Stop
            $arguments = $esxcli.system.settings.encryption.set.CreateArgs()
            $arguments.requireexecinstalledonly = $false

            $esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
            
            $checkExecInstalledOnlyPolicy = Get-ExecInstalledOnlyPolicy -ESXiHost $ESXiHost
            if ($checkExecInstalledOnlyPolicy.ExecInstalledOnlyPolicy -eq $false) {
                Write-Output "[$ESXiHost] ExecInstalledOnly policy has been successfully disabled. Please reboot the ESXi host."
            } else {
                Write-Output "[$ESXiHost] ExecInstalledOnly policy has not been successfully disabled."
            }        
        }
    }
} Export-ModuleMember -Function Set-ExecInstalledOnlyPolicy