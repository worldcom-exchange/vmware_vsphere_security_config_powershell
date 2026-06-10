param(
    [Parameter(Mandatory)]
    [string]$vCenter,

    [Parameter(Mandatory)]
    [string]$datacenterName,

    [Parameter(Mandatory)]
    [string]$sourceNetwork,

    [Parameter(Mandatory)]
    [string]$destinationNetwork
)

Start-Transcript -Path "migrate_template_networking_$(get-date -f MM-dd-yyyy-HHmmss)" -Append

$powerCLI = Get-Module -Name VMware.PowerCLI
if (!$powerCLI) {
    Import-Module VMware.PowerCLI -ErrorAction Stop
}
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

$credential = Get-Credential -Message "Enter credentials for $vCenter"
$vcenterCheck = Connect-VIServer -Server $vCenter -Credential $Credential -ErrorAction SilentlyContinue

if ($vcenterCheck.IsConnected -eq $true) {
    Write-Output "Successfully connected to vCenter Server $vCenter"
} else {
    Write-Error "Error connecting to vCenter Server $vCenter. Please validate FQDN/IP and credentials."
    $vcenterBroke = $true
    Exit
}

try {
    $templates = Get-Template -Location $datacenterName
    $sourceNetworkInfo = Get-VirtualNetwork -Name $sourceNetwork
    $destinationNetworkInfo = Get-VirtualNetwork -Name $destinationNetwork

    if (!$templates) {
        Write-Error "[$datacenterName] vSphere Datacenter does not contain any Template objects"
        Exit
    }

    if (!$sourceNetworkInfo) {
        Write-Error "[$sourceNetwork] Source network is either invalid or does not exist"
        Exit
    }

    if (!$destinationNetworkInfo) {
        Write-Error "[$destinationNetwork] Destination network is either invalid or does not exist"
        Exit
    }

    foreach ($template in $templates) {

        #Evaluate whether the selected template is assigned to the source network
        if (($template | Get-NetworkAdapter).NetworkName -eq $sourceNetwork){
            
            #Convert the selected template to a VM
            $template | Set-Template -ToVM -Confirm:$false | Out-Null
            $convertedVM = Get-VM -Name $template.Name
            if ($convertedVM) {
                Write-Output "[$($template.Name)] Template has been converted to a virtual machine"
            } else {
                Write-Error "[$($template.Name)] Template was not successfully converted to a virtual machine"
            }

            #Set the network adapter to the destination network
            $nics = $convertedVM | Get-NetworkAdapter
            foreach ($nic in $nics) {
                if ($nic.NetworkName -eq $sourceNetwork) {
                    $nic | Set-NetworkAdapter -PortGroup $DestinationNetwork -Confirm:$false | Out-Null
                    $nicUpdatedNetwork = ($convertedVM | Get-NetworkAdapter | Where-Object {$_.Name -eq $nic.Name}).NetworkName
                    if ($nicUpdatedNetwork -eq $destinationNetwork) {
                        Write-Output "[$($template.Name)] $($nic.Name) has been set to $destinationNetwork"
                    } else {
                        Write-Error "[$($template.Name)] $($nic.Name) has not successfully been set to $destinationNetwork"
                    }
                }
            }

            #Convert the VM back to a template
            $convertedVM | Set-VM -ToTemplate -Confirm:$false | Out-Null
            $convertBackToTemplate = Get-Template -Name $template.Name
            if ($convertBackToTemplate) {
                Write-Output "[$($template.Name)] VM has been converted back into a template"
            } else {
                Write-Error "[$($template.Name)] VM has not been successfully converted back into a template"
            }
            
            Write-Output ""
        }
    }
} finally {
    if (!$vcenterBroke) {
        Disconnect-VIServer -Server * -Confirm:$false | Out-Null
    }
}

Stop-Transcript