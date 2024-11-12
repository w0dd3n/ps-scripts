<#
    Full setup of ADDS Role with training data (Users, Computers, etc.)
    Requires D:\ drive to be setup on server

    Date 2024/11/12
#>

## MAIN SCRIPT CALL SECTION
##
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Setenv','Install','Config')]
    [string]$Argument
)

## AD CONFIGURATION PARAMETERS
$ServerName = "ADDS-B3CAR-SRV"
$ServerIPAddress = "10.0.2.254"
$ServerNetmask = "24"
$ServerDefaultGateway = "10.0.2.1"
$ServerDnsPrimary = "8.8.8.8"
$ServerDnsSecondary = "1.1.1.1"
$ShareDrive="D:\"

# Domain Parameters
$DomainNameDNS = "b3car.rns.aftec.fr"
$DomainNameNetbios = "B3CAR-RNS"
$SafeModeClearAdminPassword = "Azerty!1234"
$SafeModeAdministratorPassword = ConvertTo-SecureString $SafeModeClearAdminPassword -AsPlaintext -Force:$true

## SCRIPT CONFIGURATION PARAMETERS
$CurrentDate = Get-Date -Format "ddMMyyyy"
$ScriptLogfilePath = "C:\ADConfig_$CurrentDate.log"

$TaskAction = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-File $PSCommandPath -Argument Install"
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$TaskInstallName = "INSTALL-ADDS-TASK"


## FUNCTION - Setting local server environment
##
function Set-ServerEnvironment {
    Write-Output "Configuring NIC ..."
    Remove-NetIPAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex[0] `
                        -Confirm:$false

    New-NetIPAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex[0] `
                     -IPAddress $ServerIPAddress `
                     -PrefixLength $ServerNetmask `
                     -DefaultGateway $ServerDefaultGateway

    Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex[0] `
                               -ServerAddresses ($ServerDnsPrimary,$ServerDnsSecondary)
    Write-Output "Configuring NIC ... DONE"

    Write-Output "Preparing task ton continue setup after reboot ..."
    $taskAction = New-ScheduledTaskAction -Execute "Powershell.exe" `
                                          -Argument "-File $PSCommandPath -Argument Install"
    Register-ScheduledTask -Action $TaskAction `
                           -Principal $TaskPrincipal `
                           -Trigger $TaskTrigger `
                           -Settings $TaskSettings `
                           -TaskName $TaskInstallName
    Write-Output "Preparing task ton continue setup after reboot ... DONE"

    Stop-Transcript

    Rename-Computer -NewName $ServerName -Force -Restart
}

## FUNCTION - Installing Domain Controler and promoting server
##
function Install-ADDomainControler {
    Unregister-ScheduledTask -TaskName $TaskInstallName -Confirm:$false

    # Roles to be setup
    $FeatureList = @("AD-Domain-Services","DNS")

    foreach ($Feature in $FeatureList) {
        if (((Get-WindowsFeature -Name $Feature).InstallState) -eq "Available") {
            Write-Output "[ INFO ] Feature $Feature will be installed now !"
            try {
                Add-WindowsFeature -Name $Feature -IncludeManagementTools -IncludeAllSubFeature
                Write-Output "[ INFO ] $Feature : Installation SUCCESS"
            } catch {
                Write-Output "[ ERROR ] $Feature : Installation FAILED"
                Stop-Transcript
                exit

            }
        } else {
            Write-Output "[ ERROR ] Feature $Feature NOT AVAILABLE"
            Stop-Transcript
            exit
        }
    }

    Write-Output "[ INFO ] Preparing task to continue setup after reboot ..."
    $taskAction = New-ScheduledTaskAction -Execute "Powershell.exe" `
                                          -Argument "-File $PSCommandPath -Argument Config"
    Register-ScheduledTask -Action $TaskAction `
                           -Principal $TaskPrincipal `
                           -Trigger $TaskTrigger `
                           -Settings $TaskSettings `
                           -TaskName $TaskInstallName
    Write-Output "[ INFO ] Preparing task to continue setup after reboot ... DONE"


    Write-Output "[ INFO ] Installing Domain Controler ..."
    Import-Module ADDSDeployment
    Install-ADDSForest -DatabasePath 'C:\Windows\NTDS' `
                       -DomainMode 'Default' `
                       -DomainName $DomainNameDNS `
                       -DomainNetbiosName $DomainNameNetbios `
                       -ForestMode 'Default' `
                       -InstallDns $true `
                       -LogPath 'C:\Windows\NTDS' `
                       -NoRebootOnCompletion:$false `
                       -SysvolPath 'C:\Windows\SYSVOL' `
                       -SafeModeAdministratorPassword $SafeModeAdministratorPassword `
                       -Force:$true `
                       -CreateDnsDelegation = $false
    Write-Output "[ INFO ] Installing Domain Controler ... DONE"

    Stop-Transcript
}

## FUNCTION - Build up AD environment with users, computers and shares
##
function Set-ADTopology {
    Unregister-ScheduledTask -TaskName $TaskInstallName -Confirm:$false

    Write-Output "TODO - To be continued"

    Stop-Transcript
}

## MAIN SCRIPT CORE SECTION
##

Start-Transcript -Path $ScriptLogfilePath -Append -IncludeInvocationHeader

switch ($Argument)  {
    "Setenv" {
        Set-ServerEnvironment
    }
    "Install" {
        Install-ADDomainControler
    }
    "Config" {
        Set-ADTopology
    }
    default {
        Write-Output "[ ERROR ] Valid argument list : 'Setenv','Install','Config'"
        Stop-Transcript
    }
}

