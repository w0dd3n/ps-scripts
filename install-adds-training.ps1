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
$DomainAdminPassword = ConvertTo-SecureString "Azerty!1234" -AsPlainText -Force
$LocalAdminPassword = ConvertTo-SecureString "Azerty!1234" -AsPlainText -Force

$DomainNameDNS = "b3car.rns.aftec.fr"
$DomainNameNetbios = "B3CAR-RNS"
$SafeModeClearAdminPassword = "Azerty!1234"
$SafeModeAdministratorPassword = ConvertTo-SecureString $SafeModeClearAdminPassword -AsPlaintext -Force:$true
$DefaultUserPassword = ConvertTo-SecureString "Azerty!1234" -AsPlainText -Force

$SharesParam = @(
    @{ShareName = "Commun"; SharePath="D:\Commun"; GroupRead="GP_Commun_READ"; GroupWrite="GP_Commun_WRITE"},
    @{ShareName = "Administration"; SharePath="D:\Administration"; GroupRead="GP_Admin_READ"; GroupWrite="GP_Admin_WRITE"},
    @{ShareName = "Apprenants"; SharePath="D:\Apprenants"; GroupRead="GP_Apprenants_READ"; GroupWrite="GP_Apprenants_WRITE"},
    @{ShareName = "Technique"; SharePath="D:\Technique"; GroupRead="GP_Technique_READ"; GroupWrite="GP_Technique_WRITE"}
)

$DomainUsersOU = "OU=Domain Users,$DomainPath"
$DomainComputersOU = "OU=Domain Computers,$DomainPath"
$Departments = @(
    @{OU = "Direction"; Prefix = "D"},
    @{OU = "Administration"; Prefix = "A"},
    @{OU = "Pedagogie"; Prefix = "P"},
    @{OU = "Apprenants"; Prefix = "E"},
    @{OU = "Informatique"; Prefix = "I"}
)
$ITDepartmentName="Informatique"
$ITDepartmentPrefix="I"


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
                       -InstallDns:$true `
                       -LogPath 'C:\Windows\NTDS' `
                       -NoRebootOnCompletion:$false `
                       -SysvolPath 'C:\Windows\SYSVOL' `
                       -SafeModeAdministratorPassword $SafeModeAdministratorPassword `
                       -Force:$true `
                       -CreateDnsDelegation:$false
    Write-Output "[ INFO ] Installing Domain Controler ... DONE"

    Stop-Transcript
}

## FUNCTION - Build up AD environment with users, computers and shares
##
function Set-ADTopology {
    Unregister-ScheduledTask -TaskName $TaskInstallName -Confirm:$false

    $RequiredServices = Get-Service -Name ADWS, KDC, NetLogon, DNS
    foreach ($Service in $RequiredServices) {
        while ($Service.Status -ne 'Running') {
            Write-Output "[ WARNING ] Waiting service $($Service.Name) to start"
            Start-Sleep -Seconds 5
            $Service = Get-Service -Name $Service.Name
        }
        Write-Output "[ INFO ] Required service $($Service.Name) is ready"
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Output "[ ERROR ] Failed to import AD Module"
        Stop-Transcript
        exit
    }

    # Connect as domain admin
    $Credential = New-Object System.Management.Automation.PSCredential ($DomainAdminUsername, $DomainAdminPassword)

    # Create users and computers in every OU
    foreach ($Department in $Departments) {
        $UsersOU = "$department.OU,$DomainUsersOU"
        $ComputersOU = "$department.OU,$DomainComputersOU"
        $Prefix = $Department.Prefix

        for ($i = 1; $i -le 5; $i++) {
            $Username = "$Prefix-User$i"
            $Firstname = "$Prefix User $i"
            $Lastname = "$Department.OU"
            $UserPrincipalName = "$Username@$DomainName"
            $Password = $DefaultUserPassword

            New-ADUser  -SamAccountName $Username `
                        -UserPrincipalName $UserPrincipalName `
                        -Name "$Firstname $Lastname" `
                        -GivenName $Firstname `
                        -Surname $Lastname `
                        -Path $UsersOU `
                        -AccountPassword $Password `
                        -Enabled:$true `
                        -PassThru -Credential $Credential

            # Create a computer for each user (computer name = "LAPTOP-<username>")
            $ComputerName = "LAPTOP-$username"
            New-ADComputer  -Name $ComputerName `
                            -Path "OU=$ComputersOU,$DomainPath" `
                            -Credential $Credential

            Set-ADComputer  -Identity $ComputerName `
                            -Description "Computer of $Username" `
                            -UserPrincipalName $UserPrincipalName `
                            -Credential $Credential

            # Prepare specific admin accounts for IT department
            if ($OU -eq $ITDepartmentName) {
                for ($i = 1; $i -le 5; $i++) {
                    $AdminUsername = "ITAdmin$i"
                    $Firstname = "$ITDepartmentName Admin $i"
                    $Lastname = "$ITDepartmentName"
                    $UserPrincipalName = "$AdminUsername@$DomainName"
                    $Password = $LocalAdminPassword

                    New-ADUser  -SamAccountName $AdminUsername `
                                -UserPrincipalName $UserPrincipalName `
                                -Name "$Firstname $Lastname" `
                                -GivenName $Firstname `
                                -Surname $Lastname `
                                -Path "OU=$UsersOU,$DomainPath" `
                                -AccountPassword $Password `
                                -Enabled:$true `
                                -PassThru -Credential $Credential

                    $AdminComputerName = "LAPTOP-$AdminUsername"
                    New-ADComputer  -Name $adminComputerName `
                                    -Path "OU=$UsersOU,$DomainPath" `
                                    -Credential $Credential

                    Set-ADComputer  -Identity $AdminComputerName `
                                    -Description "Computer of $AdminUsername" `
                                    -UserPrincipalName $UserPrincipalName `
                                    -Credential $Credential
                }
            }
        }
    }

    # Create shared directories and prepare shares with default access
    foreach ($Share in $SharesParam) {
        try {
            New-Item -ItemType directory -Path $ShareDrive -Name $Share.ShareName
            New-SmbShare -Name $Share.ShareName `
                        -Path $Share.SharePath `
                        -FullAccess "Tout le monde"
        } catch {
            Write-Output "[ ERROR ] Failed to create shared directory : $($Share.ShareName)"
        }
    }

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

## EOF ##
