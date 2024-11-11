<#
    Powershell script to setup and populate ADDS server for training purpose

    Date - 2024/11/08
#>

## CONFIGURATION VARIABLES

[string]$DomainName = "b3car.rns.aftec.fr"
[string]$DomainPath = "DC=b3car,DC=rns,DC=aftec,DC=fr"
[string]$DomainNetbiosName = "B3CAR-RNS"
[string]$SafeModePassword = ConvertTo-SecureString "azerty1234" -AsPlainText -Force
[string]$DomainAdminUsername = "Administrator"
[string]$DomainAdminPassword = ConvertTo-SecureString "azerty1234" -AsPlainText -Force
[string]$LocalAdminPassword = ConvertTo-SecureString "azerty1234" -AsPlainText -Force
$Departments = @(
    @{OU = "Direction"; Prefix = "D"},
    @{OU = "Administration"; Prefix = "A"},
    @{OU = "Pedagogie"; Prefix = "P"},
    @{OU = "Apprenants"; Prefix = "E"},
    @{OU = "Informatique"; Prefix = "I"}
)
[string]$ITDepartmentName="Informatique"
[string]$ITDepartmentPrefix="I"
[string]$DefaultUserPassword = ConvertTo-SecureString "azerty1234" -AsPlainText -Force
[string]$ShareDrive="D:\"
$SharesParam = @(
    @{ShareName = "Commun"; SharePath="D:\Commun"; GroupRead="GP_Commun_Read"; GroupWrite="GP_Commun_Write"},
    @{ShareName = "Administration"; SharePath="D:\Administration"; GroupRead="GP_Admin_Read"; GroupWrite="GP_Admin_Write"},
    @{ShareName = "Apprenants"; SharePath="D:\Apprenants"; GroupRead="GP_Apprenants_Read"; GroupWrite="GP_Apprenants_Write"},
    @{ShareName = "Technique"; SharePath="D:\Technique"; GroupRead="GP_Technique_Read"; GroupWrite="GP_Technique_Write"}
)

## GLOBAL VARIABLES

# Prepare log file to keep track of setup process
[string]$Date = Get-Date -Format "ddMMyyyy"
[string]$Hour = Get-Date -Format "HHmm"

[string]$Err_Msg_ServicesStatus = "[ ERROR ] The script has stopped, required service $ServiceName isn't running"
[string]$Err_Msg_SysvolStatus   = "[ ERROR ] The SYSVOL folder doesn't exist"
[string]$Err_Msg_ShareDrive     = "[ ERROR ] Shares Partition doesn't exist"

[string]$Inf_Msg_ServicesStatus = "[ INFO ] Service $Name is running"
[string]$Inf_Msg_Sysvol         = "[ INFO ] The SYSVOL folder ready to setup AD DS"
[string]$Inf_Msg_ShareDrive     = "[ INFO ] Shares Partition ready to setup AD DS"


# Check services required for AD DS installation
function Check-ServicesStatus {
    $requiredServices = @('adws', 'kdc', 'netlogon', 'dns')

    foreach ($serviceName in $requiredServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop

            if ($service.Status -eq 'Running') {
                Write-Output $Inf_Msg_ServicesStatus.Replace('$ServiceName', $serviceName)
            } else {
                Write-Output $Err_Msg_ServicesStatus.Replace('$ServiceName', $serviceName)
            }
        }
        catch {
            Write-Output $Err_Msg_ServicesStatus.Replace('$ServiceName', $serviceName)
        }
    }
}

# Check environment prerequisite for AD DS installation
function Check-EnvStatus {
    # Validate SYSVOL availability
    $Path = "C:\Windows\SYSVOL"
    if (Test-Path -Path $Path) {
        Write-Output $Inf_Msg_SysvolStatus
    } else {
        throw $Err_Msg_SysvolStatus
    }

    # Validate Shares Partition Drive availability
    if (Test-Path -Path $ShareDrive) {
        Write-Output $Inf_Msg_ShareDrive
    } else {
        throw $Err_Msg_ShareDriveStatus
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        $mess = "`n[ ERROR ] $_"
        Write-Output $mess
    }
}

<#
    SCRIPT MAIN SECTION
#>

Start-Transcript -Path C:\AD_config_log_$Date`_$Hour.txt `
                 -Append `
                 -IncludeInvocationHeader

Check-ServicesStatus "adws,kdc,netlogon,dns"

Check-EnvStatus

# Setup AD DS role if not installed
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature

# Promote server as domain controler
Install-ADDSForest `
  -DomainName $DomainName `
  -CreateDnsDelegation:$false `
  -DatabasePath "C:\Windows\NTDS" `
  -DomainMode "7" `
  -DomainNetbiosName $DomainNetbiosName `
  -ForestMode "7" `
  -InstallDns:$true `
  -LogPath "C:\Windows\NTDS" `
  -NoRebootOnCompletion:$True `
  -SysvolPath "C:\Windows\SYSVOL" `
  -SafeModeAdministratorPassword $SafeModePassword `
  -Force:$true

Restart-Computer

# Wait the time server to be up and running
Start-Sleep -Seconds 60

# Connect as domain admin
$Credential = New-Object System.Management.Automation.PSCredential ($DomainAdminUsername, $DomainAdminPassword)

# Create OUs for each department of the company
foreach ($department in $Departments) {
    New-ADOrganizationalUnit -Name $department.OU `
                             -Path $DomainPath `
                             -Credential $Credential
}

# Create users and computers in every OU
foreach ($department in $Departments) {
    $OU = $department.OU
    $Prefix = $department.Prefix

    for ($i = 1; $i -le 5; $i++) {
        $username = "$Prefix-User$i"
        $firstname = "$Prefix User $i"
        $lastname = "$OU"
        $userPrincipalName = "$username@$DomainName"
        $password = $DefaultUserPassword

        New-ADUser  -SamAccountName $username `
                    -UserPrincipalName $userPrincipalName `
                    -Name "$firstname $lastname" `
                    -GivenName $firstname `
                    -Surname $lastname `
                    -Path "OU=$OU,$DomainPath" `
                    -AccountPassword $password `
                    -Enabled $true `
                    -PassThru -Credential $Credential

        Add-ADGroupMember -Identity "Domain Users" `
                          -Members $username `
                          -Credential $Credential

        # Create a computer for each user (computer name = "LAPTOP-<username>")
        $computerName = "LAPTOP-$username"
        New-ADComputer  -Name $computerName `
                        -Path "OU=$OU,$DomainPath" `
                        -Credential $Credential

        Set-ADComputer  -Identity $computerName `
                        -Description "$username's computer" `
                        -UserPrincipalName $userPrincipalName `
                        -Credential $Credential
    }

    # Prepare specific admin accounts for IT department
    if ($OU -eq $ITDepartmentName) {
        for ($i = 1; $i -le 5; $i++) {
            $adminUsername = "ITAdmin$i"
            $firstname = "$ITDepartmentName Admin $i"
            $lastname = "$ITDepartmentName"
            $userPrincipalName = "$adminUsername@$DomainName"
            $password = $LocalAdminPassword

            New-ADUser  -SamAccountName $adminUsername `
                        -UserPrincipalName $userPrincipalName `
                        -Name "$firstname $lastname" `
                        -GivenName $firstname `
                        -Surname $lastname `
                        -Path "OU=$OU,$DomainPath" `
                        -AccountPassword $password `
                        -Enabled $true `
                        -PassThru -Credential $Credential

            Add-ADGroupMember   -Identity "Domain Admins" `
                                -Members $adminUsername `
                                -Credential $Credential
            Add-ADGroupMember   -Identity "Administrators" `
                                -Members $adminUsername `
                                -Credential $Credential

            $adminComputerName = "LAPTOP-$adminUsername"
            New-ADComputer  -Name $adminComputerName `
                            -Path "OU=$OU,$DomainPath" `
                            -Credential $Credential

            Set-ADComputer  -Identity $adminComputerName `
                            -Description "$adminUsername's computer" `
                            -UserPrincipalName $userPrincipalName `
                            -Credential $Credential
        }
    }
}

# Create shared directories and prepare shares with default access
foreach ($share in $SharesParam) {
    New-Item -ItemType directory -Path $ShareDrive -Name $share.ShareName
    New-SmbShare -Name $share.ShareName `
                 -Path $share.SharePath `
                 -FullAccess "Tout le monde"
    New-ADGroup  -Name $share.GroupRead `
                 -Path "OU=Groupe,OU=$ITDepartmentName,$DomainPath" `
                 -GroupScope DomainLocal
    New-ADGroup  -Name $share.GroupWrite `
                 -Path "OU=Groupe,OU=$ITDepartmentName,$DomainPath" `
                 -GroupScope DomainLocal
}

# Create service Groups
# TODO - TO BE CONTINUED

# End of logging in file
Stop-Transcript

## EOF ##
