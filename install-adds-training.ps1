<#
    Powershell script to setup and ADDS server for training purpose
    Requires D:\ drive to be setup on server

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

[string]$Err_Msg_ShareDrive     = "[ ERROR ] Shares Partition doesn't exist"
[string]$Err_Msg_ADFeature      = "[ ERROR ] AD DS Role installation FAILED"

[string]$Inf_Msg_ShareDrive     = "[ INFO ] Shares Partition ready to setup AD DS"
[string]$Inf_Msg_ADFeature      = "[ INFO ] AD DS Role installation SUCCESS"


## SCRIPT MAIN SECTION

Start-Transcript -Path C:\AD_config_log_$Date`_$Hour.txt `
                 -Append `
                 -IncludeInvocationHeader

# Validate Shares Partition Drive availability
if (Test-Path -Path $ShareDrive) {
    Write-Output $Inf_Msg_ShareDrive
} else {
    Write-Output $Err_Msg_ShareDrive
    Stop-Transcript
    exit
}

# Setup AD DS role if not installed
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
if ((Get-WindowsFeature -Name AD-Domain-Services).Installed -eq $true) {
    Write-Output $Inf_Msg_ADFeature
} else {
    Write-Output $Err_Msg_ADFeature
    Stop-Transcript
    exit
}

# Promote server as domain controler
Install-ADDSForest `
  -DomainName $DomainName `
  -CreateDnsDelegation:$false `
  -DatabasePath "C:\Windows\NTDS" `
  -DomainMode "Win2016" `
  -DomainNetbiosName $DomainNetbiosName `
  -ForestMode "Win2016" `
  -InstallDns:$true `
  -LogPath "C:\Windows\NTDS" `
  -NoRebootOnCompletion:$True `
  -SysvolPath "C:\Windows\SYSVOL" `
  -SafeModeAdministratorPassword $SafeModePassword `
  -Force:$true

Restart-Computer

# End of logging in file
Stop-Transcript

## EOF ##
