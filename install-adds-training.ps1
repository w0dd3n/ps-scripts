<#
    Powershell script to setup and ADDS server for training purpose
    Requires D:\ drive to be setup on server

    Date - 2024/11/08
#>

## CONFIGURATION VARIABLES

$DomainName = "b3car.rns.aftec.fr"
$DomainPath = "DC=b3car,DC=rns,DC=aftec,DC=fr"
$DomainNetbiosName = "B3CAR-RNS"
$SafeModePassword = ConvertTo-SecureString "Azerty!1234" -AsPlainText -Force
$DomainAdminUsername = "Administrateur"
$DomainAdminPassword = ConvertTo-SecureString "Azerty!1234" -AsPlainText -Force
$LocalAdminPassword = ConvertTo-SecureString "Azerty!1234" -AsPlainText -Force
$ShareDrive="D:\"

## GLOBAL VARIABLES

# Prepare log file to keep track of setup process
$Date = Get-Date -Format "ddMMyyyy"
$Hour = Get-Date -Format "HHmm"

$Err_Msg_ShareDrive     = "[ ERROR ] Shares Partition doesn't exist"
$Err_Msg_ADFeature      = "[ ERROR ] AD DS Role installation FAILED"

$Inf_Msg_ShareDrive     = "[ INFO ] Shares Partition ready to setup AD DS"
$Inf_Msg_ADFeature      = "[ INFO ] AD DS Role installation SUCCESS"

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
  -DomainMode "7" `
  -DomainNetbiosName $DomainNetbiosName `
  -ForestMode "7" `
  -InstallDns:$true `
  -LogPath "C:\Windows\NTDS" `
  -NoRebootOnCompletion:$True `
  -SysvolPath "C:\Windows\SYSVOL" `
  -SafeModeAdministratorPassword $SafeModePassword `
  -Force:$true

# End of logging in file
Stop-Transcript
Restart-Computer

## EOF ##
