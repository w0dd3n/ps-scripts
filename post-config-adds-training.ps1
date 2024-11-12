<#
    Powershell script to populate ADDS server for training purpose

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
$Departments = @(
    @{OU = "Direction"; Prefix = "D"},
    @{OU = "Administration"; Prefix = "A"},
    @{OU = "Pedagogie"; Prefix = "P"},
    @{OU = "Apprenants"; Prefix = "E"},
    @{OU = "Informatique"; Prefix = "I"}
)
$ITDepartmentName="Informatique"
$ITDepartmentPrefix="I"
$DefaultUserPassword = ConvertTo-SecureString "Azerty!1234" -AsPlainText -Force
$ShareDrive="D:\"
$SharesParam = @(
    @{ShareName = "Commun"; SharePath="D:\Commun"; GroupRead="GP_Commun_Read"; GroupWrite="GP_Commun_Write"},
    @{ShareName = "Administration"; SharePath="D:\Administration"; GroupRead="GP_Admin_Read"; GroupWrite="GP_Admin_Write"},
    @{ShareName = "Apprenants"; SharePath="D:\Apprenants"; GroupRead="GP_Apprenants_Read"; GroupWrite="GP_Apprenants_Write"},
    @{ShareName = "Technique"; SharePath="D:\Technique"; GroupRead="GP_Technique_Read"; GroupWrite="GP_Technique_Write"}
)

## GLOBAL VARIABLES

# Prepare log file to keep track of setup process
$Date = Get-Date -Format "ddMMyyyy"
$Hour = Get-Date -Format "HHmm"

## SCRIPT MAIN SECTION

Start-Transcript -Path C:\AD_config_log_$Date`_$Hour.txt `
                 -Append `
                 -IncludeInvocationHeader

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