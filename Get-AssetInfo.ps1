Write-Host "########################################"
Write-Host " PS Script - Host Information gathering"
Write-Host " "
Write-Host " @Author  - <cobejero.ext@simplon.co>"
Write-Host " @Date    - Jan, 4th 2024"
Write-Host " @Licence - GPL Open Source"
Write-Host " "
Write-Host " Usage: Get-AssetInfo.ps1 | Out-File -FilePath C:\temp\$env:COMPUTERNAME.log"
Write-Host " See more: Get-CimClass"
Write-Host "########################################"
Write-Host "`n"

$ExecutionDate = Get-Date -Format "dd/MM/yyyy - HH:mm:ss"
Write-Host "### EXECUTION DATE [$ExecutionDate]"

$SysInfo = ""

$SysInfo += "`n`n### BIOS ###`n"
$SysInfo += (Get-CimInstance -ClassName Win32_BIOS | Format-List | Out-String).Trim()

$SysInfo += "`n`n### CPU ###`n"
$SysInfo += (Get-CimInstance -ClassName Win32_Processor | Select-Object -Property Name,Caption | Format-List | Out-String).Trim()

$SysInfo += "`n`n### RAM ###`n"
$SysInfo += (Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object -Property Banklabel,Manufacturer,SerialNumber,Capacity | Format-List| Out-String).Trim()

$SysInfo += "`n`n### HARD DRIVE SPACE ###`n"
$SysInfo += (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Format-List| Out-String).Trim()

$SysInfo += "`n`n### HARDWARE SYSTEM ###`n"
$SysInfo += (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property Manufacturer,Model | Format-List| Out-String).Trim()

$SysInfo += "`n`n### OPERATING SYSTEM ###`n"
$SysInfo += (Get-CimInstance -ClassName Win32_OperatingSystem | Format-List Version,BuildNumber| Out-String).Trim()

Write-Host $SysInfo
