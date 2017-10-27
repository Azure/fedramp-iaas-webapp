##This script should be run on Domain Controller

###########################################


Import-Module ActiveDirectory

$Domain = (gwmi WIN32_ComputerSystem).Domain
$Root = [ADSI]"LDAP://RootDSE"
$LDAPDomain = $Root.Get("rootDomainNamingContext")
$key = "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$key1 = "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system"


#PART 1: set Account lockout policies
Set-ADDefaultDomainPasswordPolicy -Identity $Domain -AuthType Negotiate -LockoutDuration "03:00:00" -LockoutObservationWindow "00:15:00" -LockoutThreshold "3"


#PART 2: set inactive session policies
New-GPO 'session lock gpo' |`
Set-GPRegistryValue -Key $key -ValueName 'ScreenSaveTimeOut' -Type String -Value 900 |`
Set-GPRegistryValue -Key $key -ValueName 'ScreenSaveActive' -Type String -Value 1 |`
Set-GPRegistryValue -Key $key -ValueName 'SCRNSAVE.EXE' -Type String -Value "rundll32 user32.dll,LockWorkStation" |`
Set-GPPermissions -Replace -PermissionLevel None -TargetName 'Authenticated Users' -TargetType group | `
Set-GPPermissions -PermissionLevel gpoapply -TargetType group -TargetName 'Authenticated Users' | New-GPLink -Domain $Domain -Target $LDAPDomain -enforced yes –Order 1


#PART 3: set logon message Policy
New-GPO 'logon message gpo' |`
Set-GPRegistryValue -Key $key1 -ValueName 'legalnoticecaption' -Type string -Value "Sample system use notification" |`
Set-GPRegistryValue -Key $key1 -ValueName 'legalnoticetext' -Type string -Value "Sample system use notification. Customer must edit this text to comply with customer organization and/or regulatory body requirements." |`
Set-GPPermissions -Replace -PermissionLevel None -TargetName 'Authenticated Users' -TargetType group | `
Set-GPPermissions -PermissionLevel gpoapply -TargetType group -TargetName 'Authenticated Users' | New-GPLink -Domain $Domain -Target $LDAPDomain -enforced yes –Order 3


#PART 4: set logoff message Policy
New-GPO 'logoff message gpo' |`
Set-GPRegistryValue -Key $key1 -ValueName 'verbosestatus' -Type DWORD -Value 1 |`
Set-GPPermissions -Replace -PermissionLevel None -TargetName 'Authenticated Users' -TargetType group | `
Set-GPPermissions -PermissionLevel gpoapply -TargetType group -TargetName 'Authenticated Users' | New-GPLink -Domain $Domain -Target $LDAPDomain -enforced yes –Order 2



##################################

#PART 5: Script to disable inactive user account after 35 days
#create a new folder
New-Item c:\scripts\Windows-PowerShell -type directory

#create script file
New-Item c:\scripts\Windows-PowerShell\disableinactiveaccounts.ps1 -ItemType file

#content of script file
$content= "Set-ExecutionPolicy Unrestricted
Import-Module ActiveDirectory


#Not A Policy
#get inactive accounts from 35 days
`$inactiveacc= Search-ADAccount -AccountInactive -TimeSpan 35
Foreach(`$acc in `$inactiveacc)
{
Get-ADUser -Filter 'Name -Like `$acc.Name' |Disable-ADAccount
}

<#
#get disabled accounts
`$disacc= Search-ADAccount -AccountDisabled
`$disacc
#enable accounts
Foreach(`$acc in `$disacc)
{
Get-ADUser -Filter 'Name -Like `$acc.Name' |Enable-ADAccount
}
#>"


#appending data to ps1 file
Add-Content c:\scripts\Windows-PowerShell\disableinactiveaccounts.ps1 $content



#scheduling the above script to disable inactive accounts
$principal = New-ScheduledTaskPrincipal -UserId "$($env:USERDOMAIN)\$($env:USERNAME)" -LogonType S4U -RunLevel Highest
$Action = New-ScheduledTaskAction  -Execute 'C:WindowsSystem32WindowsPowerShellv1.0powershell.exe' -Argument "-NonInteractive -NoLogo -NoProfile -File c:\scripts\Windows-PowerShell\disableinactiveaccounts.ps1'"
$Trigger = New-ScheduledTaskTrigger -Daily -At '4AM'
$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $principal -Settings (New-ScheduledTaskSettingsSet)
$Task | Register-ScheduledTask -TaskName ‘Inactive accounts script'


#########################################################################

#this is required for policies to apply- should be applied at the end of the Custom script extension only
Invoke-GPUpdate -Boot
