Enable-PSRemoting -Force
$Domain = (gwmi WIN32_ComputerSystem).Domain

Import-Module ActiveDirectory
Import-Module grouppolicy
$dcs = $Domain.split(".")
$target = "DC=" + $dcs[0]+ "," + "DC=" + $dcs[1]

<#
#Domain admin credentials
$User='aisadmin'
$Password='Azuresample123$'
$UserDomain=$Domain+’\’+$User
$SecurePassword=Convertto-SecureString –String $Password –AsPlainText –force
#PS credentials
$AdminCredentials=New-object System.Management.Automation.PSCredential $UserDomain,$SecurePassword
#>


#this etting errors out
#Setting password policy
#Set-ADDefaultDomainPasswordPolicy -Identity $Domain -AuthType Basic -Credential $AdminCredentials -MaxPasswordAge 60.00:00:00 -MinPasswordAge 1.00:00:00 -PasswordHistoryCount 24 -ComplexityEnabled $true -ReversibleEncryptionEnabled $true -MinPasswordLength 14

#this does not error out
Set-ADDefaultDomainPasswordPolicy -Identity $Domain -AuthType Negotiate -MaxPasswordAge 60.00:00:00 -MinPasswordAge 1.00:00:00 -PasswordHistoryCount 24 -ComplexityEnabled $true -ReversibleEncryptionEnabled $true -MinPasswordLength 14
Set-GPRegistryValue -Guid (Get-GPO -Name "Default Domain Policy").id -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "MinEncryptionLevel" -Value 3 -Type "DWORD"
Set-GPLink -Guid (Get-GPO -Name "Default Domain Policy").id -Target $target -LinkEnabled Yes -Enforced Yes

Get-GPRegistryValue -Guid (Get-GPO -Name "Default Domain Policy").id
#all users in the AD should change password at next logon- only keep this as an option
<#
$users= get-aduser -Filter *
ForEach($user in $users)
    {
       Set-ADUser -PasswordNeverExpires $False -ChangePasswordAtLogon $True -Identity $user -Confirm:$false -WhatIf:$false -ErrorAction Stop
                Write-Verbose -Message 'Change password at logon set to True'
    }
#>
