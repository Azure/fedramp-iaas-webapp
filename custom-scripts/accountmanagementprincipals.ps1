Set-ExecutionPolicy Unrestricted
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
#>
