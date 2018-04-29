Set-ExecutionPolicy Unrestricted
Import-Module ActiveDirectory
## Not A Policy
## Get inactive accounts that have been inactive for at least 35 days
`$inactiveacc= Search-ADAccount -AccountInactive -TimeSpan 35
Foreach(`$acc in `$inactiveacc)
  {
    Get-ADUser -Filter 'Name -Like `$acc.Name' |Disable-ADAccount
  }
