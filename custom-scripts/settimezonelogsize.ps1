Invoke-Expression "tzutil.exe /s ""UTC"""


$Logs = Get-Eventlog -List |ForEach {
Limit-Eventlog -Logname $_.Log -MaximumSize 64000Kb
}
