## This Deletes all protected item Containers and Recovery Points for an array of Recovery Services Vaults.
## If you do not want to delete all protected items in the vaults then the script will need to be adjust to filter only the specified items

Import-Module AzureRm
Add-AzureRmAccount -EnvironmentName AzureUSGovernment


Select-AzureRmSubscription -SubscriptionId "<enter your azure subscription here>"

$rcvNames = @("<enter the name of the recovery services vault you want to delete")

for($i=0;$i -lt $rcvNames.Length;$i++){
    $vaults = Get-AzureRmRecoveryServicesVault | ?{$_.Name -eq $rcvNames[$i]}
    for($j=0;$j -lt $vaults.Length;$j++){
      Set-AzureRmRecoveryServicesVaultContext -Vault $vaults[$j]

      $containers = Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM -BackupManagementType AzureVM
      $containers | %{
          $item = Get-AzureRmRecoveryServicesBackupItem -Container $_ -WorkloadType AzureVM
          Disable-AzureRmRecoveryServicesBackupProtection -Item $item -RemoveRecoveryPoints -Force -Verbose
      }
    }
}
