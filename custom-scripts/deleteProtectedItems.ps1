## This deletes all protected item containers and recovery points for an array of Recovery Services Vaults.

Import-Module AzureRm
Add-AzureRmAccount -EnvironmentName AzureUSGovernment

## Enter Azure Subscription ID
Select-AzureRmSubscription -SubscriptionId "<enter your azure subscription here>"

## AZ-RCV-01 is the default name of the Recovery Services Vault deployed. 
## To remove protected items from a different Recovery Services Vault or additional vaults, edit/add Recovery Service Vault names in the $rcvNames variable below.
$rcvNames = @("AZ-RCV-01")

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