#requires -RunAsAdministrator
#requires -Modules AzureRM

################################################################################################################
### Verify Environment ###
################################################################################################################

# Verify AzureRM Module is installed
if (Get-Module -ListAvailable -Name AzureRM) {
    Write-Host "AzureRM Module exists... Importing into session." -ForegroundColor Yellow
    Import-Module AzureRM
} 
else {
    Write-Host "AzureRM Module will be installed from the PowerShell Gallery..." -ForegroundColor Yellow
    Install-Module -Name AzureRM -Force
    Import-Module -Name AzureRM
}

<#

.Description
This script will create backup entries for protected items in the Azure Recovery Services Vault created during deployment. The script will query Azure for running VMs within a defined resource group (where the VMs have already been processed for Azure VM Encryption), and create backup entries for the protected items before triggering the initial backup.  

#>

Write-Host "`n `nAzure Security and Compliance Blueprint - FedRAMP Web Applications Automation - Post-Deployment Script `n" -foregroundcolor green
Write-Host "This script can be used for running post-deployment tasks for a multi-tier web application architecture with pre-configured security controls to help customers achieve compliance with FedRAMP requirements. See https://aka.ms/fedrampblueprint for more information. `n " -foregroundcolor yellow

########################################################################################################################
# LOGIN TO AZURE FUNCTION
########################################################################################################################
function loginToAzure {
	Param(
		[Parameter(Mandatory=$true)]
		[int]$lginCount
	)

	Write-Host "Please login using Azure Government credentials." -ForegroundColor Yellow
	
	Login-AzureRmAccount -EnvironmentName "AzureUSGovernment" -ErrorAction SilentlyContinue 	

	if($?) {
		Write-Host "Login Successful!" -ForegroundColor Green
	} 
        else {
		if($lginCount -lt 3) {
			$lginCount = $lginCount + 1
			Write-Host "Invalid Credentials! Please try logging in again." -ForegroundColor Magenta
			loginToAzure -lginCount $lginCount
		} 
                else {
			Write-Host "Credentials input are incorrect, invalid, or exceed the maximum number of retries. Verify the Azure Government account information used is correct." -ForegroundColor Magenta
			Write-Host "Press any key to exit..." -ForegroundColor Yellow
			$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			Exit
		}
	}
}

########################################################################################################################
# Generate Backup Items 
########################################################################################################################
try {
    loginToAzure -lginCount 1
    Write-Host "`n GENERATE VM BACKUP ITEMS `n" -foregroundcolor green
    Write-Host "Generating Backup Items for the deployment." -ForegroundColor Yellow

    # Resource Group and Key Vault Names
    $KeyVault = Read-Host "The name of the Key Vault used in the deployment"
    $ResourceGroup = Read-Host "Provide the name of the Resource Group deployed"
    $VMList = @("AZ-PDC-VM", "AZ-BDC-VM", "AZ-WEB-VM0", "AZ-WEB-VM1", "AZ-SQL-VM0", "AZ-SQL-VM1", "AZ-MGT-VM")

    # Set appropriate Recovery Services Vault context
    Get-AzureRmRecoveryServicesVault -Name "AZ-RCV-01" -ResourceGroupName $ResourceGroup | Set-AzureRmRecoveryServicesVaultContext

    # Initialize Recovery Services Vault for new AzureRM registration - Check for and remove old backup containers
    Get-AzureRmRecoveryServicesVault -ResourceGroupName $ResourceGroup | Set-AzureRmRecoveryServicesVaultContext
    $rcs = Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM -ResourceGroupName $ResourceGroup -BackupManagementType AzureVM -Status Registered
    if ($rcs) {
        Write-Host "`nAzureRM backup containers found... Initializing vault..." -ForegroundColor Yellow
        foreach ($c in $rcs) {
            $bi = Get-AzureRmRecoveryServicesBackupItem -Container $c -WorkloadType AzureVM
            try {
                Disable-AzureRmRecoveryServicesBackupProtection -Item $bi -RemoveRecoveryPoints -Force
            }
            catch {
                Write-Host $PSItem.Exception.Message
                Write-Host "An error has occurred while attemping to initialize AzureRM vault" -ForegroundColor Magenta
                $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Exit
            }
               
        } 
    }

    # Registering AzureVM protected items for backup
    Set-AzureRmKeyVaultAccessPolicy -VaultName $KeyVault -ResourceGroupName $ResourceGroup -PermissionsToKeys backup,get,list -PermissionsToSecrets get,list -ServicePrincipalName ff281ffe-705c-4f53-9f37-a40e6f2c68f3
    $policy = Get-AzureRmRecoveryServicesBackupProtectionPolicy -Name "FedRAMPBackup"
    
    foreach ($VM in $VMList) {
    	try {
            Enable-AzureRmRecoveryServicesBackupProtection -Policy $policy -Name $VM -ResourceGroupName $ResourceGroup
	}
	catch {
            Write-Host $PSItem.Exception.Message
            Write-Host "An error has occurred while attemping to connect $VM" -ForegroundColor Magenta
            $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Exit
        }
    }
    Write-Host "Generation of VM Backup Items completed successfully." -ForegroundColor green
}

catch {
	Write-Host $PSItem.Exception.Message
	Write-Host "An error has occurred in generating VM backup items. Please review any error messages for resolution." -ForegroundColor Magenta
	Write-Host "Press any key to exit..." -ForegroundColor Yellow
	$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	Exit    
}

########################################################################################################################
# Pull Registered Backup Items and Trigger Initial Backup
########################################################################################################################

try {
    Write-Host "`n CREATE INITIAL VM BACKUP `n" -foregroundcolor green
    Write-Host "Starting Initial Backup for all VMs in the deployment" -ForegroundColor Yellow
    # Pull Registered Backup Items 
    $BackupContainer = Get-AzureRmRecoveryServicesBackupContainer -ContainerType "AzureVM" -Status "Registered" 

    # Trigger Initial Backup
    foreach ($Backup in $BackupContainer) {
        $BackupItem = Get-AzureRmRecoveryServicesBackupItem -Container $Backup -WorkloadType "AzureVM"
        $job = Backup-AzureRmRecoveryServicesBackupItem -Item $BackupItem
    }
    Write-Host "Initial Backup is starting for all VMs." -ForegroundColor green
}

catch {
    Write-Host $PSItem.Exception.Message
	Write-Host "An error has occurred in completing the initial backup of VM assets. Please review any error messages for resolution." -ForegroundColor Magenta
	Write-Host "Press any key to exit..." -ForegroundColor Yellow
	$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	Exit
}

########################################################################################################################
# Post-Deployment
########################################################################################################################

try {
    # Post-Deployment
    Write-Host "`n POST-DEPLOYMENT COMPLETE `n" -foregroundcolor green
    Write-Host "Post-Deployment operations for this blueprint template are complete. Please proceed with validating the deployed resources through the Azure Portal. Additional information regarding this blueprint is accessible at https://aka.ms/fedrampblueprint." -foregroundcolor Yellow
}

catch {
	Write-Host $PSItem.Exception.Message
	Write-Host "An error has occurred in post-deployment for this blueprint. Please review any error messages for resolution." -ForegroundColor Magenta
	Write-Host "Press any key to exit..." -ForegroundColor Yellow
	$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	Exit
}
