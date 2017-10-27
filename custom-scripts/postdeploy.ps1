#Requires -Module AzureRM

<#
    This is a temporary fix for VMS extersion failure on the Microsoft.EnterpriseCloud.Monitoring.    
#>
 param
    (
        [parameter(mandatory = $true)][ValidateNotNullOrEmpty()][String]$ResourceGroupName,
        [parameter(mandatory = $true)][ValidateNotNullOrEmpty()][String]$WorkspaceName,        
        [parameter(mandatory = $true)][ValidateNotNullOrEmpty()][PSCredential]$AzureAuthCreds,
        [parameter(mandatory = $true)][ValidateNotNullOrEmpty()][String]$SubscriptionId,
        [String]$EnvironmentName="AzureUSGovernment"
    )

    Import-Module -Name AzureRM

    Login-AzureRmAccount -EnvironmentName $EnvironmentName -Credential $AzureAuthCreds    

    if($SubscriptionId)
    {
        Select-AzureRmSubscription -SubscriptionId $SubscriptionId;
    }  

    Write-Output "Getting VMs ..." 
     $rmvms=Get-AzureRmVM | Where-Object {$_.ResourceGroupName -eq $ResourceGroupName }

     foreach ($vm in $rmvms) 
     {
        try{
            $MachineName = $vm.Name

            Write-Output "Updating $MachineName ..." 
            $cloudMonitoring =Get-AzureRmVMExtension -ResourceGroupName $ResourceGroupName -VMName $MachineName -Name "EnterpriseCloudMonitoring" -Status
            $status = $cloudMonitoring.ProvisioningState    

            if($status -eq "Failed"){
                Remove-AzureRmVMExtension -ResourceGroupName $ResourceGroupName -VMName $MachineName -Name "EnterpriseCloudMonitoring" -Force        

                $Workspace = Get-AzureRmOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName  -ErrorAction Stop
                $OmsLocation = $Workspace.Location
                # Get the workspace ID
                $WorkspaceId = $Workspace.CustomerId

                # Get the primary key for the OMS workspace
                $WorkspaceSharedKeys = Get-AzureRmOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
                $WorkspaceKey = $WorkspaceSharedKeys.PrimarySharedKey

                $PublicSettings = @{"workspaceId" = $WorkspaceId }
                $ProtectedSettings = @{"workspaceKey" = $WorkspaceKey}

                Set-AzureRmVMExtension -ExtensionName "EnterpriseCloudMonitoring" -ResourceGroupName $ResourceGroupName -VMName $MachineName -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -TypeHandlerVersion 1.0 -Settings $PublicSettings -ProtectedSettings $ProtectedSettings -Location $OmsLocation
                 Write-Output "Update $MachineName completed!" 
        }
        }
        catch{

        }
     }