## Solution overview

For more information about this solution, see [
Azure Security and Compliance Blueprint - FedRAMP Web Applications Automation](https://aka.ms/fedrampblueprint).

## Deploy the solution

This Azure Blueprint solution is comprised of JSON configuration files and PowerShell scripts that are handled by Azure Resource Manager's API service to deploy resources within Azure. ***Note: This solution deploys to Azure Government.***

### Quickstart
1. Clone or download this repository to run from a local workstation.

2. Run the pre-deployment PowerShell script: **/predeploy/Orchestration_InitialSetup.ps1** [Read more about pre-deployment.](#pre-deployment)

3. Click the button below, sign into the Azure portal, enter the required ARM template parameters, and click **Purchase**. [Read more about deployment.](#deployment)

	[![Deploy to Azure](http://azuredeploy.net/AzureGov.png)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2Ffedramp-iaas-webapp%2Fmaster%2Fazuredeploy.json)
	
4. When the deployment completes, there is a post-deployment script in the repository for registering and initiating initial backup. This step can be completed before or after configuring the VM environment for the application to be deployed into the environment.

### Pre-deployment

During pre-deployment, confirm that an Azure Government subscription and local workstation are prepared to deploy the solution. The final pre-deployment step is running a PowerShell orchestration script that verifies the setup requirements, gathers parameters and credentials, and creates resources in Azure to prepare for deployment.

#### Azure subscription requirements

This Azure Blueprint solution is designed to deploy to Azure Government. The solution does not currently support Azure commercial regions. For users with multi-tenant environments, the account used to deploy must be a member of the Azure Active Directory instance that is associated with the subscription where this blueprint solution will be deployed.

#### Local workstation requirements

PowerShell is utilized to initiate pre-deployment tasks. PowerShell version 5.0 or greater must be installed on the local workstation deploying this blueprint. In PowerShell, use the following command to verify the installed PowerShell version:

`$PSVersionTable.psversion`

In order to run the pre-deployment script, the current Azure PowerShell AzureRM modules must be installed on the local workstation (see [Installing AzureRM modules](https://docs.microsoft.com/powershell/azure/install-azurerm-ps)). The pre-deployment script will verify if an AzureRM PowerShell module is installed.   

The local workstation's PowerShell execution policy will need to be set to `RemoteSigned` or `Unrestricted` to execute the pre-deployment script. Click [here](https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies) for information about PowerShell execution policies and detailed instructions.

To clone this repository using the command line, a [Git client](https://git-scm.com/downloads) must be available on the local workstation. Alternatively, the repository can be downloaded directly from GitHub.

#### SSL certificate
This solution deploys an Application Gateway which requires an SSL certificate. The pre-deployment script will generate a self-signed SSL certificate after prompting for a domain (e.g., `contoso.local`). Note that self-signed certificates are not recommended for use in production environments.

#### Pre-deployment script

The pre-deployment PowerShell script will verify that the necessary Azure PowerShell modules are installed. Azure PowerShell modules provide cmdlets for managing Azure resources. After all the setup requirements are verified, the script will ask users to sign into Azure and will then prompt for parameters and credentials to use when the solution is deployed. The script will prompt for the following parameters, in this order:

* **Admin Username**: Administrator username for use as the administrator account on deployed virtual machines.
* **Admin Password**: Administrator password for use with the administrator account on deployed virtual machines. Passwords must be at least 14 characters and contain one each of the following: lower case character, upper case character, number, and special character.
* **Domain Name**: Domain name for the self-signed SSL certificate. Domain names utilized for this blueprint must adhere to RFC 1123 and NetBIOS (e.g., `contoso.local`).
* **Azure Government Subscription ID**: Azure Government subscription ID details can be found in the Azure Government portal. Navigate to https://portal.azure.us and sign in. Expand the service menu on the left side of the portal, select "more services," and begin typing "subscription" in the filter box. Click **Subscriptions** to open the subscriptions blade. Note the subscription ID, which has the GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
* **Resource Group Name**: The resource group name for use with this deployment; must be a string of 1-90 alphanumeric characters (such as 0-9, a-z, A-Z), periods, underscores, hyphens, and parenthesis and it cannot end in a period (e.g., `blueprint-rg`). 
	* **Key Vault Name**: The Key Vault name will be automatically generated from the **Resource Group Name** parameter, as the deployment cannot use an existing Key Vault resource for this blueprint (e.g., `blueprint-rg-KV`). 

#### Pre-deployment instructions

1. Clone or download this GitHub repository to the local workstation.
	- `git clone https://github.com/Azure/fedramp-iaas-webapp.git`
2. Start PowerShell with administrative privileges.
3. Run **Orchestration_InitialSetup.ps1**, found in the predeploy directory.
4. When prompted, enter the parameters described above.

Note the resource group name, Key Vault name, and domain name used as these will be required during the deployment phase.

### Deployment

During this phase, an Azure Resource Manager (ARM) template will deploy Azure resources to the selected subscription and perform configuration activities.

After clicking the **Deploy to Azure Gov** button, the Azure portal will open and prompt users for the following settings:

**Basics**
* **Subscription**: Choose the same subscription used during the pre-deployment phase.
* **Resource group**: Select **Use existing** and choose the resource group created during pre-deployment.
* **Location**: Verify **USGovVirginia** is selected by default.  
	***Note: This solution must be deployed in the USGovVirginia region due to service availability.***

**Settings**
* **Key Vault Name**: Name of the Key Vault created during pre-deployment.
* **Key Vault Resource Group Name**: Name of the resource group created during pre-deployment.

All other settings contain default values that may be optionally adjusted by users.

#### Deployment instructions

1. Click the button below.

	[![Deploy to Azure](http://azuredeploy.net/AzureGov.png)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2Ffedramp-iaas-webapp%2Fmaster%2Fazuredeploy.json)
2. Enter the settings described above.
3. Review the terms and conditions and click **I agree to the terms and conditions stated above**.
4. Click **Purchase**.

#### Monitoring deployment status
This solution uses multiple nested templates to deploy and configure the resources shown in the architecture diagram. The full deployment will take approximately 120 minutes. The deployment can be monitored from the Azure portal. When complete, there will be 35 individual deployments to the resource group with a total of 49 deployed resources. If deployment errors are encountered, check the [troubleshooting](#troubleshooting) section below.

### Post-deployment

#### Accessing deployed resources

Deployed VMs are accessible through the MGT VM that is created from the deployment. From this VM, any deployed VM from this blueprint solution will be remotely accessible. The default name of the MGT VM is **AZ-MGT-VM**.

#### Initial backup

After successful deployment of this blueprint, users can opt to run the **PostDeployment.ps1** script found in the **/postdeploy** directory for initializing encrypted VM backups into the Azure Recovery Services Vault deployed with the blueprint solution. 

Initial backup can be run immediately after the deployment finishes successfully. Alternatively, users can select to run initial backup after the environment is configured for the application that will be used with this blueprint. 

#### Cost

Deploying this solution will create resources within the selected Azure subscription. Users will be responsible for the costs associated with these resources, so it is important to review applicable pricing and legal terms associated with all the resources and offerings deployed as part of this solution. For cost estimates, the [Azure Pricing Calculator](https://azure.microsoft.com/en-us/pricing/calculator/) can be used.

#### Extending the solution with advanced configuration

For users with working knowledge of using Azure Resource Manager (ARM) templates, the deployment can be customized by editing  azuredeploy.json or any of the templates located in the nested templates folder. Some items users may want to edit include, but are not limited to:
- Network security group rules (nestedtemplates/virtualNetworkNSG.json)
- OMS alert rules and configuration (nestedtemplates/provisioningAutoAccOMSWorkspace)
- Application Gateway routing rules (nestedtemplates/provisioningApplicationGateway.json)
- Adding a DB to the SQL Server 2017 AlwaysOn Availability Group (externaltemplates/AddDBtoAG.json)

Additional documentation regarding template deployment is available at the following links:

- [Azure Resource Manager Templates](https://docs.microsoft.com/azure/azure-resource-manager/resource-group-overview#template-deployment)
- [ARM Template Functions](https://docs.microsoft.com/azure/azure-resource-manager/resource-group-template-functions)
- [ARM Templating and Nesting Resources](https://docs.microsoft.com/azure/azure-resource-manager/resource-group-linked-templates)

#### Troubleshooting
- #### Failed deployment
	- If the deployment should fail, first attempt to re-deploy the solution.
		- Open the Resource groups blade in the Azure portal, select the appropriate resource group, click on Deployments, click on `Microsoft.Template` deployment, then click the redeploy button.
 	- If further issues are encountered, to avoid incurring costs and orphaned resources, it is advised to delete the resource group and all resources associated with the failed deployment. See the section below for instructions on deleting all resources deployed by the solution.
- #### Login delay
	If any of the deployed VMs hang at login, presenting **please wait for the user profile service**, restart affected VMs through the Azure portal. This will effectively restart the user profile service, if the service is timing out.

- #### Known issues
	- There is a known bug when initializing backups for this solution. If Azure reports a missing `Microsoft Visual C++ Redistributable` for any VM, attempt to initiate backup through the deployed Azure Recovery Services Vault from the Azure portal.   
	- For reporting bugs, users may submit a GitHub issue pertaining to the errors experienced.

- #### Template customization
	Be very mindful of edits made to the JSON templates, as that can affect the integrity of the blueprint deployment. Editing the templates is recommended only for users familiar with Azure Resource Manager deployments.  

#### How to delete deployed resources

To help with deleting protected resources, use the **custom-scripts/deleteProtectedItems.ps1** script if the **postdeploy/PostDeployment.ps1** script has been executed for creating the initial recovery point. This PowerShell script will remove any deletion locks on the resources inside the deployed Recovery Services Vault. Note that the script needs to be edited to include the selected subscription ID. The default Recovery Service Vault name of 'AZ-RCV-01' is already set in the script. 

If only the deployment has been run, with no backup operations executed through the post-deployment script, only the resource group deployed needs to be deleted for removing deployed resources.  

## Disclaimer

- This document is for informational purposes only. MICROSOFT MAKES NO WARRANTIES, EXPRESS, IMPLIED, OR STATUTORY, AS TO THE INFORMATION IN THIS DOCUMENT. This document is provided "as-is." Information and views expressed in this document, including URL and other internet website references, may change without notice. Customers reading this document bear the risk of using it.  
- This document does not provide customers with any legal rights to any intellectual property in any Microsoft products or solutions.  
- Customers may copy and use this document for internal reference purposes.  
- Certain recommendations in this document may result in increased data, network, or compute resource usage in Azure, and may increase a customer's Azure license and/or subscription costs.  
- This architecture is intended to serve as a foundation for customers to adjust to their specific requirements and should not be used as-is in a production environment.
- This document is developed as a reference and should not be used to define all means by which a customer can meet specific compliance requirements and regulations. Customers should seek legal support from their organization on approved compliant customer implementations.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
