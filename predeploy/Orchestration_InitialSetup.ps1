#requires -RunAsAdministrator
#requires -Modules AzureRM

################################################################################################################
### Verify Environment ###
################################################################################################################

# Verify AzureRM Module is installed
if (Get-Module -ListAvailable -Name AzureRM) {
    Write-Host "AzureRM Module exists... Importing into session"
    Import-Module AzureRM
    } 
    else {
        Write-Host "AzureRM Module will be installed from the PowerShell Gallery"
        Install-Module -Name AzureRM -Force
    }

<#
.Description
This script will create a Key Vault with a Key Encryption Key for VM DIsk Encryption and Azure AD Application Service Principal inside a specified Azure subscription

.Parameter adminUsername
Name of the local admin credentials for all VM's to be created.
(This value cannot be 'admin')

.Parameter adminPassword
Must meet complexity requirements
14+ characters, 2 numbers, 2 upper and lower case, and 2 special chars

.Parameter sqlServerServiceAccountPassword
Must meet complexity requirements
14+ characters, 2 numbers, 2 upper and lower case, and 2 special chars

.Parameter domain
Must be the Domain name to be created 
Example: contoso.local

#>

Write-Host "`n `nAzure Blueprint Automation: Web Applications for FedRAMP - Pre-Deployment Script `n" -foregroundcolor green
Write-Host "This script can be used for creating the necessary preliminary resources to deploy a multi-tier web application architecture with pre-configured security controls to help customers achieve compliance with FedRAMP requirements. See https://aka.ms/fedrampblueprint for more information. `n " -foregroundcolor yellow

Write-Host "`n LOGIN TO AZURE `n" -foregroundcolor green
$global:azureUsername = $null
$global:azurePassword = $null


########################################################################################################################
# LOGIN TO AZURE FUNCTION
########################################################################################################################
function loginToAzure {
	Param(
			[Parameter(Mandatory=$true)]
			[int]$lginCount
	)

	$global:azureUsername = Read-Host "Enter your Azure username"
	$global:azurePassword = Read-Host -assecurestring "Enter your Azure password"


	$AzureAuthCreds = New-Object System.Management.Automation.PSCredential -ArgumentList @($global:azureUsername,$global:azurePassword)
	$azureEnv = Get-AzureRmEnvironment -Name $EnvironmentName
	Login-AzureRmAccount -EnvironmentName "AzureUSGovernment" -Credential $AzureAuthCreds

	if($?) {
		Write-Host "Login successful!"
	} 
    else {
		if($lginCount -lt 3) {
			$lginCount = $lginCount + 1
			Write-Host "Invalid Credentials! Try Logging in again"
			loginToAzure -lginCount $lginCount
		} 
        else {
			Throw "Your credentials are incorrect or invalid exceeding maximum retries. Make sure you are using your Azure Government account information"
		}
	}
}

########################################################################################################################
# KEY VAULT NAME VALIDATION FUNCTION
########################################################################################################################
function checkKeyVaultName {
    Param(
		[Parameter(Mandatory=$true)]
		[string]$keyVaultName
	)
    $firstchar = $keyVaultName[0]
    if ($firstchar -match '^[0-9]+$') {
        $keyVaultNew = Read-Host "KeyVault name can't start with numeric value, Enter keyVaultName"
        checkKeyVaultName -keyVaultName $keyVaultNew
        return;
    }
    return $keyVaultName;
}

########################################################################################################################
# ADMIN USERNAME VALIDATION FUNCTION
########################################################################################################################
function checkAdminUserName {
    $username = Read-Host "Enter an admin username"
    if ($username.ToLower() -eq "admin") {
        Write-Host "Not a valid Admin username, please select another"  
        checkAdminUserName
        return
    }
    return $username
}

########################################################################################################################
# PASSWORD VALIDATION FUNCTION
########################################################################################################################
function checkPasswords {
	Param(
		[Parameter(Mandatory=$true)]
		[string]$name
	)
	$password = Read-Host -assecurestring "Enter $($name)"
    $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($password)
    $pw2test = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
	$passLength = 14
	$isGood = 0
	if ($pw2test.Length -ge $passLength) {
		$isGood = 1
        if ($pw2test -match " ") {
          "Password does not meet complexity requirements. Password cannot contain spaces"
          checkPasswords -name $name
          return
        } 
        else {
          $isGood = 2
        }
        if ($pw2test -match "[^a-zA-Z0-9]") {
			    $isGood = 3
        } 
        else {
            "Password does not meet complexity requirements. Password must contain a special character"
            checkPasswords -name $name
            return
        }
	    if ($pw2test -match "[0-9]") {
			    $isGood = 4
        } 
        else {
            "Password does not meet complexity requirements. Password must contain a numerical character"
            checkPasswords -name $name
            return
        }
	    if ($pw2test -cmatch "[a-z]") {
	        $isGood = 5
        } 
        else {
            "Password must contain a lowercase letter"
            "Password does not meet complexity requirements"
            checkPasswords -name $name
            return
        }
	    if ($pw2test -cmatch "[A-Z]") {
	        $isGood = 6
        } 
        else {
            "Password must contain an uppercase character"
            "Password does not meet complexity requirements"
            checkPasswords -name $name
        }
	    if ($isGood -ge 6) {
            $passwords | Add-Member -MemberType NoteProperty -Name $name -Value $password
            return
        } 
        else {
            "Password does not meet complexity requirements"
            checkPasswords -name $name
            return
        }
    } 
    else {
    "Password is not long enough - Passwords must be at least " + $passLength + " characters long"
    checkPasswords -name $name
    return
    }
}

########################################################################################################################
# GENERATE RANDOM PASSWORD FOR CERT FUNCTION
########################################################################################################################
Function New-RandomPassword() {
    [CmdletBinding()]
    param(
        [int]$Length = 14
    )
    $ascii=$NULL;For ($a=33;$a -le 126;$a++) {$ascii+=,[char][byte]$a}
    for ($loop=1; $loop -le $length; $loop++) {
        $RandomPassword+=($ascii | GET-RANDOM)
    }
    return $RandomPassword
}

function Generate-Cert() {
	[CmdletBinding()]
	param(
    [securestring]$certPassword,
	[string]$domain
    )
		## This script generates a self-signed certificate
		$filePath = ".\"
		$cert = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $domain
		$path = 'cert:\localMachine\my\' + $cert.thumbprint
		$certPath = $filePath + '\cert.pfx'
		$outFilePath = $filePath + '\cert.txt'
		Export-PfxCertificate -cert $path -FilePath $certPath -Password $certPassword
		$fileContentBytes = get-content $certPath -Encoding Byte
		[System.Convert]::ToBase64String($fileContentBytes) | Out-File $outFilePath
}

########################################################################################################################
# Create KeyVault or setup existing keyVault
########################################################################################################################
function orchestration {
	Param(
		[string]$environmentName = "AzureUSGovernment",
		[string]$location = "USGov Virginia",
		[Parameter(Mandatory=$true)]
		[string]$subscriptionId,
		[Parameter(Mandatory=$true)]
		[string]$azureUsername,
		[Parameter(Mandatory=$true)]
		[SecureString]$azurePassword,
		[Parameter(Mandatory=$true)]
		[string]$resourceGroupName,
		[Parameter(Mandatory=$true)]
		[string]$keyVaultName,
		[Parameter(Mandatory=$true)]
		[string]$adminUsername,
		[Parameter(Mandatory=$true)]
		[SecureString]$adminPassword,
		[Parameter(Mandatory=$true)]
		[SecureString]$sqlServerServiceAccountPassword,
		[Parameter(Mandatory=$true)]
		[string]$domain
	)
	$errorActionPreference = 'stop'
    $keyVaultName = checkKeyVaultName -keyVaultName $keyVaultName;
	try {
		$Exists = Get-AzureRmSubscription  -SubscriptionId $SubscriptionId
		Write-Host "Using existing authentication"
	}
	catch {}
	if (-not $Exists) {
		Write-Host "Authenticate to Azure subscription"
		Add-AzureRmAccount -EnvironmentName $EnvironmentName | Out-String | Write-Verbose
	}
	Write-Host "Selecting subscription as default"
	Select-AzureRmSubscription -SubscriptionId $SubscriptionId | Out-String | Write-Verbose

	    # Create AAD app . Fill in $aadClientSecret variable if AAD app was already created
        $guid = [Guid]::NewGuid().toString();
        $aadAppName = "Blueprint" + $guid ;
		# Check if AAD app with $aadAppName was already created
		$SvcPrincipals = (Get-AzureRmADServicePrincipal -SearchString $aadAppName);
		if(-not $SvcPrincipals) {
			# Create a new AD application if not created before
			$identifierUri = [string]::Format("http://localhost:8080/{0}",[Guid]::NewGuid().ToString("N"));
			$defaultHomePage = 'http://contoso.com';
			$now = [System.DateTime]::Now;
			$oneYearFromNow = $now.AddYears(1);
			$aadClientSecret = [Guid]::NewGuid() | ConvertTo-SecureString -AsPlainText -force;

			Write-Host "Creating new AAD application ($aadAppName)";
			$ADApp = New-AzureRmADApplication -DisplayName $aadAppName -HomePage $defaultHomePage -IdentifierUris $identifierUri  -StartDate $now -EndDate $oneYearFromNow -Password $aadClientSecret;
			$servicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $ADApp.ApplicationId;
			$SvcPrincipals = (Get-AzureRmADServicePrincipal -SearchString $aadAppName);
			if(-not $SvcPrincipals)
			{
					# AAD app wasn't created
					Write-Error "Failed to create AAD app $aadAppName. Please log-in to Azure using Login-AzureRmAccount  and try again";
					return;
			}
			$aadClientID = $servicePrincipal.ApplicationId;
			Write-Host "Created a new AAD Application ($aadAppName) with ID: $aadClientID ";
		}
		else {
			if(-not $aadClientSecret) {
				$aadClientSecret = Read-Host -Prompt "Aad application ($aadAppName) was already created, input corresponding aadClientSecret and hit ENTER. It can be retrieved from https://manage.windowsazure.com portal" ;
			}
			if(-not $aadClientSecret) {
				Write-Error "Aad application ($aadAppName) was already created. Re-run the script by supplying aadClientSecret parameter with corresponding secret from https://manage.windowsazure.com portal";
				return;
			}
			$aadClientID = $SvcPrincipals[0].ApplicationId;
		}

	# Create KeyVault or setup existing keyVault
	Write-Host "Creating resource group '$($resourceGroupName)' to hold key vault"
	if (-not (Get-AzureRmResourceGroup -Name $resourceGroupName -Location $location -ErrorAction SilentlyContinue)) {
		New-AzureRmResourceGroup -Name $resourceGroupName -Location $location  | Out-String | Write-Verbose
	}

	#Create a new vault if vault doesn't exist
	if (-not (Get-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue )) {
		Write-Host "Create a keyVault '$($keyVaultName)' to store the service principal ids and passwords"
		New-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -EnabledForTemplateDeployment -Location $location | Out-String | Write-Verbose
		Write-Host "Created a new KeyVault named $keyVaultName to store encryption keys";

		# Specify privileges to the vault for the AAD application - https://msdn.microsoft.com/en-us/library/mt603625.aspx
		Write-Host "Set Azure Key Vault Access Policy."
		Write-Host "Set ServicePrincipalName: $aadClientID in Key Vault: $keyVaultName";
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ServicePrincipalName $aadClientID -PermissionsToKeys wrapKey -PermissionsToSecrets set;
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ServicePrincipalName $aadClientID -PermissionsToKeys backup,get,list,wrapKey -PermissionsToSecrets get,list,set;
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -EnabledForDiskEncryption;
        $keyEncryptionKeyName = $keyVaultName + "kek"

		if($keyEncryptionKeyName) {
			try {
			    $kek = Get-AzureKeyVaultKey -VaultName $keyVaultName -Name $keyEncryptionKeyName -ErrorAction SilentlyContinue;
			}
			catch [Microsoft.Azure.KeyVault.KeyVaultClientException] {
				Write-Host "Couldn't find key encryption key named : $keyEncryptionKeyName in Key Vault: $keyVaultName";
				$kek = $null;
			}
			if(-not $kek) {
				Write-Host "Creating new key encryption key named:$keyEncryptionKeyName in Key Vault: $keyVaultName";
				$kek = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name $keyEncryptionKeyName -Destination Software -ErrorAction SilentlyContinue;
				Write-Host "Created  key encryption key named:$keyEncryptionKeyName in Key Vault: $keyVaultName";
			}
			$keyEncryptionKeyUrl = $kek.Key.Kid;
		}

		$certPassword = New-RandomPassword
		$secureCertPassword = ConvertTo-SecureString $certPassword -AsPlainText -Force
		Generate-Cert -certPassword $secureCertPassword -domain $domain
		$certificate = Get-Content -Path ".\cert.txt" | Out-String

		Write-Host "Set Azure Key Vault Access Policy. Set adminUsername in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'adminUsername' -Destination 'Software'
		$adminUsernameSecureString = ConvertTo-SecureString $adminUsername -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminUsername' -SecretValue $adminUsernameSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set AdminPassword in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'adminPassword' -Destination 'Software'
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminPassword' -SecretValue $adminPassword

		Write-Host "Set Azure Key Vault Access Policy. Set SqlServerServiceAccountPassword in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sqlServerServiceAccountPassword' -Destination 'Software'
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sqlServerServiceAccountPassword' -SecretValue $sqlServerServiceAccountPassword

		Write-Host "Set Azure Key Vault Access Policy. Set sslCert in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sslCert' -Destination 'Software'
		$sslCertSecureString = ConvertTo-SecureString "$certificate" -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sslCert' -SecretValue $sslCertSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set sslCertPassword in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sslPassword' -Destination 'Software'
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sslPassword' -SecretValue $secureCertPassword

		Write-Host "Set Azure Key Vault Access Policy. Set domain in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'domain' -Destination 'Software'
		$domainSecureString = ConvertTo-SecureString $domain -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'domain' -SecretValue $domainSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set guid in Key Vault: $keyVaultName";
		$guid = new-guid
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'guid' -Destination 'Software'
		$guidSecureString = ConvertTo-SecureString $guid -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'guid' -SecretValue $guidSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set Application Client ID in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadClientID' -Destination 'Software'
		$aadClientIDSecureString = ConvertTo-SecureString $aadClientID -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientID' -SecretValue $aadClientIDSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set Application Client Secret in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadClientSecret' -Destination 'Software'
		$aadClientSecretSecureString = ConvertTo-SecureString $aadClientSecret -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientSecret' -SecretValue $aadClientSecretSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set Key Encryption URL in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -Destination 'Software'
		$keyEncryptionKeyUrlSecureString = ConvertTo-SecureString $keyEncryptionKeyUrl -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -SecretValue $keyEncryptionKeyUrlSecureString
	}

}

########################################################################################################################
# Run Pre-Deployment and Orchestration
########################################################################################################################

try {
	loginToAzure -lginCount 1
	Write-Host "You will now be asked to create credentials for the administrator and sql service accounts. `n"
	Write-Host "`n CREATE CREDENTIALS `n" -foregroundcolor green
    $adminUsername = checkAdminUserName
	$passwordNames = @("adminPassword","sqlServerServiceAccountPassword")
	$passwords = New-Object -TypeName PSObject
	for ($i=0;$i -lt $passwordNames.Length;$i++) {
	   checkPasswords -name $passwordNames[$i]
	}
	orchestration -azureUsername $global:azureUsername -adminUsername $adminUsername -azurePassword $global:azurePassword -adminPassword $passwords.adminPassword -sqlServerServiceAccountPassword $passwords.sqlServerServiceAccountPassword
    Write-Host "`n ORCHESTRATION COMPLETE `n" -foregroundcolor green
    Write-Host "Initial Pre-Deployment and Orchestration operations for this blueprint template are complete. Please proceed with finishing the deployment through the portal link in the Quickstart section at https://aka.ms/fedrampblueprint" -foregroundcolor Yellow
}

catch {
	Write-Host $PSItem.Exception.Message
	Write-Host "An error has occurred in the pre-deployment orchestration setup. Please review any error messages before attempting a re-deployment. Thank You"
}