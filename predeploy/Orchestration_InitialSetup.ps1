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
    }

<#

.Description
This script will create a Key Vault with a Key Encryption Key for VM DIsk Encryption and Azure AD Application Service Principal inside a specified Azure subscription. A self-signed SSL Cert is utilized in administering the Key Vault for this deployment.

.Parameter adminUsername
Name of the local admin credentials for all VM's to be created. Validation exists in the script to limit the creation of incompatible admin user names. 

.Parameter adminPassword
Must meet complexity requirements
14+ characters, 2 numbers, 2 upper and lower case, and 2 special chars. Validation exists in the script to ensure compatibility.

.Parameter sqlServerServiceAccountPassword
Must meet complexity requirements
14+ characters, 2 numbers, 2 upper and lower case, and 2 special chars. Validation exists in the script to ensure compatibility.

.Parameter domain
Must be the Domain name to be created. Validation exists in the script to ensure compatibility.

#>

Write-Host "`n `nAzure Security and Compliance Blueprint - FedRAMP Web Applications Automation - Pre-Deployment Script `n" -foregroundcolor green
Write-Host "This script can be used for creating the necessary preliminary resources to deploy a multi-tier web application architecture with pre-configured security controls to help customers achieve compliance with FedRAMP requirements. See https://aka.ms/fedrampblueprint for more information. `n " -foregroundcolor yellow

Write-Host "`n DEFINE YOUR DOMAIN `n" -foregroundcolor green


########################################################################################################################
# LOGIN TO AZURE FUNCTION
########################################################################################################################
function loginToAzure {
	Param(
		[Parameter(Mandatory=$true)]
		[int]$lginCount
	)

	Write-Host "Please login with your Azure Government credentials." -ForegroundColor Yellow
	
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
			Write-Host "Your credentials are incorrect or invalid exceeding maximum retries. Make sure you are using your Azure Government account information." -ForegroundColor Magenta
			Write-Host "Press any key to exit..." -ForegroundColor Yellow
			$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			Exit
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
        $keyVaultNew = Read-Host "Key Vault name can't start with numeric value. Please enter a new Key Vault Name." 
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
        Write-Host "Not a valid Admin username, please select another." -ForegroundColor Magenta  
        checkAdminUserName
        return
    }
    return $username
}

########################################################################################################################
# DOMAIN NAME VALIDATION FUNCTION
########################################################################################################################
function CheckDomainName {  
	[CmdletBinding()]
	param(
        [Parameter(Mandatory=$true)]
	    [string]$domain
    )
    if ($domain.length -gt "15") {
        Write-Host "Domain Name is too long. Must be less than 15 characters." -ForegroundColor Magenta 
        CheckDomainName
        Return
    }
    if ($domain -notmatch "^[a-zA-Z0-9.-]*$") {
        Write-Host "Invalid character set utilized. Please verify domain name contains only alphanumeric, hyphens, and at least one period." -ForegroundColor Magenta 
        CheckDomainName
        Return
    }
    if ($domain -notmatch "[.]") {
        Write-Host "Invalid Domain Name specified. Please verify domain name contains only alphanumeric, hyphens, and at least one period." -ForegroundColor Magenta  
        CheckDomainName
        Return
    }
    Return $domain
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
          Write-Host "Password does not meet complexity requirements. Password cannot contain spaces." -ForegroundColor Magenta
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
            Write-Host "Password does not meet complexity requirements. Password must contain a special character." -ForegroundColor Magenta
            checkPasswords -name $name
            return
        }
	    if ($pw2test -match "[0-9]") {
			    $isGood = 4
        } 
        else {
            Write-Host "Password does not meet complexity requirements. Password must contain a numerical character." -ForegroundColor Magenta
            checkPasswords -name $name
            return
        }
	    if ($pw2test -cmatch "[a-z]") {
	        $isGood = 5
        } 
        else {
            Write-Host "Password must contain a lowercase letter." -ForegroundColor Magenta
            Write-Host "Password does not meet complexity requirements." -ForegroundColor Magenta
            checkPasswords -name $name
            return
        }
	    if ($pw2test -cmatch "[A-Z]") {
	        $isGood = 6
        } 
        else {
            Write-Host "Password must contain an uppercase character." -ForegroundColor Magenta
            Write-Host "Password does not meet complexity requirements." -ForegroundColor Magenta
            checkPasswords -name $name
        }
	    if ($isGood -ge 6) {
            $passwords | Add-Member -MemberType NoteProperty -Name $name -Value $password
            return
        } 
        else {
            Write-Host "Password does not meet complexity requirements." -ForegroundColor Magenta
            checkPasswords -name $name
            return
        }
    } 
    else {
        Write-Host "Password is not long enough - Passwords must be at least " + $passLength + " characters long." -ForegroundColor Magenta
        checkPasswords -name $name
        return
    }
}

########################################################################################################################
# GENERATE RANDOM PASSWORD FOR CERT FUNCTION
########################################################################################################################
Function New-AlphaNumericPassword () {
    [CmdletBinding()]
    param(
        [int]$Length = 14
    )
        $ascii=$NULL
        $AlphaNumeric = @(48..57;65..90;97..122)
        Foreach ($Alpha in $AlphaNumeric) {
            $ascii+=,[char][byte]$Alpha
            }
        for ($loop=1; $loop -le $length; $loop++) {
            $RandomPassword+=($ascii | GET-RANDOM)
        }
    return $RandomPassword
}

Write-Host "Please provide a domain name you would like to use with this deployment." -ForegroundColor Yellow
$DomainName = Read-Host "Domain Name" 
Write-Host "`n"
$domainused = checkdomainname $domainname

function Generate-Cert() {
	[CmdletBinding()]
	param(
    [securestring]$certPassword,
	[string]$domain = $domainused
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
Write-Host "`n LOGIN TO AZURE `n" -foregroundcolor green

function orchestration {
	Param(
		[string]$environmentName = "AzureUSGovernment",
		[string]$location = "USGov Virginia",
		[Parameter(Mandatory=$true)]
		[string]$subscriptionId,
		[Parameter(Mandatory=$true)]
		[string]$resourceGroupName,
		[Parameter(Mandatory=$true)]
		[string]$keyVaultName,
		[Parameter(Mandatory=$true)]
		[string]$adminUsername,
		[Parameter(Mandatory=$true)]
		[SecureString]$adminPassword,
                [string]$domain = $domainused
	)

	$errorActionPreference = 'stop'
    $keyVaultName = checkKeyVaultName -keyVaultName $keyVaultName;
	try {
		$Exists = Get-AzureRmSubscription  -SubscriptionId $SubscriptionId
		Write-Host "Using existing authentication" -ForegroundColor Yellow
	}
	catch {}
	if (-not $Exists) {
		Write-Host "Authenticate to Azure subscription" -ForegroundColor Yellow
		Add-AzureRmAccount -EnvironmentName $EnvironmentName | Out-String | Write-Verbose
	}
	Write-Host "Selecting subscription as default" -ForegroundColor Yellow
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

			Write-Host "Creating new AAD application ($aadAppName)" -ForegroundColor Yellow;
			$ADApp = New-AzureRmADApplication -DisplayName $aadAppName -HomePage $defaultHomePage -IdentifierUris $identifierUri  -StartDate $now -EndDate $oneYearFromNow -Password $aadClientSecret;
			$servicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $ADApp.ApplicationId;
			$SvcPrincipals = (Get-AzureRmADServicePrincipal -SearchString $aadAppName);
			if(-not $SvcPrincipals)
			{
					# AAD app wasn't created
					Write-Error "Failed to create AAD app $aadAppName. Please log-in to Azure using Login-AzureRmAccount and try again." -ForegroundColor Magenta;
					return;
			}
			$aadClientID = $servicePrincipal.ApplicationId;
			Write-Host "Created a new AAD Application ($aadAppName) with ID: $aadClientID." -ForegroundColor Yellow;
		}
		else {
			if(-not $aadClientSecret) {
				$aadClientSecret = Read-Host -Prompt "Aad application ($aadAppName) was already created, input corresponding aadClientSecret and hit ENTER. It can be retrieved from https://manage.windowsazure.com portal." ;
			}
			if(-not $aadClientSecret) {
				Write-Error "Aad application ($aadAppName) was already created. Re-run the script by supplying aadClientSecret parameter with corresponding secret from https://manage.windowsazure.com portal.";
				return;
			}
			$aadClientID = $SvcPrincipals[0].ApplicationId;
		}

	# Create KeyVault or setup existing keyVault
	Write-Host "Creating resource group '$($resourceGroupName)' to hold key vault." -ForegroundColor Yellow
	if (-not (Get-AzureRmResourceGroup -Name $resourceGroupName -Location $location -ErrorAction SilentlyContinue)) {
		New-AzureRmResourceGroup -Name $resourceGroupName -Location $location  | Out-String | Write-Verbose
	}

	#Create a new vault if vault doesn't exist
	if (-not (Get-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue )) {
		Write-Host "Create a keyVault '$($keyVaultName)' to store the service principal ids and passwords." -ForegroundColor Yellow
		New-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -EnabledForTemplateDeployment -Location $location | Out-String | Write-Verbose
		Write-Host "Created a new KeyVault named $keyVaultName to store encryption keys" -ForegroundColor Yellow;

		# Specify privileges to the vault for the AAD application - https://msdn.microsoft.com/en-us/library/mt603625.aspx
		Write-Host "Set Azure Key Vault Access Policy." -ForegroundColor Yellow
		Write-Host "Set ServicePrincipalName: $aadClientID in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ServicePrincipalName $aadClientID -PermissionsToKeys wrapKey -PermissionsToSecrets set;
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ServicePrincipalName $aadClientID -PermissionsToKeys backup,get,list,wrapKey -PermissionsToSecrets get,list,set;
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -EnabledForDiskEncryption;
        $keyEncryptionKeyName = $keyVaultName + "kek"

		if($keyEncryptionKeyName) {
			try {
			    $kek = Get-AzureKeyVaultKey -VaultName $keyVaultName -Name $keyEncryptionKeyName -ErrorAction SilentlyContinue;
			}
			catch [Microsoft.Azure.KeyVault.KeyVaultClientException] {
				Write-Host "Couldn't find key encryption key named : $keyEncryptionKeyName in Key Vault: $keyVaultName" -ForegroundColor Magenta;
				$kek = $null;
			}
			if(-not $kek) {
				Write-Host "Creating new key encryption key named: $keyEncryptionKeyName in Key Vault: $keyVaultName" -ForegroundColor Yellow;
				$kek = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name $keyEncryptionKeyName -Destination Software -ErrorAction SilentlyContinue;
				Write-Host "Created key encryption key named: $keyEncryptionKeyName in Key Vault: $keyVaultName" -ForegroundColor Yellow;
			}
			$keyEncryptionKeyUrl = $kek.Key.Kid;
		}

		$certPassword = New-AlphaNumericPassword
		$secureCertPassword = ConvertTo-SecureString $certPassword -AsPlainText -Force
		Generate-Cert -certPassword $secureCertPassword -domain $domain
		$certificate = Get-Content -Path ".\cert.txt" | Out-String

        try {
		    Write-Host "Set Azure Key Vault Access Policy. Set adminUsername in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'adminUsername' -Destination 'Software'
		    $adminUsernameSecureString = ConvertTo-SecureString $adminUsername -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminUsername' -SecretValue $adminUsernameSecureString

		    Write-Host "Set Azure Key Vault Access Policy. Set AdminPassword in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'adminPassword' -Destination 'Software'
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminPassword' -SecretValue $adminPassword

		    Write-Host "Set Azure Key Vault Access Policy. Set sslCert in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sslCert' -Destination 'Software'
		    $sslCertSecureString = ConvertTo-SecureString "$certificate" -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sslCert' -SecretValue $sslCertSecureString

		    Write-Host "Set Azure Key Vault Access Policy. Set sslCertPassword in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sslPassword' -Destination 'Software'
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sslPassword' -SecretValue $secureCertPassword

		    Write-Host "Set Azure Key Vault Access Policy. Set domain in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'domain' -Destination 'Software'
		    $domainSecureString = ConvertTo-SecureString $domain -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'domain' -SecretValue $domainSecureString

		    Write-Host "Set Azure Key Vault Access Policy. Set guid in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $guid = new-guid
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'guid' -Destination 'Software'
		    $guidSecureString = ConvertTo-SecureString $guid -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'guid' -SecretValue $guidSecureString

		    Write-Host "Set Azure Key Vault Access Policy. Set Application Client ID in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadClientID' -Destination 'Software'
		    $aadClientIDSecureString = ConvertTo-SecureString $aadClientID -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientID' -SecretValue $aadClientIDSecureString

		    Write-Host "Set Azure Key Vault Access Policy. Set Application Client Secret in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadClientSecret' -Destination 'Software'
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientSecret' -SecretValue $aadClientSecret

		    Write-Host "Set Azure Key Vault Access Policy. Set Key Encryption URL in Key Vault: $keyVaultName" -ForegroundColor Yellow;
		    $key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -Destination 'Software'
		    $keyEncryptionKeyUrlSecureString = ConvertTo-SecureString $keyEncryptionKeyUrl -AsPlainText -Force
		    $secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -SecretValue $keyEncryptionKeyUrlSecureString
        }
        catch {
			Write-Host "An error occurred while setting Key Vault resources. Please review any associated error messages, clean up previously created assets, and attempt to re-deploy." -ForegroundColor Magenta
			Write-Host "Press any key to exit..." -ForegroundColor Yellow
			$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			Exit
		}
	}
}

########################################################################################################################
# Run Pre-Deployment and Orchestration
########################################################################################################################

try {
	loginToAzure -lginCount 1
	Write-Host "You will now be asked to create credentials for the administrator and sql service accounts. `n" -ForegroundColor Yellow
	Write-Host "`n CREATE CREDENTIALS `n" -foregroundcolor green
    $adminUsername = checkAdminUserName
	$passwordNames = @("adminPassword")
	$passwords = New-Object -TypeName PSObject
	for ($i=0;$i -lt $passwordNames.Length;$i++) {
	   checkPasswords -name $passwordNames[$i]
	}
	orchestration -adminUsername $adminUsername -adminPassword $passwords.adminPassword
    Write-Host "`n ORCHESTRATION COMPLETE `n" -foregroundcolor green
    Write-Host "Initial Pre-Deployment and Orchestration operations for this blueprint template are complete. Please proceed with finishing the deployment through the portal link in the Quickstart section at https://aka.ms/fedrampblueprint." -foregroundcolor Yellow
}

catch {
	Write-Host $PSItem.Exception.Message
	Write-Host "An error has occurred in the pre-deployment orchestration setup. Please review any error messages before attempting a re-deployment. Thank You." -ForegroundColor Magenta
	Write-Host "Press any key to exit..." -ForegroundColor Yellow
	$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	Exit
}
