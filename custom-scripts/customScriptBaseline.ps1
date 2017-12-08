
    param
    (
        [String]$MachineName,
        [String]$ResourceGroupName,
        [String]$AutomationAccountName,
        [String]$WorkspaceName,
        [String]$AzureUserName,
        [String]$AzurePassword,
        [String]$SubscriptionId,
        [String]$EnvironmentName,
        [String]$MachinesToSetPasswordPolicy,
        [String]$DomainName,
        [String]$SQLPrimaryName,
        [String]$SQLSecondaryName,
        [String]$AlwaysOnAvailabilityGroupName
    )

    Disable-AzureRmDataCollection
    Enable-PSRemoting -Force
    Write-Host "Check Module exists"
    Install-Packageprovider -Name Nuget -MinimumVersion 2.8.5.201 -Force


    # Add and update modules on the Automation account
    Write-Output "Importing necessary modules..."

    # Create a list of the modules necessary to register a hybrid worker
    $AzureRmModule = @{"Name" = "AzureRM"; "Version" = ""}
    $Modules = @($AzureRmModule)

    # Import modules
    foreach ($Module in $Modules) {
        $ModuleName = $Module.Name
        # Find the module version
        if ([string]::IsNullOrEmpty($Module.Version)){
            # Find the latest module version if a version wasn't provided
            $ModuleVersion = (Find-Module -Name $ModuleName).Version
        } else {
            $ModuleVersion = $Module.Version
        }
        # Check if the required module is already installed
        $CurrentModule = Get-Module -Name $ModuleName -ListAvailable | where "Version" -eq $ModuleVersion
        if (!$CurrentModule) {

            $null = Install-Module -Name $ModuleName -RequiredVersion $ModuleVersion -Force
            Write-Output " Successfully installed version $ModuleVersion of $ModuleName..."
        } else {
            Write-Output " Required version $ModuleVersion of $ModuleName is installed..."
        }
    }

    Import-Module -Name AzureRM

    $AzureAuthCreds = New-Object System.Management.Automation.PSCredential -ArgumentList @($AzureUserName,(ConvertTo-SecureString -String $AzurePassword -AsPlainText -Force))


     $azureEnv = Get-AzureRmEnvironment -Name $EnvironmentName
     Login-AzureRmAccount -Environment $azureEnv -Credential $AzureAuthCreds

    if($SubscriptionId)
    {
        Select-AzureRmSubscription -SubscriptionId $SubscriptionId;
    }

    <#
    try{
        # $cloudMonitoring =Get-AzureRmVMExtension -ResourceGroupName $ResourceGroupName -VMName $MachineName -Name "EnterpriseCloudMonitoring" -Status
        # $status = $cloudMonitoring.ProvisioningState

        $Workspace = Get-AzureRmOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName  -ErrorAction Stop
        $OmsLocation = $Workspace.Location
        #Get the workspace ID
        $WorkspaceId = $Workspace.CustomerId

        #Get the primary key for the OMS workspace
        $WorkspaceSharedKeys = Get-AzureRmOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
        $WorkspaceKey = $WorkspaceSharedKeys.PrimarySharedKey

        $PublicSettings = @{"workspaceId" = $WorkspaceId }
        $ProtectedSettings = @{"workspaceKey" = $WorkspaceKey}
        Write-Output "Setting EnterpriseCloudMonitoring Extension"
        Set-AzureRmVMExtension -ExtensionName "EnterpriseCloudMonitoring" -ResourceGroupName $ResourceGroupName -VMName $MachineName -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" -TypeHandlerVersion 1.0 -Settings $PublicSettings -ProtectedSettings $ProtectedSettings -Location $OmsLocation
    }
    catch{

    }

    $ext = Get-AzureRmVMExtension -ResourceGroupName $ResourceGroupName -VMName $MachineName -Name "EnterpriseCloudMonitoring"
    $ext
    while($ext.ProvisioningState -ne "Succeeded")
     {
       Write-Output "Not ready..."
       Start-Sleep -s 10
       $ext = Get-AzureRmVMExtension -ResourceGroupName $ResourceGroupName -VMName $MachineName -Name "EnterpriseCloudMonitoring"
     }
     #>
    ########################################################################################################################
    # Add Hybrid Worker Group If not exist
    ########################################################################################################################
    try{

        $i = 18

        do {

            # Check for the MMA folders
            try {
                # Change the directory to the location of the hybrid registration module
                cd "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\AzureAutomation"
                $version = (ls | Sort-Object LastWriteTime -Descending | Select -First 1).Name
                cd "$version\HybridRegistration"

                # Import the module
                Import-Module (Resolve-Path('HybridRegistration.psd1'))

                # Mark the flag as true
                $hybrid = $true
            } catch{

                $hybrid = $false

            }
            # Sleep for 10 seconds
            Start-Sleep -s 10
            $i--

        } until ($hybrid -or ($i -le 0))

        if ($i -le 0) {
            throw "The HybridRegistration module was not found. Please ensure the Microsoft Monitoring Agent was correctly installed."
        }

        $Account = Get-AzureRmAutomationAccount -ResourceGroupName  $ResourceGroupName -Name  $AutomationAccountName
        $RegistrationInfo = $Account | Get-AzureRmAutomationRegistrationInfo
        $endPointUrl = $RegistrationInfo.EndPoint
        $token = $RegistrationInfo.PrimaryKey
        $_id = New-Guid
        $runBookName = $MachineName + "_" + $_id
        Add-HybridRunbookWorker -Name $runBookName -EndPoint $endPointUrl -Token $token
    }
    catch{
        #don nothing is group exists
    }

    ########################################################################################################################
    # Section2:  Get Hybrid Worker Group Name
    ########################################################################################################################

    try{
        $HybridWorkerGroups = Get-AzureRMAutomationHybridWorkerGroup -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName

        # Wait for Hybrid Workers Provision
        if($HybridWorkerGroups -eq ""){
            $timeout = new-timespan -Minutes 5
            $sw = [diagnostics.stopwatch]::StartNew()
            while ($sw.elapsed -lt $timeout){
                $HybridWorkerGroups = Get-AzureRMAutomationHybridWorkerGroup -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName

                if ($HybridWorkerGroups -ne ""){
                    #write-host "Hybrid Workers Provisioned!"
                    return
                }
                start-sleep -seconds 5
            }
            #"Timed out"
        }

        $computerIdList="";
        foreach ($worker in $HybridWorkerGroups){
            #Write-Host "Name: $($worker.name)";
            $computerIdList = $computerIdList + $worker.name + "=Windows;"
        }

        if($computerIdList -ne "" -and $computerIdList -match '.+?;$'){
            # Remove the last Character
            $computerIdList = $computerIdList.Substring(0,$computerIdList.Length-1)
        }

        ########################################################################################################################
        # Section2: Automation Account Variable
        ########################################################################################################################
        $VariableName = "ComputerIdList"

        if(-not (Get-AzureRmAutomationVariable -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName | Where-Object { $_.Name -eq $VariableName } ) ){

            New-AzureRmAutomationVariable -Name $VariableName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Encrypted $false -Value $computerIdList
        }
        else{
            Set-AzureRmAutomationVariable -Name $VariableName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Encrypted $false -Value $computerIdList
        }
    }
    catch{

    }





    Configuration SetHybridWorderList
    {

        param
        (
        [String]$MachineName,
        [String]$ResourceGroupName,
        [String]$AutomationAccountName,
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $AzureAuthCreds,

        [String]$SubscriptionId,
        [String]$EnvironmentName

        )

        Import-DscResource -ModuleName PSDesiredStateConfiguration
        Import-Module -Name AzureRM

        Node $MachineName
        {
            WindowsFeature PSWA
            {
                Name = 'WindowsPowerShellWebAccess'
                Ensure = 'Present'
            }

            #Apply AppLocker
        Service AppIDsvc {
            Name = 'AppIDSvc'
            #StartupType = 'Automatic'
            State = 'Running'
            BuiltinAccount = 'LocalService'
            DependsOn = "[File]XMLPol","[Script]ApplyLocalApplockerPol"

        }
        Script ApplyLocalApplockerPol {
            GetScript = {
                @{
                    GetScript = $GetScript
                    SetScript = $SetScript
                    TestScript = $TestScript
                    Result  = ([xml](Get-AppLockerPolicy -Effective -Xml)).InnerXML
                }
            }
            SetScript = {
                Set-AppLockerPolicy -XMLPolicy 'C:\windows\temp\polApplocker.xml'
            }
            TestScript = {
                if(
                Compare-Object -ReferenceObject  ([xml](Get-AppLockerPolicy -Effective -Xml)).InnerXML `
                               -DifferenceObject ([xml](Get-Content 'C:\windows\temp\polApplocker.xml')).InnerXml
                ) {
                    return $false
                } else {
                    return $true
                }
            }
            DependsOn = "[File]XMLPol"
        }
        File  XMLPol {
            DestinationPath = 'C:\windows\temp\polApplocker.xml'
            Ensure = 'Present';
            Force = $true
            Contents = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Appx" EnforcementMode="Enabled" />
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured" />
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
    <FilePublisherRule Id="f216d2ae-b7eb-484e-8ef5-297c961577c3" Name="Program Files: MICROSOFT® WINDOWS® OPERATING SYSTEM signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="*">
          <BinaryVersionRange LowSection="6.3.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="df9784b2-bd11-4e06-8cd5-9adf604529ac" Name="Program Files: MICROSOFT MONITORING AGENT signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT MONITORING AGENT" BinaryName="*">
          <BinaryVersionRange LowSection="8.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="9436f91a-d2da-45e7-bfdb-7faae7db71c3" Name="Program Files: MICROSOFT® VISUAL STUDIO® 2013 signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® VISUAL STUDIO® 2013" BinaryName="*">
          <BinaryVersionRange LowSection="12.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="529fc03c-5568-48a7-8faa-346d74e8aa35" Name="Program Files: MICROSOFT SYSTEM CENTER ONLINE signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT SYSTEM CENTER ONLINE" BinaryName="*">
          <BinaryVersionRange LowSection="1.10.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="f8819956-50ed-4954-bb77-2d62c67e4869" Name="Program Files: PREMIER PROACTIVE ASSESSMENT SERVICES signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="PREMIER PROACTIVE ASSESSMENT SERVICES" BinaryName="*">
          <BinaryVersionRange LowSection="2.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="79ebf396-b3e0-468e-8f2a-77aa3a4386b3" Name="Program Files: HYBRID SERVICE MANAGEMENT AUTOMATION signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="HYBRID SERVICE MANAGEMENT AUTOMATION" BinaryName="*">
          <BinaryVersionRange LowSection="7.2.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePublisherRule Id="841b0342-7a75-4ddb-9dc9-e3bc8ecf05f4" Name="Program Files: INTERNET EXPLORER signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="*">
          <BinaryVersionRange LowSection="11.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="Enabled" />
  <RuleCollection Type="Script" EnforcementMode="Enabled" />
</AppLockerPolicy>
'@
        }
        }
    }


    $ConfigData = @{
        AllNodes = @(
            @{
                NodeName = $MachineName
                PSDscAllowPlainTextPassword = $true
            }
        )
    } # End of Config Data


try {
      if([string]::IsNullOrWhiteSpace($SQLPrimaryName)){
          if($SQLPrimaryName -eq $MachineName){
              Import-Module Sqlps -DisableNameChecking;
              $primaryInst = "$($SQLPrimaryName).$($DomainName)"
              $secondaryInst = "$($SQLSecondaryName).$($DomainName)"
              $MyAgPrimaryPath = "SQLSERVER:\SQL\$($primaryInst)\Default\AvailabilityGroups\$($AlwaysOnAvailablityGroupName)"
              $MyAgSecondaryPath = "SQLSERVER:\SQL\$($secondaryInst)\Default\AvailabilityGroups\$($AlwaysOnAvailablityGroupName)"

              #Add-Type -AssemblyName "Microsoft.SqlServer.Smo"
              [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo");
              import-module SQLps;
              # Connect to the specified instance
              $srv = new-object ('Microsoft.SqlServer.Management.Smo.Server') $primaryInst
              New-Item "f:\backup" –type directory

              New-SMBShare –Name "Backup" –Path "f:\backup"  –FullAccess contoso\sqlservicetestuser,contoso\testuser

              # Cycle through the databases
              foreach ($db in $srv.Databases) {
                  if ($db.IsSystemObject -ne $True -and $db.Name -notlike "AutoHa*")
                  {
                      $dbname = $db.Name
                      #"Changing database $dbname to set Recovery Model to Full"
                      $db.RecoveryModel = 'Full'
                      $db.Alter()
                      $DatabaseBackupFile = "\\" + $primaryInst + "\Backup\" + $dbname +".bak"
                      $LogBackupFile =   "\\" + $primaryInst + "\Backup\"  + $dbname +"_log.trn"

                      Backup-SqlDatabase -Database $dbname -BackupFile $DatabaseBackupFile -ServerInstance $primaryInst
                      Backup-SqlDatabase -Database $dbname -BackupFile $LogBackupFile -ServerInstance $primaryInst  -BackupAction Log

                      Restore-SqlDatabase -Database $dbname -BackupFile $DatabaseBackupFile -ServerInstance $secondaryInst -NoRecovery
                      Restore-SqlDatabase -Database $dbname -BackupFile $LogBackupFile -ServerInstance $secondaryInst -RestoreAction 'Log'   -NoRecovery

                      Add-SqlAvailabilityDatabase -Path $MyAgPrimaryPath -Database $dbname
                      Add-SqlAvailabilityDatabase -Path $MyAgSecondaryPath -Database $dbname

                  }
              }
          }
    }
}
catch{}

try {
      if([string]::IsNullOrWhiteSpace($SQLSecondaryName)){
          Import-Module Sqlps -DisableNameChecking;
          $domainPrefix = $DomainName.Split(".")[0]
          if($SQLSecondaryName -eq $MachineName){
            Invoke-Sqlcmd -InputFile ".\SQL0CustomCMD.sql" -Variable domain=$domainPrefix | Out-File -filePath "C:\MyFolder\TestSQLCmd.rpt"
          }
      }
}
catch {}


# calling the configuration
SetHybridWorderList -MachineName $MachineName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -AzureAuthCreds $AzureAuthCreds -SubscriptionId $SubscriptionId -EnvironmentName $EnvironmentName -ConfigurationData $ConfigData -Verbose
Start-DscConfiguration -Wait -Force -Path .\SetHybridWorderList -Verbose

Invoke-Expression "tzutil.exe /s ""UTC"""


$Logs = Get-Eventlog -List |ForEach {
Limit-Eventlog -Logname $_.Log -MaximumSize 64000Kb

}


try{
    # Set Password Policy

    if([string]::IsNullOrWhiteSpace($MachinesToSetPasswordPolicy)){
        $adMachineArray = $MachinesToSetPasswordPolicy.Split(";")
        $index = $adMachineArray.IndexOf($MachineName)
        if($index -gt -1){

            $Domain = (gwmi WIN32_ComputerSystem).Domain

            Import-Module ActiveDirectory
            Import-Module grouppolicy
            $dcs = $Domain.split(".")
            $target = "DC=" + $dcs[0]+ "," + "DC=" + $dcs[1]

            #this does not error out
            Set-ADDefaultDomainPasswordPolicy -Identity $Domain -AuthType Negotiate -MaxPasswordAge 60.00:00:00 -MinPasswordAge 1.00:00:00 -PasswordHistoryCount 24 -ComplexityEnabled $true -ReversibleEncryptionEnabled $true -MinPasswordLength 14
            Set-GPLink -Guid (Get-GPO -Name "Default Domain Policy").id -Target $target -LinkEnabled Yes -Enforced Yes

            $Domain = (gwmi WIN32_ComputerSystem).Domain
            $Root = [ADSI]"LDAP://RootDSE"
            $LDAPDomain = $Root.Get("rootDomainNamingContext")
            $key = "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
            $key1 = "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system"


            #PART 1: set Account lockout policies
            Set-ADDefaultDomainPasswordPolicy -Identity $Domain -AuthType Negotiate -LockoutDuration "03:00:00" -LockoutObservationWindow "00:15:00" -LockoutThreshold "3"


            #PART 2: set inactive session policies
            New-GPO 'session lock gpo' |`
            Set-GPRegistryValue -Key $key -ValueName 'ScreenSaveTimeOut' -Type String -Value 900 |`
            Set-GPRegistryValue -Key $key -ValueName 'ScreenSaveActive' -Type String -Value 1 |`
            Set-GPRegistryValue -Key $key -ValueName 'SCRNSAVE.EXE' -Type String -Value "rundll32 user32.dll,LockWorkStation" |`
            Set-GPPermissions -Replace -PermissionLevel None -TargetName 'Authenticated Users' -TargetType group | `
            Set-GPPermissions -PermissionLevel gpoapply -TargetType group -TargetName 'Authenticated Users' | New-GPLink -Domain $Domain -Target $LDAPDomain -enforced yes -Order 1


            #PART 3: set logon message Policy
            New-GPO 'logon message gpo' |`
            Set-GPRegistryValue -Key $key1 -ValueName 'legalnoticecaption' -Type string -Value "Sample system use notification" |`
            Set-GPRegistryValue -Key $key1 -ValueName 'legalnoticetext' -Type string -Value "Sample system use notification. Customer must edit this text to comply with customer organization and/or regulatory body requirements." |`
            Set-GPPermissions -Replace -PermissionLevel None -TargetName 'Authenticated Users' -TargetType group | `
            Set-GPPermissions -PermissionLevel gpoapply -TargetType group -TargetName 'Authenticated Users' | New-GPLink -Domain $Domain -Target $LDAPDomain -enforced yes -Order 3


            #PART 4: set logoff message Policy
            New-GPO 'logoff message gpo' |`
            Set-GPRegistryValue -Key $key1 -ValueName 'verbosestatus' -Type DWORD -Value 1 |`
            Set-GPPermissions -Replace -PermissionLevel None -TargetName 'Authenticated Users' -TargetType group | `
            Set-GPPermissions -PermissionLevel gpoapply -TargetType group -TargetName 'Authenticated Users' | New-GPLink -Domain $Domain -Target $LDAPDomain -enforced yes -Order 2



            #PART 5: disable inactive AccountDisabled
            $principal = New-ScheduledTaskPrincipal -UserId "$($env:USERDOMAIN)\$($env:USERNAME)" -LogonType S4U -RunLevel Highest
            $Action = New-ScheduledTaskAction  -Execute 'C:WindowsSystem32WindowsPowerShellv1.0powershell.exe' -Argument "-NonInteractive -NoLogo -NoProfile -File .\accountmanagementprincipals.ps1"
            $Trigger = New-ScheduledTaskTrigger -Daily -At '4AM'
            $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $principal -Settings (New-ScheduledTaskSettingsSet)
            $Task | Register-ScheduledTask -TaskName "Inactive accounts script"

            Invoke-GPUpdate -Boot

        }

    }
}
catch{
}

gpupdate
