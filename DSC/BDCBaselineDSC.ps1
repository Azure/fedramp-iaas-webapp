configuration BDCBaselineDSC
{
   param
    (
        ### Prepare BDC ###
        [Parameter(Mandatory)]
        [String]$DNSServer,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30,

        ### Configure Antimalware ###
        [string]$IsSingleInstance = "Yes",
		[bool]$CheckForSignaturesBeforeRunningScan,
		[bool]$DisableArchiveScanning,
		[bool]$DisableAutoExclusions,
		[bool]$DisableBehaviorMonitoring,
		[bool]$DisableCatchupFullScan,
		[bool]$DisableCatchupQuickScan,
		[bool]$DisableEmailScanning,
		[bool]$DisableIntrusionPreventionSystem,
		[bool]$DisableIOAVProtection,
		[bool]$DisablePrivacyMode,
		[bool]$DisableRealtimeMonitoring,
		[bool]$DisableRemovableDriveScanning,
		[bool]$DisableRestorePoint,
		[bool]$DisableScanningMappedNetworkDrivesForFullScan,
		[bool]$DisableScanningNetworkFiles,
		[bool]$DisableScriptScanning,
		[string[]]$ExclusionExtension,
	    [string[]]$ExclusionPath,
		[string[]]$ExclusionProcess,		
		[ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
		[string]$HighThreatDefaultAction,
		[ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
		[string]$LowThreatDefaultAction,
		[ValidateSet("Advanced","Basic","Disabled")]
		[string]$MAPSReporting,
		[ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
		[string]$ModerateThreatDefaultAction,
		[UInt32]$QuarantinePurgeItemsAfterDelay,
		[bool]$RandomizeScheduleTaskTimes,
		[ValidateSet("Both","Incoming","Outcoming")]
		[string]$RealTimeScanDirection,
		[ValidateSet("Everyday","Friday","Monday","Never","Saturday","Sunday","Thursday","Tuesday","Wednesday")]
		[string]$RemediationScheduleDay,
		[DateTime]$RemediationScheduleTime,
		[UInt32]$ReportingAdditionalActionTimeOut,
		[UInt32]$ReportingCriticalFailureTimeOut,
		[UInt32]$ReportingNonCriticalTimeOut,
		[UInt32]$ScanAvgCPULoadFactor,
		[bool]$ScanOnlyIfIdleEnabled,
		[ValidateSet("FullSCan","QuickScan")]
		[string]$ScanParameters,
		[UInt32]$ScanPurgeItemsAfterDelay,
		[ValidateSet("Everyday","Friday","Monday","Never","Saturday","Sunday","Thursday","Tuesday","Wednesday")]
		[string]$ScanScheduleDay,
		[DateTime]$ScanScheduleQuickScanTime,
		[DateTime]$ScanScheduleTime,
		[ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
		[string]$SevereThreatDefaultAction,
		[UInt32]$SignatureAuGracePeriod,
		[string]$SignatureDefinitionUpdateFileSharesSources,
		[bool]$SignatureDisableUpdateOnStartupWithoutEngine,
		[string]$SignatureFallbackOrder,
		[UInt32]$SignatureFirstAuGracePeriod,
		[ValidateSet("Everyday","Friday","Monday","Never","Saturday","Sunday","Thursday","Tuesday","Wednesday")]
		[string]$SignatureScheduleDay,
		[DateTime]$SignatureScheduleTime,
		[UInt32]$SignatureUpdateCatchupInterval,
		[UInt32]$SignatureUpdateInterval,
		[ValidateSet("Always","Never","None")]
		[string]$SubmitSamplesConsent,
		[ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
		[string]$ThreatIDDefaultAction_Actions,
		[UInt64]$ThreatIDDefaultAction_Ids,
		[bool]$UILockdown,
		[ValidateSet("Allow","Block","Clean","NoAction","Quarantine","Remove","UserDefined")]
		[string]$UnknownThreatDefaultAction
		
		
    )
	
	
	
    Import-DscResource -ModuleName WindowsDefender -ModuleVersion "1.0.0.2"

    Import-DscResource -ModuleName  xStorage, xNetworking, PSDesiredStateConfiguration
	
    $Interface=Get-NetAdapter|Where Name -Like "Ethernet*"|Select-Object -First 1
    $InterfaceAlias=$($Interface.Name)
    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        ### Configure Antimalware ###
        Service WindowsDefender
		{
			Name = 'WinDefend'
			State = 'Running'
			Ensure = 'Present'
		}
		WindowsDefender SetParameters
		{
			IsSingleInstance = $IsSingleInstance
			ExclusionPath = $ExclusionPath
			ExclusionExtension = $ExclusionExtension
			ExclusionProcess = $ExclusionProcess
			RealTimeScanDirection = $RealTimeScanDirection
			RemediationScheduleDay = $RemediationScheduleDay	
			ScanScheduleDay = $ScanScheduleDay
			DisableRealtimeMonitoring = $DisableRealtimeMonitoring
			DependsOn = "[Service]WindowsDefender"
		}

        ### Prepare BDC ###
        xWaitforDisk Disk2
        {
                DiskNumber = 2
                RetryIntervalSec =$RetryIntervalSec
                RetryCount = $RetryCount
        }
        xDisk ADDataDisk
        {
            DiskNumber = 2
            DriveLetter = 'F'
            DependsOn = "[xWaitForDisk]Disk2"
        }
        WindowsFeature ADDSInstall
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[xDisk]ADDataDisk"
        }

	WindowsFeature ADAdminCenter 
        { 
            Ensure = "Present" 
            Name = "RSAT-AD-AdminCenter"
			DependsOn = "[WindowsFeature]ADDSInstall"
        }
		
	WindowsFeature ADDSTools 
        { 
            Ensure = "Present" 
            Name = "RSAT-ADDS-Tools"
			DependsOn = "[WindowsFeature]ADDSInstall"
        } 

        xDnsServerAddress DnsServerAddress
        {
            Address        = $DNSServer
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn="[WindowsFeature]ADDSInstall"
        }

        WindowsFeature PSWA
        {
            Name = 'WindowsPowerShellWebAccess'
            Ensure = 'Present'
        }  

        
   }
}


configuration BDCConfigureBaselineDSC
{
   param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )

    Import-DscResource -ModuleName xActiveDirectory, xStorage

    [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)

    Node localhost
    {
        LocalConfigurationManager
        {
       	    ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }
        xWaitForADDomain DscForestWait
        {
            DomainName = $DomainName
            DomainUserCredential= $DomainCreds
            RetryCount = $RetryCount
            RetryIntervalSec = $RetryIntervalSec
        }
        xADDomainController BDC
        {
            DomainName = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath = "F:\NTDS"
            LogPath = "F:\NTDS"
            SysvolPath = "F:\SYSVOL"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
        Script script1
        {
            SetScript =
            {
                $dnsFwdRule = Get-DnsServerForwarder
                if ($dnsFwdRule)
                {
                    Remove-DnsServerForwarder -IPAddress $dnsFwdRule.IPAddress -Force
                }
                Write-Verbose -Verbose "Removing DNS forwarding rule"
            }
            GetScript =  { @{} }
            TestScript = { $false}
            DependsOn = "[xADDomainController]BDC"
        }
    }
}