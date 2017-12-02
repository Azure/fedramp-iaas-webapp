    #
# Copyright="� Microsoft Corporation. All rights reserved."
#

configuration SQLWBaselineDSC
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Parameter(Mandatory)]
        [String]$SharePath,

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
    Import-DscResource -ModuleName xComputerManagement, xSmbShare, cDisk,xDisk,xActiveDirectory
    
    Node localhost
    {
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
        
        xWaitforDisk Disk2
        {
             DiskNumber = 2
             RetryIntervalSec =$RetryIntervalSec
             RetryCount = $RetryCount
        }

        cDiskNoRestart DataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
        }

        WindowsFeature ADPS
        {
            Name = "RSAT-AD-PowerShell"
            Ensure = "Present"
        } 

        xComputer DomainJoin
        {
            Name = $env:COMPUTERNAME
            DomainName = $DomainName
            Credential = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
        }

        File FSWFolder
        {
            DestinationPath = "F:\$($SharePath.ToUpperInvariant())"
            Type = "Directory"
            Ensure = "Present"
            DependsOn = "[xComputer]DomainJoin"
        }

        xSmbShare FSWShare
        {
            Name = $SharePath.ToUpperInvariant()
            Path = "F:\$($SharePath.ToUpperInvariant())"
            FullAccess = "BUILTIN\Administrators"
            Ensure = "Present"
            DependsOn = "[File]FSWFolder"
        }
        
        LocalConfigurationManager 
        {
            RebootNodeIfNeeded = $True
        }
    }     
}
