Configuration MGTBaselineDSC
{
	param(
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
	
	Import-DscResource -ModuleName PSDesiredStateConfiguration
	Import-DscResource -ModuleName WindowsDefender -ModuleVersion "1.0.0.2"
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
        

        
	}
}