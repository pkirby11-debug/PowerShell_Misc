<#
.SYNOPSIS
    Detects whether the Windows 10 ESU key is required. Intended for use with Intune Proactive Remediations.

.DESCRIPTION
    This script checks if a device meets the prerequisites for the Windows 10 Year 1 ESU key.
    It is designed to be the "detection" script in an Intune Proactive Remediation.

    The script will exit with code 0 (Success/Compliant) if:
    - The ESU key is already installed.
    - The device does not meet the prerequisites (e.g., wrong OS version, LTSC, UBR too low).

    The script will exit with code 1 (Failure/Remediation Required) if:
    - The device meets all prerequisites but does not have the ESU key installed.

.NOTES
    Author: Jules
    Date: 2025-10-30
    Version: 1.0
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

begin {
    # --- Script Configuration ---
    $ESUKey = "K4VWN-3GQCW-WRY4K-2PCKV-G6TR8"
    $ESUActivationID = "f520e45e-7413-4a34-a497-d2765967d094" # Win10 ESU Year1
    $RequiredOSVersion = "22H2"
    $RequiredUBR = 5131
    # --------------------------

    $PartialKey = $ESUKey.Split('-')[-1]
    $LogDirectory = "C:\ProgramData\Microsoft\Intune\Logs"
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }
    $LogFile = Join-Path -Path $LogDirectory -ChildPath "Detect-Win10ESU-Intune.log"

    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] - $Message"
        $logEntry | Out-File -FilePath $LogFile -Append
        Write-Output $logEntry
    }

    "--------------------------------------------------" | Out-File -FilePath $LogFile -Append
    Write-Log "ESU Key Detection Script Started."
}

process {
    try {
        Write-Log "Performing OS eligibility checks..."
        $OSInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $OSVersion = $OSInfo.DisplayVersion
        $OSEdition = $OSInfo.EditionID
        $CurrentUBR = $OSInfo.UBR

        if ($OSEdition -like "*EnterpriseS*" -or $OSEdition -like "*IoTEnterpriseS*") {
            Write-Log "Device is LTSC ($OSEdition). ESU key not applicable. Exiting as compliant."
            exit 0
        }
        Write-Log "OS Edition is not LTSC."

        if ($OSVersion -ne $RequiredOSVersion) {
            Write-Log "OS version ($OSVersion) does not meet requirement ($RequiredOSVersion). Exiting as compliant."
            exit 0
        }
        Write-Log "OS Version check passed ($OSVersion)."

        if ($CurrentUBR -lt $RequiredUBR) {
            Write-Log "OS build revision ($CurrentUBR) is below minimum ($RequiredUBR). Exiting as compliant."
            exit 0
        }
        Write-Log "OS build revision check passed ($CurrentUBR)."

        Write-Log "Device meets all prerequisites. Checking for ESU key..."
        $slmgrOutput = cscript.exe C:\Windows\System32\slmgr.vbs /dlv $ESUActivationID
        if ($slmgrOutput -match "License Status: Licensed") {
            Write-Log "ESU key is installed and licensed. Exiting as compliant."
            exit 0
        }

        Write-Log "ESU key not found. Remediation is required." -Level "WARN"
        exit 1

    }
    catch {
        $errorMessage = $_.Exception.Message -replace "[\r\n]", " "
        Write-Log "An unexpected error occurred: $errorMessage" -Level "ERROR"
        exit 1
    }
}

end {
    Write-Log "Script execution finished."
    "--------------------------------------------------" | Out-File -FilePath $LogFile -Append
}
