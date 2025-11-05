<#
.SYNOPSIS
    Installs the Windows 10 ESU MAK key on the local device. Intended for deployment via Intune.

.DESCRIPTION
    This script installs and activates the Windows 10 Year 1 ESU MAK key. It is designed to be
    deployed through Microsoft Intune, running directly on the target device. It performs a series
    of prerequisite checks (OS version, Edition, and minimum build number), verifies if the key is
    already installed, logs all actions to a local file, and outputs status messages for Intune reporting.

.NOTES
    Author: Jules
    Date: 2025-10-30
    Version: 2.4
    - Added explicit Activation ID to the /ato command for more reliable activation.
    - Corrected prerequisite check to use the OS build number (UBR).
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

begin {
    # --- Script Configuration ---
    $ESUKey = "K4VWN-3GQCW-WRY4K-2PCKV-G6TR8"
    $ESUActivationID = "f520e45e-7413-4a34-a497-d2765967d094" # Win10 ESU Year1
    $RequiredOSVersion = "22H2"
    $RequiredUBR = 5131 # UBR corresponds to KB5046613 or later
    # --------------------------

    $PartialKey = $ESUKey.Split('-')[-1]

    # Log file will be in a standard, non-user-specific location.
    $LogDirectory = "C:\ProgramData\Microsoft\Intune\Logs"
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }
    $LogFile = Join-Path -Path $LogDirectory -ChildPath "Install-Win10ESU-Intune.log"

    # Function to write log entries to file and console
    function Write-Log {
        param(
            [string]$Message,
            [string]$Level = "INFO"
        )
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] - $Message"
        $logEntry | Out-File -FilePath $LogFile -Append
        Write-Output $logEntry # This ensures output is captured by Intune
    }

    # Log file header
    "--------------------------------------------------" | Out-File -FilePath $LogFile -Append
    Write-Log "ESU Key Installation Script Started."
}

process {
    try {
        # 1a. OS Version and Edition Checks
        Write-Log "Performing OS eligibility checks..."
        $OSInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $OSVersion = $OSInfo.DisplayVersion
        $OSEdition = $OSInfo.EditionID
        $CurrentUBR = $OSInfo.UBR

        if ($OSVersion -ne $RequiredOSVersion) {
            Write-Log "Unsupported OS version. Required: $RequiredOSVersion. Found: $OSVersion." -Level "ERROR"
            throw "Unsupported OS version: $OSVersion."
        }
        Write-Log "OS Version check passed (Required: $RequiredOSVersion, Found: $OSVersion)."

        if ($OSEdition -like "*EnterpriseS*" -or $OSEdition -like "*IoTEnterpriseS*") {
            Write-Log "Unsupported LTSC OS Edition found: $OSEdition." -Level "ERROR"
            throw "Unsupported LTSC OS Edition: $OSEdition."
        }
        Write-Log "OS Edition check passed (Not LTSC). Found: $OSEdition."

        # 1b. Prerequisite Update Check (UBR)
        Write-Log "Checking for minimum OS build revision (UBR)..."
        if ($CurrentUBR -lt $RequiredUBR) {
            Write-Log "Unsupported OS build. Required UBR: $RequiredUBR or higher. Found: $CurrentUBR." -Level "ERROR"
            throw "Unsupported OS build revision: $CurrentUBR."
        }
        Write-Log "OS build revision check passed (Required: $RequiredUBR or higher, Found: $CurrentUBR)."

        # 2. Check if ESU key is already installed
        Write-Log "Checking for existing ESU key..."
        $slmgrOutput = cscript.exe C:\Windows\System32\slmgr.vbs /dlv
        if ($slmgrOutput -match "Partial Product Key: $PartialKey") {
            Write-Log "ESU key ending in '$PartialKey' is already installed." -Level "INFO"
            "--------------------------------------------------" | Out-File -FilePath $LogFile -Append
            return # Exit successfully
        }
        Write-Log "No existing ESU key found. Proceeding with installation."

        # 3. Install the ESU key
        Write-Log "Installing ESU product key..."
        $installOutput = cscript.exe C:\Windows\System32\slmgr.vbs /ipk $ESUKey
        if (($installOutput -join ' ') -notlike "*successfully*") {
            Write-Log "Failed to install product key. Details: $($installOutput -join ' ')" -Level "ERROR"
            throw "Failed to install product key."
        }
        Write-Log "Product key installed successfully."
        Start-Sleep -Seconds 5

        # 4. Activate the ESU key
        Write-Log "Activating ESU product key with Activation ID: $ESUActivationID..."
        $activationOutput = cscript.exe C:\Windows\System32\slmgr.vbs /ato $ESUActivationID
        if (($activationOutput -join ' ') -like "*successfully*") {
            Write-Log "Successfully activated the ESU product key." -Level "SUCCESS"
        }
        else {
            Write-Log "Product key installed, but activation failed. Details: $($activationOutput -join ' ')" -Level "ERROR"
            throw "Activation failed."
        }
    }
    catch {
        # This will catch any terminating errors from the 'try' block
        $errorMessage = $_.Exception.Message -replace "[\r\n]", " "
        Write-Log "An error occurred during script execution: $errorMessage" -Level "ERROR"
        # Exit with a non-zero code to signal failure to Intune
        exit 1
    }
}

end {
    Write-Log "Script execution finished."
    "--------------------------------------------------" | Out-File -FilePath $LogFile -Append
}
