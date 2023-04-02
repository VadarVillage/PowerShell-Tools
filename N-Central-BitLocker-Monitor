# By Tim Hargrove
Function appendStatusString ($message, $statusString) {
    <# Removes default status string from, and appends new string to the final message
        usage:
            $statusString = appendStatusString "some text to append" $statusString
            $statusString = appendStatusString -message "some text to append" -staStr $statusString
            $statusString = appendStatusString $someString $statusString
            #>

    $statusString = $statusString.replace($statusStringDefault, "")
    $statusString = -join($statusString, " ", "$($statusStringPrefix)$($message)")

    return $statusString
}

Function printStatusString ($statusString) {
    <# splits $statusString on $statusStringPrefix and prints each line for n-central
        call function any time the script exits - This will act as a log in the Self-Heal section of each device

        usage (this function requires no arguments):
            printStatusString
    #>
    $messages = $statusString.Split($statusStringPrefix)
    Write-Host "`n`n######################################### Summary #################################################"
    foreach ($message in $messages) {Write-Host "$($message)"}
    Write-Host "`n`n###################################################################################################"
}

Function tpmReadyCheck {
    try {
        # Check for TPM, exit if no TPM
        $tpmData = Get-Tpm
        $str = "(TpmPresent: $($tpmData.TpmPresent), TpmReady: $($tpmData.TpmReady), TpmEnabled: $($tpmData.TpmEnabled), TpmActivated: $($tpmData.TpmActivated))"

        # if TPM is ready, then proceed to next step
        if ($tpmData.TpmReady -eq $true) { 
            $message = "Pass: $str"
        }
        # if TPM is enabled, then proceed to next step
        elseif ($tpmData.TpmEnabled -eq $true) { 
            $message = "Pass: $str"
        }
        # if TPM is present, then proceed to next step
        elseif ($tpmData.TpmPresent -eq $true) { 
            $message = "Pass: $str"
        }
        # if there is no TPM
        elseif ($tpmData.TpmPresent -eq $false) { 
            $message = "Fail: $str"
        }
        # if there is a TPM but it is disabled
        elseif ($tpmData.TpmEnabled -eq $false) {
            $message = "Fail: $str"
        }
        # if TPM is not ready - this could be for lots of reasons, including OS compatibility
        elseif ($tpmData.TpmReady -eq $false) {
            $message = "Fail: $str"
        }
        else {
            $message= "Unknown: $str"
        }

        return $message
    }
    catch { 
        $string_err = "$($_.Exception)"

        Switch -wildcard ($string_err.ToLower()) {
            "*the tbs service is not running and could not be started*" { $message = "(None)" }
            "*not recognized as the name of a cmdlet*" { $message = "(None)" }
            default { $message = "(Error: $string_err)" }
        }

        return $message
    }
}

Function blSettingsCheck {
    try {
        # Check status of Bitlocker
        $bitlockerData = Get-BitLockerVolume -MountPoint "$($driveLetter):"
        $str =  "VolumeStatus: $($bitlockerData.VolumeStatus), EncryptionPercentage: $($bitlockerData.EncryptionPercentage)%, ProtectionStatus: $($bitlockerData.ProtectionStatus)"
        Write-Host "$($bitlockerData | Format-Table | Out-String)"

        # Fail: if bitlocker is off and encryption is not in progress, then exit. If encryption is in progress, then BL will report as OFF (false positive)
        if (($bitlockerData.ProtectionStatus -eq "Off") -and ($bitlockerData.VolumeStatus -ne 'EncryptionInProgress')) {
            if (Test-Path $blDaysFile) { Remove-Item -Path $blDaysFile -Force }
            $message = "Off: Bitlocker is off. $str"
        }
        # Pass or Fail: if encryption is in progress for more than $blDays, then set to fail. Else, pass
        elseif ($bitlockerData.VolumeStatus -eq 'EncryptionInProgress') {
            $now = Get-Date

            # if there is already a datetime on file, then compare
            if (Test-Path $blDaysFile) { 
                $priorNow = [datetime](Get-Content -Path $blDaysFile)
                $diff = NEW-TIMESPAN -Start $priorNow -End $now
                
                # the drive has been encrypting for $blMaxDays
                if ($diff.Days -gt $blMaxDays) {
                    $message = "Fail: Encryption in progress for $($diff.Days) days. $str"
                }
                # the drive has been encrypting for too long
                elseif ($diff.Days -gt $blDays) {
                    $message = "Warning: Encryption in progress for $($diff.Days) days. $str"
                }
                # the drive is still encrypting, but within the limit
                else {
                    $message = "Pass: Encryption in progress for $($diff.Days) days. $str"
                }
            }
            # if there is no datetime on file, then create a datetime file for comparison later
            else {
                New-Item -Path $blDaysFile
                Set-Content $blDaysFile $now.ToString()
                $message = "Pass: Encryption in progress. $str"
            }
        }
        # Pass: if bitlocker is on
        elseif ($bitlockerData.ProtectionStatus -eq "On") {
            if (Test-Path $blDaysFile) { Remove-Item -Path $blDaysFile -Force }
            $message = "Pass: Bitlocker is on. $str"
        }
        else {
            $message= "Unknown: $str"
        }

        return $message
    }
    catch {
        $string_err = "$($_.Exception)"

        Switch -wildcard ($string_err.ToLower()) {
            "*does not have an associated bitLocker volume*" { $message = "None" }
            "*not recognized as the name of a cmdlet*" { $message = "None" }
            default { $message = "Error: $string_err" }
        }

        return $message
    }
}

Function blKeyCheck {
    $found = $false

    try {
        $bitlockerData = Get-BitLockerVolume -MountPoint "$($driveLetter):"

        if (!$found) {
            foreach ($item in $bitlockerData.KeyProtector) { 
                if ($item.KeyProtectorType -eq "RecoveryPassword") { 
                    $message = "Pass"
                    $recoveryKey = $item.RecoveryPassword
                    $found = $true
                    break
                } 
            }
        }

        if (!$found) {
            $message = "None"
            $recoveryKey = "None"
            $found = $true
        }

        return $recoveryKey, $message
    }
    catch {
        $string_err = "$($_.Exception)"

        Switch -wildcard ($string_err.ToLower()) {
            "*does not have an associated bitLocker volume*" { $message = "None" }
            "*not recognized as the name of a cmdlet*" { $message = "None" }
            default { $message = "Error: $string_err" }
        }

        $recoveryKey = "None"
        $found = $false

        return $recoveryKey, $message
    }

}

# initialize variables
# Start-Transcript -Path "C:\Temp\bitlocker_log.txt" -ErrorAction SilentlyContinue
try {
    # ##################################################### Variables ##################################################
    Write-Host "Initializing Variables"
    $ErrorActionPreference = “Stop”
    $ampName = "BAZ - Bitlocker - Custom Device Properties"
    $statusStringPrefix = "#~#"  # this is added to the beginning of the string each time you call the function "appendStatusString"
    $statusStringDefault = "Normal: AMP Error: '$($ampName)' exited early, there is probably an error in the powershell script."
    $statusString = $statusStringDefault

    <# OUTPUT VARIABLES - these are output to N-Central:#>
    $blStatus = @()
    $recoveryKey = @()

    <# Variables used to monitor the time running time of "EncryptionInProgress" bitlocker status #>
    $blDaysFile = "C:\Temp\bitlocker.timestamp"  # this file contains the timestamp
    $blDays = 2  # number of days to allow a computer to encrypt the drive before warning that it is taking a long time
    $blMaxDays = 10

    <# Drives #>
    $drives = Get-PSDrive -PSProvider FileSystem
    $rootDrive = $env:SystemDrive[0]

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Check TPM chip~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Write-Host "Starting tpmReadyCheck"
    $message = tpmReadyCheck
    $statusString = appendStatusString "TPM - $message" $statusString
    $blStatus += "TPM: ($message)"

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~For each drive letter, get bitlocker info~~~~~~~~~~~~~~~~~~~~
    foreach ($drive in $drives) {
        if ($drive.DisplayRoot) { 
            # mapped drives have a DisplayRoot, we want to skip these
            continue
        }
        $blSetStatus = ""
        $blKeyStatus = ""
        $blKey = ""
        $driveLetter = ($drive.Root)[0]
        if ($driveLetter -eq $rootDrive) { $root = "(OS) " } else { $root = "" }

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Check bitlocker status~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        Write-Host "Starting blSettingsCheck for drive $($driveLetter)$($root)"
        $message = blSettingsCheck
        $statusString = appendStatusString "$($driveLetter) $($root)Drive Bitlocker - $message" $statusString

        switch -wildcard ($message.ToLower()) {
            "*pass:*" { $continue = $true }
            "*warning: encryption*" { $continue = $true } # encryption has been in progress for a few days
            "*fail: encryption*" { $continue = $true }  # encryption has been in progress for way too long
            "*fail: this version of windows*" { $continue = $false }
            "*error:*" { $continue = $false; $message = "None" }
            "*off:*" { $continue = $false; $message = "Off" }
            "*unknown:*" { $continue = $true }
            default { $continue = $true; $message = "None" }
        }

        $blSetStatus = $message
        
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Check Bitlocker key~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        Write-Host "Starting blKeyCheck for drive $($driveLetter) $($root)"
        $blKey, $message = blKeyCheck

        $blKeyStatus = $message

        $statusString = appendStatusString "$($driveLetter) $($root)Drive Password: $blKey" $statusString
        $statusString = appendStatusString "$($driveLetter) $($root)Drive - $message" $statusString

        $blStatus += "$($driveLetter) Drive: ($($root)Bitlocker: $($blSetStatus), $($root)Password: $($blKeyStatus))"
        $recoveryKey += "$($driveLetter) $($root)Drive Password: $blKey"
    }

    $blStatus = $blStatus -join " | | "
    $recoveryKey = $recoveryKey -join " | | "

    printStatusString $statusString
}
catch {
    $string_err = "$($_.Exception)"
    Write-Host "ERROR: $string_err"
    $blStatus = $blStatus -join ", "
    $recoveryKey = $recoveryKey -join ", "

    printStatusString $statusString
}
# Stop-Transcript -ErrorAction SilentlyContinue
