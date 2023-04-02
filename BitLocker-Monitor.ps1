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

Function extractBlKey ($nableData) {
    $separator = " | | "
    $cDrvKey = ($nableData.split([string[]]$separator,[StringSplitOptions]::None)[0]).Split(" ")[4]
    return $cDrvKey
}

Function resolveEnforceLevel ($orgLevel, $deviceLevel) {
    <# compares $deviceLevel to $orgLevel and sets $enforceLevel
        $enforceLevel possible values: 'Disable', 'Enforce', 'Monitor', 'Follow Org Level'
    
        usage (this function requires no arguments):
            resolveEnforceLevel
    #>
    Switch ($deviceLevel) {
        "Follow Org Level" { $enforceLevel = $orgLevel }
        "Disabled" { $enforceLevel = "Disable" }
        "Enforce" { $enforceLevel = $deviceLevel }
        "Monitor" { $enforceLevel = $deviceLevel }
        default { $enforceLevel = $deviceLevel }
    }
    return $enforceLevel
}

Function updateStatus ($newStatus, $status) {
    <# use this function to update the value of $status
        $status default value: 1
            if the amp fails near the start of this script, the the value will be 1
            possible $status values:
                * 0        Passed (the bitlocker key in n-able matches the key found by this script)
                * 1 - 999: Warning (in most cases, bitlocker is disabled but the old key is still in n-able)
                * 1000:    Failed (the bitlocker key in n-able DOES NOT match the key found by this script)
        
        usage:
            updateStatus -$newStatus 1000
    #>
        # Set $status to $newStatus if $newStatus is greater
        if (($newStatus -gt $status) -or ($status -eq 1)) { $status = $newStatus }

        return $status
    }

Function applyEnforceLevel($disable, $monitor, $enforce, $status) {
    <# updates $status code and $message, based on $enforceLevel
        the Status value returned, is based on the value of $enforceLevel
            $dStatus: "Disable"
            $mStatus: "monitor"
            $eStatus: "enforce"

        usage:
            applyEnforceLevel 0, Pass, 999, Warning, 1000, Fail
    #>

    Switch ($enforceLevel.ToLower()) {
        "disable" { 
            $status = updateStatus -newStatus $disable.status -status $status
            $statusMessage = $disable.message
        }
        "monitor" { 
            $status = updateStatus -newStatus $monitor.status -status $status
            $statusMessage = $monitor.message
        }
        "enforce" { 
            $status = updateStatus -newStatus $enforce.status -status $status
            $statusMessage = $enforce.message
        }
    }

    return $status, $statusMessage
}

Function tpmReadyCheck {
    # Check for TPM, exit if no TPM
    $tpmData = Get-Tpm
    $str = "$($statusStringPrefix)TpmPresent: $($tpmData.TpmPresent), TpmReady: $($tpmData.TpmReady), TpmEnabled: $($tpmData.TpmEnabled)"

    # if TPM is ready, then proceed to next step
    if ($tpmData.TpmReady -eq $true) { 
        $message = "TPM ready. $str"
    }
    # if TPM is enabled, then proceed to next step
    elseif ($tpmData.TpmEnabled -eq $true) { 
        $message = "TPM enabled. $str"
    }
    # if TPM is present, then proceed to next step
    elseif ($tpmData.TpmPresent -eq $true) { 
        $message = "TPM present. $str"
    }
    # if there is no TPM
    elseif ($tpmData.TpmPresent -eq $false) { 
        $message = "TPM not present. $str"
    }
    # if there is a TPM but it is disabled
    elseif ($tpmData.TpmEnabled -eq $false) {
        $message = "TPM disabled. $str"
    }
    # if TPM is not ready - this could be for lots of reasons, including OS compatibility
    elseif ($tpmData.TpmReady -eq $false) {
        $message = "TPM not ready. $str"
    }
    # at this point, we're just going to continue and see what happens
    else {
        $message= "Can't determine TPM state. $str"
    }

    return $message
}

Function blSettingsCheck {
    # Check status of Bitlocker
    $bitlockerData = Get-BitLockerVolume -MountPoint "$($driveLetter):"
    $str =  "$($statusStringPrefix)Bitlocker:`n$($bitlockerData | Format-Table | Out-String)"

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
    # at this point, we'll just throw a warning
    else {
        $message= "Can't determine Bitlocker state. $str"
    }

    return $message
}

Function blKeyCheck($nableKey) {
    <#
    $nableData is the value of the custom property stored in n-able "BitLocker Key - C Drive"
    $nableKey is the bitlocker key stored in nable, derived from $nableData
    #>
    $bitlockerData = Get-BitLockerVolume -MountPoint "$($driveLetter):"
    $message = "Protection Status: $($bitlockerData.ProtectionStatus), Volume Status: $($bitlockerData.VolumeStatus)"
    $continue = $false

    foreach ($item in $bitlockerData.KeyProtector) { 
        if ($nableKey -eq $item.RecoveryPassword) {
            $recoveryKey = $item.RecoveryPassword
            $continue = $true
            break 
        } 
    }

    return $continue, $message, $recoveryKey
}

Function blEnable {
    $bl = Enable-BitLocker -MountPoint "$($driveLetter):" -EncryptionMethod Aes256 -TpmProtector -SkipHardwareTest -ErrorAction SilentlyContinue -ErrorVariable err
    $void = Add-BitLockerKeyProtector -MountPoint "$($driveLetter):" -RecoveryPasswordProtector -ErrorAction SilentlyContinue

    if ($err) {
        $errMessage = $err | Out-String

        if ($errMessage -like "*This version of Windows does not support this feature*") {
            $message = "Fail: This version of Windows does not support Bitlocker."
        }
        else{
            $message = "Fail: Error - $err"
        }
    }

    else{
        # Check bitlocker status until it is on, or fail if loop limit is reached
        $i = 0
        $iMax = 10
        $continue = $true
        while ($continue) {
            if ($i -ge $iMax) { break }
            $i += 1
        
            Start-Sleep -Seconds 10
            $message = blSettingsCheck
            if (!($message -like "Off:*")) { $continue = $false }
        }
    }

    return $message
}

# initialize variables
# Start-Transcript -Path "C:\Temp\bitlocker_log.txt" -ErrorAction SilentlyContinue
try {
    # ##################################################### Variables ##################################################
    Write-Host "Initializing Variables"
    $ampName = "BAZ - Bitlocker - Monitor"
    $statusStringPrefix = "#~#"  # this is added to the beginning of the string each time you call the function "appendStatusString"
    $statusStringDefault = "Normal: AMP Error: '$($ampName)' exited early, there is probably an error in the powershell script. `nBitlocker key currently stored in N-Able: $($nableData)"
    $statusString = $statusStringDefault
    $blStatusString = ""
    $recoveryKey = ""  # example data: C (OS) Drive Password: 671803-165088-585596-414414-611237-419342-551265-456951 | | D Drive Password: None | | E Drive Password: None

    <# OUTPUT VARIABLES - these are output to N-Central:
        possible $status values:
        * 0        Passed (the bitlocker key in n-able matches the key found by this script)
        * 1 - 999: Warning (in most cases, bitlocker is disabled but the old key is still in n-able)
        * 1000:    Failed (the bitlocker key in n-able DOES NOT match the key found by this script)
    #>
    $status = 1
    $blStatus = @{}
    $tpmStatus = $statusStringDefault
    $blSettingsStatus = $statusStringDefault
    $blKeyStatus = $statusStringDefault

    <# INPUT VARIABLES - these are input by N-Central: #>
    $driveLetter = $driveLetter[0]  # strip drive letter from other characters like "C:", or "C:\", etc.
    # $driveLetter = $env:SystemDrive
    # $enforceLevel: 'Disable', 'Enforce', 'Monitor' - Derived from values provided by N-Able ($orgLevel and $deviceLevel)
    $enforceLevel = resolveEnforceLevel -orgLevel $orgLevel -deviceLevel $deviceLevel

    <# Variables used to monitor the time running time of "EncryptionInProgress" bitlocker status #>
    $blDaysFile = "C:\Temp\bitlocker-$driveLetter-drive.bazar"  # this file contains the timestamp
    $blDays = 2  # number of days to allow a computer to encrypt the drive before warning that it is taking a long time
    $blMaxDays = 10

    # default status string and integer - these are the most commonly used options for pass, warning, or fail
    $pass = @{"status" = 0; "message" = "Pass"}
    $warning = @{"status" = 999; "message" = "Warning"}
    $fail = @{"status" = 1000; "message" = "Fail"}

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Check TPM chip~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Write-Host "Starting tpmReadyCheck"
    $message = tpmReadyCheck

    # default values, override as necessary.
    $disable = $pass
    $monitor = $warning
    $enforce = $fail

    <#
    * If the TPM is ready, then set the status to 0 and the message to "Pass", regardless of the "Enforce Level" set in n-able
    * If the TPM is NOT ready, then run the function "applyEnforceLevel" and provide the desired message for each Enforce Level
        "applyEnforceLevel" will determine which status message to send back to n-central based on the Enforce Level
    #>
    Switch -wildcard ($message.ToLower()) {
        "*tpm ready*" { $disable = $monitor = $enforce = $pass; $continue = $true }
        "*tpm enabled*" { $disable = $monitor = $enforce = $pass; $continue = $true }
        "*tpm present*" { $disable = $monitor = $enforce = $pass; $continue = $true }
        "*tpm not present*" { $enforce = $warning; $continue = $false }
        "*tpm disabled*" { $continue = $false }
        "*tpm not ready*" { $continue = $false }
        "*can't determine*" { $enforce = $warning; $continue = $false }
        default { $enforce = $warning; $continue = $false }
    }

    $blStatus.TPM = ($message.split($statusStringPrefix)[0])[0..80] -join ""
    $statusString = appendStatusString $message $statusString
    $blStatusString = "($($driveLetter) TPM: $($blStatus.TPM) || $($driveLetter) Bitlocker: Pass || $($driveLetter) Key: Pass)"

    if ($continue) {
        $status, $tpmStatus = applyEnforceLevel $disable $monitor $enforce $status
    }
    else {
        if ($deviceClass.ToLower() -eq "srv") { $disable = $monitor = $enforce = $pass }
        $status, $tpmStatus = applyEnforceLevel $disable $monitor $enforce $status
        $blStatus.blStatus = $blStatus.blKey = $blKeyStatus = $blSettingsStatus = $pass.message
        printStatusString $statusString

        return
    }

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Check bitlocker status~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Write-Host "Starting blSettingsCheck"
    $message = blSettingsCheck

    # default values, override as necessary
    $disable = $pass
    $monitor = $warning
    $enforce = $fail

    # if Bitlocker is off, try to turn it on before the final check. If it is still off, then stop
    if ($message -like "Off:*") { 
        if (($enforceLevel.ToLower() -eq "enforce") -and (($deviceClass.ToLower() -eq "lap") -or ($deviceClass.ToLower() -eq "wks"))) { $message = blEnable } 
    }

    switch -wildcard ($message.ToLower()) {
        "pass:*" {$disable = $monitor = $enforce = $pass; $continue = $true }
        "warning: encryption*" { $enforce = $warning; $continue = $true } # encryption has been in progress for a few days
        "fail: encryption*" { $continue = $true }  # encryption has been in progress for way too long
        "fail: this version of windows*" { $enforce = $warning; $continue = $false }
        "fail: error - " { $enforce = $warning; $continue = $false }
        "off:*" { $continue = $false }
        "can't determine*" { $enforce = $warning; $continue = $false }
        default { $enforce = $warning; $continue = $false }
    }

    $blStatus.blStatus = ($message.split($statusStringPrefix)[0])[0..80] -join ""
    $statusString = appendStatusString $message $statusString
    $blStatusString = "($($driveLetter) TPM: $($blStatus.TPM) || $($driveLetter) Bitlocker: $($blStatus.blStatus) || $($driveLetter) Key: Pass)"

    if ($continue) {
        $status, $blSettingsStatus = applyEnforceLevel $disable $monitor $enforce $status
    }
    else {
        if ($deviceClass.ToLower() -eq "srv") { $disable = $monitor = $enforce = $pass }
        $status, $blSettingsStatus = applyEnforceLevel $disable $monitor $enforce $status
        $blStatus.blKey = $blKeyStatus = $pass.message
        printStatusString $statusString

        return
    }
    
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Check Bitlocker key~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Write-Host "Starting blKeyCheck"
    $statusString = appendStatusString "Current key stored in N-Central: $($nableData)" $statusString
    Write-Host "`n`nCurrent key stored in N-Central: $($nableData)`n`n"
    $cDrvKey = extractBlKey -nableData $nableData
    $continue, $message, $recoveryKey = blKeyCheck -nableKey $cDrvKey
    $blStatus.blKey = ($message.split($statusStringPrefix)[0])[0..80] -join ""

    if ($continue -eq $false) {
        # If bitlocker key check failed
        $disable = $pass
        $monitor = $warning
        $enforce = $fail
        $status, $blKeyStatus = applyEnforceLevel $disable $monitor $enforce $status
        $statusString = appendStatusString $message $statusString
    }
    else {
        # If bitlocker key check passed
        $disable = $monitor = $enforce = $pass
        $status, $blKeyStatus = applyEnforceLevel $disable $monitor $enforce $status
        $statusString = appendStatusString $message $statusString
        Write-Host "This is the BL Key for $($driveLetter): $recoveryKey"
    }

    printStatusString $statusString

    $blStatusString = "($($driveLetter) TPM: $($blStatus.TPM) || $($driveLetter) Bitlocker: $($blStatus.blStatus) || $($driveLetter) Key: $($blStatus.blKey))"
}
catch {
    $string_err = $_ | Out-String
    Write-Host "ERROR: $string_err"
}
# Stop-Transcript -ErrorAction SilentlyContinue
