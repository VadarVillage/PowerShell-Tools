# by Tim Hargrove

# this script will attempt to uninstall things, if it fails you can view the uninstall string in n-central
# if you intend to run this script outside of n-central, you must provide a value for the below variables:
# $appKeyWord = ""  # unique part of the software name, or the whole name - be wary of ambiguous terminology
# $wArgs = ""  # command line switches

<# ####################### values provided by n-able amp input #######################################
$appKeyWord = unique part of the software name, or the whole name - be wary of ambiguous terminology
$appKeyWord = "Windows Software Probe"

$wArgs = command line switches
$wArgs = "/arg1 /arg2 /arg3"     or     $args = "/arg1arg2arg3"
#>

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

Function msiExecFix ($uninstallString) {
    # n-able stores the uninstall string erroniously - like this "MsiExec.exe /I{E398D23D-110B-4F07-B733-3B4C8CA20778}"
    $appUID = ($uninstallString.Split("{")[1]).Split("}")[0]
    $uninstallString = "{$appUID}"
    return $uninstallString
}

try {
    <# ############################## Initialize Variables ################################################ #>
    Write-Host "Initializing Variables"
    $ampName = "BAZ - Silent Uninstall Helper"
    $statusStringPrefix = "#~#"  # this is added to the beginning of the string each time you call the function "appendStatusString"
    $statusStringDefault = "Normal: AMP Error: '$($ampName)' exited early, there is probably an error in the powershell script."
    $statusString = $statusStringDefault
    $aArgs = $wArgs.Split(" ")
    <# #################################################################################################### #>

    # this is where windows keeps uninstall keys
    # n-able appears to store their keys in "HKLM:\SOFTWARE\WOW6432Node..."
    $regLocations = @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )

    # search the regLocations keys for UninstallString
    $uninstallString = "none"
    foreach ($key in (Get-ChildItem $regLocations)) {
        if ($key.GetValue("DisplayName") -like "*$($appKeyWord)*") {
            $uninstallString = $key.GetValue("UninstallString")
            break
        }
    }

    if ($uninstallString -eq "none") { 
        $message = "Uninstall String not found in the registry for key word: $($appKeyWord)"
        $statusString = appendStatusString -message $message -statusString $statusString
    }
    elseif ($uninstallString.StartsWith("MsiExec.exe")) {
        $uninstallString = msiExecFix $uninstallString
        $message = "Found uninstall string for keyword: $($appKeyWord)`nAttempting uninstall: $($uninstallString) $($wArgs)"
        $statusString = appendStatusString -message $message -statusString $statusString
        $aArgs += "/X"
        $aArgs += $uninstallString
        Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList $aArgs
    }
    else {
        $message = "Found uninstall string for keyword: $($appKeyWord)`nAttempting uninstall: $($uninstallString) $($wArgs)"
        $statusString = appendStatusString -message $message -statusString $statusString
        & "$uninstallString" $aArgs
    }

    printStatusString $statusString
}
catch {
    $message = $_ | Out-String
    $statusString = appendStatusString -message $message -statusString $statusString
    printStatusString $statusString
}
