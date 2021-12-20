<# 
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! FIX OFFICE 365 GROUP MEMBERSHIP & SUBSCRIPTION !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Script will ensure that users with a UPN ending with specified domain ($domain) are members and subscribers of specified group ($group_email)
 #>

Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline

# OPTIONS
$domain = "@DOMAIN.com"  # users in this domain will be added to the group
$group_email = "group@DOMAIN.com"  # put the group email here
# END OF OPTIONS

Try {
    # this is necessary to catch non terminating errors: https://stackoverflow.com/questions/1142211/try-catch-does-not-seem-to-have-an-effect
    $ErrorActionPreference = "Stop";
    Write-Host("Working, please wait...")
    # Get the group to check/subscribe/add members to
    $group = Get-UnifiedGroup -Identity $group_email
    # Get all current members of the group
    $members = Get-UnifiedGroupLinks -Identity $group.Name -LinkType Members
    # Get all users within the specified $domain
    $users = Get-User -ResultSize Unlimited –RecipientTypeDetails UserMailbox -Filter "UserPrincipalName -like '*$($domain)'"

    # print list of users and info about the group they'll be joining
    Write-Host "
    `nGroup Name - $($group.DisplayName)
    `nGroup Email - $($group_email)
    `nThe following users will be checked and corrected as needed. Each user will be added as a member and subscribed to the group:`n" -ForegroundColor Green
    foreach ($user in $users) {
        write-host $user.UserPrincipalName
        }
    
    # prompt to continue if list looks good
    $continue = Read-Host "`nWould you like to proceed? (y/n)"

    if (($continue -eq 'y') -or ($continue -eq 'yes')) {
        Write-Host "Adding users to group that are not currently member"
        foreach ($user in $users) {
            if ($user.name -notin $members.Name) {
                Write-Host "Adding member:   $($user.UserPrincipalName)"
                Add-UnifiedGroupLinks -Identity $group.Name -LinkType Members -Links $user.UserPrincipalName
                }
            }
        }


    # Subscribe all current members that are not subscribed
    $subscribers = Get-UnifiedGroupLinks -Identity $group.Name -LinkType Subscribers
    Write-Host "Subscribing all members not currently subscribed..."
    foreach ($user in $users) {
        If ($user.Name -notin $subscribers.Name) {
            Write-Host "Adding $($user.UserPrincipalName)."
            Add-UnifiedGroupLinks -Identity $group.Name -LinkType Subscribers -Links $user.UserPrincipalName
            }
        }
# Done!
Write-Host "Done!" -ForegroundColor Green
} catch {
    Switch -Wildcard ($Error[0].CategoryInfo)
    {
        "*ManagementObjectAmbiguousException*" {
            $answer = 'n'
            $answer = Read-Host "$($member.Name) is too ambiguous. Would you like to input an email address? (y or n)?"
            if (($answer -eq 'y') -or ($answer -eq 'yes')) {
                $email = Read-Host "Input an email address or type 'cancel'. Example: $($user.Name)@bazarsolutions.com"
                if ($email -ne 'cancel') {
                    Add-UnifiedGroupLinks -Identity $group.Name -LinkType Subscribers -Links $email
                }
            }
        }
        Default {
            Write-Host "There was an error subscribing all users in ""$($group.DisplayName)""." -ForegroundColor Red
            Write-Host $($Error[0].Exception) -ForegroundColor Red
        }
    }
    $ErrorActionPreference = "Continue"; # Reset the error action pref to default
    continue
}
