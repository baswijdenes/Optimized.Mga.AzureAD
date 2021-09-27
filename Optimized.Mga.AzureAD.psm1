#region functions 
function Get-AzureADDirectoryRoleMembers {
    [CmdletBinding()]
    param (
    )   
    begin {
        $AzureADAdmins = [System.Collections.Generic.List[System.Object]]::new()  
    }  
    process {
        $Roles = Get-Mga -URL 'https://graph.microsoft.com/v1.0/directoryRoles?$Select=id,displayName'
        foreach ($Role in $Roles) {
            try {
                $URL = 'https://graph.microsoft.com/v1.0/directoryRoles/{0}/members?$select=id,userPrincipalName,givenName,surname,displayName' -f $Role.Id 
                $Members = $null
                $Members = Get-Mga -URL $URL
                if ($null -ne $Members -and ($null -eq $Members.value)) {
                    foreach ($Member in $Members) {
                        try {
                            $Object = [PSCustomObject]@{
                                UserPrincipalName    = $Member.userPrincipalName
                                AdminRole            = $Role.displayName
                                PermanentlyActivated = $true
                            }
                            $AzureADAdmins.Add($Object)  
                        }
                        catch {
                            continue
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
    }   
    end {
        return $AzureADAdmins
    }
}

function Get-AzureADPIMDirectoryRoleMembers {
    [CmdletBinding()]
    param (
        
    ) 
    begin {
        $DirectoryRolesURL = 'https://graph.microsoft.com/beta/privilegedAccess/aadRoles/resources/3fb0eae6-990e-4f5f-b997-5fcc618dd30f/roleDefinitions'
        $RoleAssignmentURL = 'https://graph.microsoft.com/beta/privilegedAccess/aadRoles/resources/3fb0eae6-990e-4f5f-b997-5fcc618dd30f/roleAssignments'
        $RolesSelectURL = '{0}?$select=id,displayName' -f $DirectoryRolesURL
        $Roles = Get-Mga -URL $RolesSelectURL
        $RolesHash = @{}
        foreach ($Role in $Roles) {
            $RolesHash.Add($Role.id, $Role)
        }
        $AllUsersURL = 'https://graph.microsoft.com/beta/users?$select=userPrincipalName,id,accountEnabled&$top=999'
        $AllUsers = Get-Mga -URL $AllUsersURL
        $AllUsersHash = @{}
        foreach ($User in $AllUsers) {
            $AllUsersHash.Add($User.id, $User)
        }
    }   
    process {
        $RoleAssignments = Get-Mga -URL $RoleAssignmentURL
        $RoleAssignmentsReport = [System.Collections.Generic.List[System.Object]]::new()  
        foreach ($Assignment in $RoleAssignments) {
            try {
                $User = $null
                $User = $AllUsersHash[$Assignment.subjectId]
                $Role = $null
                $Role = $RolesHash[$Assignment.roleDefinitionId]
                $Object = [PSCustomObject]@{
                    User           = $User.userPrincipalName
                    AccountEnabled = $User.accountEnabled
                    Role           = $Role.displayName
                }
                $RoleAssignmentsReport.Add($Object)
            }
            catch {
                continue
            }
        }
    } 
    end {
        return ($RoleAssignmentsReport | Where-Object { ($_.AccountEnabled -eq $true) -and ($null -ne $_.user) })
    }
}

function Get-AzureADUsersPerOnPremiseOU {
    [CmdletBinding()]
    param (
        [parameter(mandatory)]
        $OU
    )
    begin {
        $Select = '$Select={0}' -f "givenName,surname,Description,onPremisesSamAccountName,accountEnabled,onPremisesDistinguishedName"
        $URL = 'https://graph.microsoft.com/beta/users?$Top=999&{0}' -f $Select
    }
    process {
        try {
            $AllUsers = Get-Mga $URL
            $Return = $AllUsers | Where-Object { ($_.onPremisesDistinguishedName -like "*$OU") -and ($_.AccountEnabled -eq $true) } 
        }
        catch {
            throw $_.Exception.Message
        }
    }  
    end {
        return $Return
    }
}

function Get-AzureADUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Guest', 'Member')]
        $UserType
    )
    begin {
        $filter = 'UserType eq ''{0}''' -f $UserType
        Write-Verbose "Get-AzureADUsers: begin: Filter: $filter."
        $URL = 'https://graph.microsoft.com/beta/users?$filter=({0})&$select=displayName,userPrincipalName,createdDateTime,signInActivity' -f $filter
    }
    process {
        try {
            Write-Verbose "Get-AzureADUsers: process: Starting search..."
            $List = Get-Mga -URL $URL
        }
        catch {
            throw $_.Exception.Message
        }    
    }
    end {
        Write-Verbose "Get-AzureADUsers: end: Running extra check to see if property SignInActivity is available."
        foreach ($L in $List) {
            $SignInActivity = $null
            $SignInActivity = $L.psobject.Properties['SignInActivity']
            if ($SignInActivity.Name -eq 'SignInActivity') {
                Write-Verbose "Get-AzureADUsers: end: Property is available in content. Returning output."
                $PropertyActive = $true
                break
            }
        }
        if ($PropertyActive) {
            return $List
        }       
        else {
            throw 'STOPPING SCRIPT.. There is no SignInActivity at all in the output. Stopping script otherwise we will delete all guest users.'
        }
    }
}

function Remove-AzureADUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        $Users,
        [Parameter(Mandatory = $true)]
        $DaysOld,
        [Parameter(Mandatory = $true)]
        $DeleteAfterDays,
        [Parameter(Mandatory = $false)]
        [switch]
        $ReportOnly
    )  
    begin {
        $UsersList = [System.Collections.Generic.List[System.Object]]::new()
        foreach ($User in $Users) {
            try {
                if ($null -eq ($User.PsObject.Properties | Where-Object { $_.Name -eq 'SignInActivity' })) {
                    $SignInDate = $null
                    Write-Verbose 'Remove-AzureADUsers: begin: The property SignInActivity is not available. This could either be because the user has not logged on, or has not logged in for 90 days.'
                    If (([Datetime]$User.createdDateTime).AddDays($DaysOld) -ge (Get-Date)) {
                        Write-Verbose "Remove-AzureADUsers: begin: Account is is created between now and $DaysOld ago. Deletion = False."
                        $Deletion = $false
                    } 
                    else {
                        Write-Verbose "Remove-AzureADUsers: begin: Account is older than $DaysOld days and will be deleted from AzureAD. Deletion = True."
                        $Deletion = $true
                    }  
                }
                else {
                    Write-Verbose "Remove-AzureADUsers: begin: Login found: $([Datetime]$User.signInActivity.lastSignInDateTime)"
                    $SignInDate = [Datetime]$User.signInActivity.lastSignInDateTime
                    If (([Datetime]$User.signInActivity.lastSignInDateTime) -ge (Get-Date).AddDays(-$DeleteAfterDays)) {
                        Write-Verbose "Remove-AzureADUsers: begin: LastLogin is less than 30 days ago. Deletion = False."
                        $Deletion = $false
                    }
                    else {
                        Write-Verbose "Remove-AzureADUsers: begin: LastLogin is longer than 30 days ago. Deletion = True."
                        $deletion = $true
                    }
                }
                $Object = [PSCustomObject] @{
                    userPrincipalName  = $User.userPrincipalName
                    UserID             = $User.id
                    LastSignInDateTime = $SignInDate
                    CreatedDateTime    = [Datetime]$User.createdDateTime
                    Deletion           = $Deletion
                }
                $UsersList.Add($Object)
            }
            catch {
                continue
            }
        }
    }
    process {
        if ($ReportOnly -eq $false) {
            $EndUsers = $UsersList | Where-Object { $_.Deletion -eq 'true' }
            $global:endusers = $EndUsers
            foreach ($EndUser in $EndUsers) {
                try {
                    $Filter = $EndUser.UserId
                    $URL = 'https://graph.microsoft.com/v1.0/users/{0}' -f $Filter
                    Write-Verbose "Remove-AzureADUsers: process: We will delete user $($EndUser.userPrincipalName) on URL: $URL"
                    Delete-Mga -URL $URL
                }
                catch {
                    continue
                }
            }
        }
        else {
            Write-Verbose "Remove-AzureADUsers: process: ReportOnly equals $ReportOnly... returning output."
        }
    }
    end {      
        return $UsersList
    }
}
#endregion