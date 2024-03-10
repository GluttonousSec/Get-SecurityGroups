# Check if Active Directory module is installed
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    # Install Active Directory module in the current user scope
    Install-Module -Name ActiveDirectory -Scope CurrentUser -Force
}

# Import Active Directory module
Import-Module ActiveDirectory

# Define output CSV file path
$outputFile = "SecurityGroupAudit.csv"

# Initialize an array to store audit results
$auditResults = @()

# Retrieve all security groups from Active Directory
$securityGroups = Get-ADGroup -Filter {GroupCategory -eq "Security"} -Properties * | Sort-Object Name

# Iterate through each security group
foreach ($group in $securityGroups) {
    $members = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.ObjectClass -eq "User" -or $_.ObjectClass -eq "Group" } | Select-Object -ExpandProperty Name -Unique

    # Create a custom object for each security group
    $groupInfo = [PSCustomObject]@{
        Name = $group.Name
        Description = $group.Description
        Members = $members -join ","
        MemberCount = $members.Count
        ManagedBy = $group.ManagedBy
        Created = $group.Created
        Modified = $group.Modified
        DN = $group.DistinguishedName
    }

    # Add the group information to the audit results array
    $auditResults += $groupInfo
}

# Export audit results to CSV file
$auditResults | Export-Csv -Path $outputFile -NoTypeInformation

Write-Host "Security group audit completed. Results exported to: $outputFile"
