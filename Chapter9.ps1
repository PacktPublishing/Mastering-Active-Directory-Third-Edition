# View Syntax for New-ADOrganizationalUnit

Get-Command New-ADOrganizationalUnit -Syntax

# Create new OU

New-ADOrganizationalUnit -Name "Asia" -Description "Asia Branch"

# OU properties

Get-ADOrganizationalUnit -Identity "OU=Asia,DC=rebeladmin,DC=com"

# Change OU Attributes

Get-ADOrganizationalUnit -Identity "OU=Asia,DC=rebeladmin,DC=com" | Set-ADOrganizationalUnit -ManagedBy "Asia IT Team"

# Protect OU from accedental deletion

Get-ADOrganizationalUnit -Identity "OU=Asia,DC=rebeladmin,DC=com" | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true

# Create Sub-OU

New-ADOrganizationalUnit -Name "Users" -Path "OU=Asia,DC=rebeladmin,DC=com" -Description "Users in Asia Branch"

# Move Object to OU

Get-ADUser "tuser3" | Move-ADObject -TargetPath "OU=Users,OU=Asia,DC=rebeladmin,DC=com"

# Move Multiple Object to OU

Get-ADUser -Filter 'Name -like "Test*"' -SearchBase "OU=Users,OU=Europe,DC=rebeladmin,DC=com" | Move-ADObject -TargetPath "OU=Users,OU=Asia,DC=rebeladmin,DC=com"

# Remove OU

Remove-ADOrganizationalUnit "OU=Laptops,OU=Europe,DC=rebeladmin,DC=com"