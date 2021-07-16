# Syntax for New-ADUser

Get-Command New-ADUser -Syntax

# Create New User

New-ADUser -Name "Talib Idris" -GivenName "Talib" -Surname "Idris" -SamAccountName "tidris" -UserPrincipalName "tidris@rebeladmin.com" -Path "OU=Users,OU=Europe,DC=rebeladmin,DC=com" -AccountPassword(Read-Host -AsSecureString "Type Password for User") -Enabled $true

# Create Bulk Users

Import-Csv "C:\ADUsers.csv" | ForEach-Object {
    $upn = $_.SamAccountName + "@rebeladmin.com" 
    New-ADUser -Name $_.Name `
     -GivenName $_."GivenName" `
     -Surname $_."Surname" `
     -SamAccountName $_."samAccountName" `
     -UserPrincipalName $upn `
     -Path $_."Path" `
     -AccountPassword (ConvertTo-SecureString "Pa$$w0rd" -AsPlainText -force) -Enabled $true
    }

# Syntax for New-ADComputer

Get-Command New-ADComputer -Syntax

# Create Computer Object

New-ADComputer -Name "REBEL-PC-01" -SamAccountName "REBEL-PC-01" -Path "OU=Computers,OU=Europe,DC=rebeladmin,DC=com"

# Add Attibute Values

Set-ADUser tidris -OfficePhone "0912291120" -City "London"

# Update Exisiting Attibute Values

Set-ADUser tidris -OfficePhone "0112291120"

# Search AD Users

Get-ADUser -Filter * -SearchBase 'OU=Users,OU=Europe,DC=rebeladmin,DC=com' | Set-ADUser -City "London"

# Search and Update

Get-ADUser -Filter {City -like "London"} | Set-ADUser -City "Kingston"

# Update Computer Object

Set-ADComputer REBEL-PC-01 -Description "Sales Computer"

# Search and Update

Get-ADComputer -Filter {Name -like "REBEL-PC-*"} | Set-ADComputer -Location "M35 Building"

# Syntax for Remove-ADUser

Get-Command Remove-ADUser -Syntax

# Remove AD User

Remove-ADUser -Identity "dzhang"

# Search and Remove

Get-ADUser -Filter {Name -like "Test1*"} | Remove-ADUser

# Remove Computer Object

Remove-ADComputer -Identity "REBEL-PC-01"

# Search and Remove

Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=Europe,DC=rebeladmin,DC=com' | Remove-ADComputer

# View User Attributes

Get-ADUser -Identity user1 -Properties *

# Filter User based on attibutes

Get-ADUser -Filter * -Properties Name,UserPrincipalName,Modified | ft Name,UserPrincipalName,Modified
Get-ADUser -Filter {City -like "Kingston"} -Properties Name,UserPrincipalName,Modified | ft Name,UserPrincipalName,Modified 

# Export search results

Get-ADUser -Filter {City -like "Kingston"} -Properties Name,UserPrincipalName,Modified | select-object Name,UserPrincipalName,Modified | Export-csv -path C:\ADUSerList.csv

# Syntax for Search-ADAccount 

Get-Command Search-ADAccount -Syntax

# Search for lockedout accounts

Search-ADAccount -LockedOut | FT Name,UserPrincipalName

# Prevent accedental deletion

Set-ADObject -Identity ‘CN=Dishan Francis,DC=rebeladmin,DC=com’ -ProtectedFromAccidentalDeletion $true

# Enable RecycleBin

Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target rebeladmin.com

# Deleted Objects

Get-ADObject -filter 'isdeleted -eq $true' -includeDeletedObjects

# Restore Deleted Object

Get-ADObject -Filter 'samaccountname -eq "dfrancis"' -IncludeDeletedObjects | Restore-ADObject






