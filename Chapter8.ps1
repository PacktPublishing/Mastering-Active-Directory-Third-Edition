# Filter Custom Attribute Value

Get-ADuser "tuser4" -Properties nINumber | ft nINumber

# New User Template

New-ADUser -Name "_TechSupport_Template" -GivenName "_TechSupport" -Surname "_Template" -SamAccountName "techtemplate" -UserPrincipalName "techtemplate@rebeladmin.com" -Path "OU=Users,OU=Europe Office,DC=rebeladmin,DC=com" -AccountPassword(Read-Host -AsSecureString "Type Password for User") -Enabled $false

# Add Template to Group

Add-ADGroupMember "Technical Department" "techtemplate"

# Create Managed Service Account

New-ADServiceAccount -Name "MyAcc1" -RestrictToSingleComputer

# Associate MSA with Host

Add-ADComputerServiceAccount -Identity REBEL-SRV01 -ServiceAccount "MyAcc1"

# Install MSA

Install-ADServiceAccount -Identity "MyAcc1"

# Test MSA

Test-ADServiceAccount "MyAcc1"

# View MSA Account Properties

Get-ADServiceAccount "MyAcc1"

# KDS Root Key

Add-KdsRootKey –EffectiveImmediately

# Remove 10 Hours Replication Time

Add-KdsRootKey –EffectiveTime ((get-date).addhours(-10))

# Create gMSA

New-ADServiceAccount "Mygmsa1" -DNSHostName "web.rebeladmin.com" –PrincipalsAllowedToRetrieveManagedPassword "IISFARM"

# View gMSA Properties 

Get-ADServiceAccount "Mygmsa1"

# Install gMSA

Install-ADServiceAccount -Identity "Mygmsa1"

# Test gMSA

Test-ADServiceAccount " Mygmsa1"

# Uninstall MSA

Remove-ADServiceAccount –identity "Mygmsa1"

# View Syntax for New-ADGroup Command

Get-Command New-ADGroup -Syntax

# Create New AD Group

New-ADGroup -Name "Sales Team" -GroupCategory Security -GroupScope Global -Path "OU=Users,OU=Europe,DC=rebeladmin,DC=com"

# Protect Group From Accedental Deletion 

Get-ADGroup "Sales Team" | Set-ADObject -ProtectedFromAccidentalDeletion:$true

# Add members to group

Add-ADGroupMember "Sales Team" tuser3,tuser4,tuser5

# Remove member from group

Remove-ADGroupMember "Sales Team" tuser4

# View group properties

Get-ADGroup "Sales Team"

# Filter data in group

Get-ADGroup "Sales Team" -Properties DistinguishedName,Members | fl DistinguishedName,Members

# Change group scope

Set-ADGroup "Sales Team" -GroupScope Universal

# Remove AD group

Remove-ADGroup "Sales Team"

# Create iNetOrgPerson object

New-ADUser -Name "Inet User1" -GivenName "Inet"
 -Surname "User1" -SamAccountName "inetuser1"
 -UserPrincipalName "isuer1@rebeladmin.com"
 -AccountPassword (Read-Host -AsSecureString
 "Type Password for User")
 -Enabled $true -Path "OU=Users,OU=Europe,DC=rebeladmin,DC=com"
 –Type iNetOrgPerson

 # Convert iNetOrgPerson object to user object

 Set-ADUser "inetuser1" -Remove @{objectClass='inetOrgPerson'}



