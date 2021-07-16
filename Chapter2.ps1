# Find AD Forest Mode

Get-ADForest | fl Name,ForestMode

# Enable Privileged Access Maangment Feature

Enable-ADOptionalFeature 'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target rebeladmin.com

# Find Memebrs of Domain Admin Group

Get-ADGroupMember "Domain Admins"

# Time Based Group Membership

Add-ADGroupMember -Identity 'Domain Admins' -Members 'acurtiss' -MemberTimeToLive (New-TimeSpan -Minutes 60)

# Show TTL value

Get-ADGroup 'Domain Admins' -Property member -ShowMemberTimeToLive

