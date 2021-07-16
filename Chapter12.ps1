# Create Conditional Forwarder

Add-DnsServerConditionalForwarderZone -Name "contoso.com" -ReplicationScope "Forest" -MasterServers 10.1.5.4
Add-DnsServerConditionalForwarderZone -Name "rebeladmin.com" -ReplicationScope "Forest" -MasterServers 10.1.0.4

# Search AD User

Get-ADUser -Server CON-DC01.contoso.com -Filter * -SearchBase "OU=Test,DC=CONTOSO,DC=COM"
Get-ADUser -Server DC01.rebeladmin.com -Filter * -SearchBase "OU=Sales,DC=rebeladmin,DC=com"

# Create RODC Computer Account

Add-ADDSReadOnlyDomainControllerAccount -DomainControllerAccountName REBEL-RODC-01 -DomainName rebeladmin.com -DelegatedAdministratorAccountName "rebeladmindfrancis" -SiteName LondonSite

# Install AD DS Role

Install-WindowsFeature –Name AD-Domain-Services -IncludeManagementTools

# Create RODC

Import-Module ADDSDeployment 
Install-ADDSDomainController ` 
-Credential (Get-Credential) ` 
-CriticalReplicationOnly:$false ` 
-DatabasePath "C:WindowsNTDS" ` 
-DomainName "rebeladmin.com" ` 
-LogPath "C:WindowsNTDS" `
-ReplicationSourceDC "REBEL-PDC-01.rebeladmin.com" `
-SYSVOLPath "C:WindowsSYSVOL" ` 
-UseExistingAccount:$true ` 
-Norebootoncompletion:$false 
-Force:$true

# Review Password Replication Policy Allowed list

Get-ADDomainControllerPasswordReplicationPolicy -Identity REBEL-RODC-01 -Allowed

# Review Password Replication Policy Denied list

Get-ADDomainControllerPasswordReplicationPolicy -Identity REBEL-RODC-01 -Denied

# Add user to allowed list

Add-ADDomainControllerPasswordReplicationPolicy -Identity REBEL-RODC-01 -AllowedList "user1"

# Add user to deny list

Add-ADDomainControllerPasswordReplicationPolicy -Identity REBEL-RODC-01 -DeniedList "user2"

# Enable AD recycle bin

Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target rebeladmin.com

# List deleted objects

Get-ADObject -filter 'isdeleted -eq $true' -includeDeletedObjects

# Restore Object

Get-ADObject -Filter 'samaccountname -eq "dfrancis"' -IncludeDeletedObjects | Restore-ADObject

# Install Backup Feature

Install-WindowsFeature -Name Windows-Server-Backup –IncludeAllSubFeature

# Recover from Systemstate backup

$ADBackup = Get-WBBackupSet | select -Last 1
Start-WBSystemStateRecovery -BackupSet $ADBackup
