# Install AD DS Feature

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Configre First Domain Controller

Install-ADDSForest -DomainName "rebeladmin.com" -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "7" -DomainNetbiosName "REBELADMIN" -ForestMode "7" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$True -SysvolPath "C:\Windows\SYSVOL" -Force:$true

# Check Service Status

Get-Service adws,kdc,netlogon,dns

# Domain Controller Details

Get-ADDomainController 

# Domain Properties

Get-ADDomain rebeladmin.com

# Sysvol Share details

Get-smbshare SYSVOL

# Setup Additional Domain Controller

Install-ADDSDomainController -CreateDnsDelegation:$false -NoGlobalCatalog:$true -InstallDns:$true -DomainName "rebeladmin.com" -SiteName "Default-First-Site-Name" -ReplicationSourceDC "REBEL-SDC01.rebeladmin.com" -DatabasePath "C:\Windows\NTDS" -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$true -SysvolPath "C:\Windows\SYSVOL" -Force:$true

# Domain Controller Details

Get-ADDomainController -Filter * |  Format-Table Name, IPv4Address, Site

# Confirm Global Catalog Status

Get-ADDomainController -Discover -Service "GlobalCatalog"

# Move FSMO Role

Move-ADDirectoryServerOperationMasterRole -Identity REBEL-SDC-02 -OperationMasterRole InfrastructureMaster

# List Installed Windows Features

Get-WindowsFeature -ComputerName DC01 | Where Installed

# Verify FSMO Role Holder

Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster  

# Move FSMO Roles

Move-ADDirectoryServerOperationMasterRole -Identity DC22 -OperationMasterRole SchemaMaster,DomainNamingMaster,PDCEmulator,RIDMaster,InfrastructureMaster

# Uninstall AD DS

Uninstall-ADDSDomainController -DemoteOperationMasterRole -RemoveApplicationPartition 

# Upgrade Domain Functional Level

Set-ADDomainMode -identity rebeladmin.net -DomainMode Windows2016Domain

# Upgrade Forest Functional Level

Set-ADForestMode -Identity rebeladmin.net -ForestMode Windows2016Forest

# Verify Domain Mode

Get-ADDomain | fl Name,DomainMode

# Verify Forest Mode

Get-ADForest | fl Name,ForestMode

# View Events

Get-EventLog -LogName 'Directory Service' | where {$_.eventID -eq 2039 -or $_.eventID -eq 2040} | Format-List
Get-EventLog -LogName 'Directory Service' | where {$_.eventID -eq 1458} | Format-List

# Domain Controller Details

Get-ADDomainController -Filter * | Format-Table Name, IPv4Address



