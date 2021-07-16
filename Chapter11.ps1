# Create User in LDS

New-ADUser -name "tidris" -Displayname "Talib Idris" -server 'localhost:389' -path "CN=webapp01,DC=rebeladmin,DC=com"

# List users in LDS

Get-ADUser -Filter * -SearchBase "CN=webapp01,DC=rebeladmin,DC=com" -server 'localhost:389'

# Review existing replication site configuration

Get-ADReplicationSite -Filter *

# Change Site Name

Rename-ADObject -Identity "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=rebeladmin,DC=com" -NewName "LondonSite"

# Change site description

Get-ADReplicationSite -Identity LondonSite | Set-ADReplicationSite -Description "UK AD Site"

# Create New Site

New-ADReplicationSite -Name "CanadaSite" -Description "Canada AD Site"

# List Domaincontrollers

Get-ADDomainController -Filter * | select Name,ComputerObjectDN,Site | fl

# Move Dc to a Site

Move-ADDirectoryServer -Identity "REBEL-SDC-02" -Site "CanadaSite"

# Create New sitelink

New-ADReplicationSiteLink -Name "London-Canada" -SitesIncluded LondonSite,CanadaSite -Cost 205 -ReplicationFrequencyInMinutes 30 -InterSiteTransportProtocol IP

# New site link bridge

New-ADReplicationSiteLinkBridge -Name "London-Canada-Bridge" -SiteLinksIncluded "London-Canada","London-CanadaDRLink"

# Remove site link from site link bridge

Set-ADReplicationSiteLinkBridge -Identity "London-Canada-Bridge" -SiteLinksIncluded @{Remove='London-CanadaDRLink'}

# Add site link to site link bridge

Set-ADReplicationSiteLinkBridge -Identity "London-Canada-Bridge" -SiteLinksIncluded @{Add='London-CanadaDRLink'}

# Create subnet 

New-ADReplicationSubnet -Name "192.168.0.0/24" -Site LondonSite

# Change values of existing subnet

Set-ADReplicationSubnet -Identity "192.168.0.0/24" -Site CanadaSite

# View subnet data

Get-ADReplicationSubnet -Filter {Site -Eq "CanadaSite"}