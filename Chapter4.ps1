# List DNS Forwarders

Get-DnsServerForwarder

# List Root Servers

Get-DnsServerRootHint

# View SOA Record

Get-DnsServerResourceRecord -ZoneName "REBELADMIN.COM" -RRType "SOA" | Select-Object -ExpandProperty RecordData

# Create A Record

Add-DnsServerResourceRecordA -Name "blog" -ZoneName "REBELADMIN.COM" -IPv4Address "192.168.0.200"

# Remove A Record

Remove-DnsServerResourceRecord -ZoneName "REBELADMIN.COM" -RRType "A" -Name "blog"

# List A Records

Get-DnsServerResourceRecord -ZoneName "REBELADMIN.COM" -RRType "A"

# Find NS Records

Get-DnsServerResourceRecord -ZoneName "REBELADMIN.COM" -RRType "NS"

# List SRV Records

Get-DnsServerResourceRecord -ZoneName "REBELADMIN.COM" -RRType "SRV"

# Detailed output of SOA record

Get-DnsServerResourceRecord -ZoneName "REBELADMIN.COM" -RRType "SRV" | Select-Object -ExpandProperty RecordData

# Add Primary Zone

Add-DnsServerPrimaryZone -Name "rebeladmin.net" -ReplicationScope "Forest" -PassThru

# Allow Zone Transfer

Set-DnsServerPrimaryZone -Name "rebeladmin.net" -SecureSecondaries TransferToSecureServers -SecondaryServers 192.168.0.106

# Add Secondry Zone

Add-DnsServerSecondaryZone -Name "rebeladmin.net" -ZoneFile "rebeladmin.net.dns" -MasterServers 192.168.0.105

# Add Reverse Lookup Zone

Add-DnsServerPrimaryZone -NetworkID "10.10.10.0/24" -ReplicationScope "Domain"

# Create Condtional Forwarder

Add-DnsServerConditionalForwarderZone -Name "rebeladmin.net" -ReplicationScope "Forest" -MasterServers 10.0.0.5

# Add DNS server client subnet

Add-DnsServerClientSubnet -Name "blockA" -IPv4Subnet 10.0.0.6/32

# Add DNS Policy 

Add-DnsServerQueryResolutionPolicy -Name "blockApolicy" -Action IGNORE -ClientSubnet  "EQ,blockA"

# Add Primary Zone

Add-DnsServerPrimaryZone -Name "dev.rebeladmin.com" -ZoneFile "dev.rebeladmin.com.dns"

# Create A Record

Add-DnsServerResourceRecordA -Name "app1" -ZoneName "dev.rebeladmin.com" -AllowUpdateAny -IPv4Address "192.168.0.110"

# DNS Zone Deligation

Add-DnsServerZoneDelegation -Name "rebeladmin.com" -ChildZoneName "dev" -NameServer "REBEL-SDC-01.rebeladmin.com" -IPAddress 192.168.0.110


