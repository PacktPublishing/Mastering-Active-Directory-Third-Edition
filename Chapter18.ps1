## Enable TLs 1.2 ##

New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null

	New-ItemProperty -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null

	New-ItemProperty -path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

	New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null

	New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null

	New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
	
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
	
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
	
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
	
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Host 'TLS 1.2 has been enabled.'

## Sync NTLM Hash ##

$adConnector = "<CASE SENSITIVE AD CONNECTOR NAME>"
$azureadConnector = "<CASE SENSITIVE AZURE AD CONNECTOR NAME>"
Import-Module adsync
$c = Get-ADSyncConnector -Name $adConnector
$p = New-Object Microsoft.IdentityManagement.PowerShell.ObjectModel.ConfigurationParamter "Microsoft.Synchronize.ForceFullPasswordSync", String, ConnectorGlobal, $null, $null, $null
$p.Value = 1
$c.GlobalParameters.Remove($p.Name)
$c.GlobalParameters.Add($p)
$c = Add-ADSyncConnector -Connector $c
Set-ADSyncAADPasswordSyncConfiguration -SourceConnector $adConnector -TargetConnector $azureadConnector -Enable $false
Set-ADSyncAADPasswordSyncConfiguration -SourceConnector $adConnector -TargetConnector $azureadConnector -Enable $true

## Create self-sign Certificate for secure LDAP ##

$domainname="rebeladmlive.onmicrosoft.com"
$certlife=Get-Date
New-SelfSignedCertificate -Subject *.$domainname -NotAfter $certlife.AddDays(365) -KeyUsage DigitalSignature, KeyEncipherment -Type SSLServerAuthentication -DnsName *.$domainname, $domainname

## Enable NTLM hash sync for Azure AD DS ##

Login-AzAccount
$DomainServicesResource = Get-AzResource -ResourceType "Microsoft.AAD/DomainServices"
$securitySettings = @{"DomainSecuritySettings"=@{"NtlmV1"="Disabled";"SyncNtlmPasswords"="Enabled";"TlsV1"="Disabled"}}
Set-AzResource -Id $DomainServicesResource.ResourceId -Properties $securitySettings -Verbose -Force


## Setup new resourse group ## 

New-AzResourceGroup -Name REBELDRRG1 -Location "West US"

## Setup new virtual network ## 

$drvmsubnet = New-AzVirtualNetworkSubnetConfig -Name drvmsubnet -AddressPrefix "10.1.3.0/24"
New-AzVirtualNetwork -Name REBELDRVN1 -ResourceGroupName REBELDRRG1 -Location "West US" -AddressPrefix "10.1.0.0/16" -Subnet $drvmsubnet

## Create Global VNET peering from REBELVN1 to REBELDRVN1 ##

$vnet1 = Get-AzVirtualNetwork -Name REBELVN1 -ResourceGroupName REBELRG1
$vnet2 = Get-AzVirtualNetwork -Name REBELDRVN1 -ResourceGroupName REBELDRRG1
Add-AzVirtualNetworkPeering -Name REBELVN1toEBELDRVN1 -VirtualNetwork $vnet1 -RemoteVirtualNetworkId $vnet2.Id

## Create Global VNET peering from REBELDRVN1 to REBELVN1 ##

$vnet1 = Get-AzVirtualNetwork -Name REBELVN1 -ResourceGroupName REBELRG1
$vnet2 = Get-AzVirtualNetwork -Name REBELDRVN1 -ResourceGroupName REBELDRRG1
Add-AzVirtualNetworkPeering -Name REBELDRVN1toREBELVN1 -VirtualNetwork $vnet2 -RemoteVirtualNetworkId $vnet1.Id