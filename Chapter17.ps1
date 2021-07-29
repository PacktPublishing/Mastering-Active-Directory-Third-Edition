## Install AD Role ##

Install-WindowsFeature –Name AD-Domain-Services -IncludeManagementTools

## Install RSAT Tools ##

Add-WindowsFeature RSAT-AD-PowerShell

## List all commands under module ##

Get-Command -Module ActiveDirectory

## List command syntax ###

Get-Command New-ADUser -Syntax

## Help for command ##

Get-Help New-ADUser

## More information about the command ##

Get-Help New-ADUser -Detailed

## Technical information about the command ##

Get-Help New-ADUser -Full

## Online help ##

Get-Help New-ADUser -Online

## Directory information ##

Get-ADRootDSE

## List FSMO roles ##

Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,IsGlobalCatalog,OperationMasterRoles

## List domain controllers with name,IP and site info ##

Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,Site

## List forest,domain,domain controller ip and site details ##

$Forestwide = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ } write-output $Forestwide -Filter * | Select-Object Name,Forest,Domain,IPv4Address,Site

## List rodc ##

$Domain = Read-Host 'What is your Domain Name ?'
Get-ADDomain -Identity $Domain | select ReplicaDirectoryServers,ReadOnlyReplicaDirectoryServer

## List inbound replication partners for domain controller ##

Get-ADReplicationPartnerMetadata -Target REBEL-SRV01.rebeladmin.com

## List inbound replication partners for domain ##

Get-ADReplicationPartnerMetadata -Target "rebeladmin.com" -Scope Domain

## List replication faliures for a domain controller ##

Get-ADReplicationFailure -Target REBEL-SRV01.rebeladmin.com

## List replication faliures for a domain ##

Get-ADReplicationFailure -Target rebeladmin.com -Scope Domain

## List replication faliures for forest ##

Get-ADReplicationFailure -Target rebeladmin.com -Scope Forest

## List replication faliures for a site ##

Get-ADReplicationFailure -Target LondonSite -Scope Site

## Active Directory Domain Controller Replication Status##

 $domaincontroller = Read-Host 'What is your Domain Controller?'
 ## Define Objects ##
 $report = New-Object PSObject -Property @{
 ReplicationPartners = $null
 LastReplication = $null
 FailureCount = $null
 FailureType = $null
 FirstFailure = $null
 }

## Replication Partners  Report ##

 $report.ReplicationPartners = (Get-ADReplicationPartnerMetadata -Target $domaincontroller).Partner
 $report.LastReplication = (Get-ADReplicationPartnerMetadata -Target $domaincontroller).LastReplicationSuccess

## Replication Faliures ##

 $report.FailureCount = (Get-ADReplicationFailure -Target $domaincontroller).FailureCount
 $report.FailureType = (Get-ADReplicationFailure -Target $domaincontroller).FailureType
 $report.FirstFailure = (Get-ADReplicationFailure -Target $domaincontroller).FirstFailureTime

## Format Output ##

 $report | select ReplicationPartners,LastReplication,FirstFailure,FailureCount,FailureType | Out-GridView

## AD replication site objects ##

Get-ADReplicationSite -Filter *

## List replication site links ##

Get-ADReplicationSiteLink -Filter {SitesIncluded -eq "CanadaSite"} | Format-Table Name,Cost,ReplicationFrequencyInMinutes -AutoSize

## Site-link bridge information ##

Get-ADReplicationSiteLinkBridge -Filter *

## Replication subnet details ##

Get-ADReplicationSubnet -Filter * | Format-Table Name,Site -AutoSize

## List bridge head servers ##

$BHservers = ([adsi]"LDAP://CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=rebeladmin,DC=com").bridgeheadServerListBL
$BHservers | Out-GridView

## Script to gather information about Replication Topology ##

 ## Define Objects ##
 $replreport = New-Object PSObject -Property @{
 Domain = $null
 }

## Find Domain Information ##

 $replreport.Domain = (Get-ADDomain).DNSroot

## List down the AD sites in the Domain ##

 $a = (Get-ADReplicationSite -Filter *)
 Write-Host "########" $replreport.Domain "Domain AD Sites" "########"
 $a | Format-Table Description,Name -AutoSize

 ## ------------------------------------------------------------------------------ ##

## List down Replication Site link Information ##

 $b = (Get-ADReplicationSiteLink -Filter *)
 Write-Host "########" $replreport.Domain "Domain AD Replication SiteLink Information" "########"
 $b | Format-Table Name,Cost,ReplicationFrequencyInMinutes -AutoSize
 ## List down SiteLink Bridge Information ##
 $c = (Get-ADReplicationSiteLinkBridge -Filter *)
 Write-Host "########" $replreport.Domain "Domain AD SiteLink Bridge Information" "########"
 $c | select Name,SiteLinksIncluded | Format-List

  ## ------------------------------------------------------------------------------ ##

## List down Subnet Information ##
 $d = (Get-ADReplicationSubnet -Filter * | select Name,Site)
 Write-Host "########" $replreport.Domain "Domain Subnet Information" "########"
 $d | Format-Table Name,Site -AutoSize
 ## List down Prefered BridgeHead Servers ##
 $e = ([adsi]"LDAP://CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=rebeladmin,DC=com").bridgeheadServerListBL
 Write-Host "########" $replreport.Domain "Domain Prefered BridgeHead Servers" "########"
 $e
 ## End of the Script ##

  ## ------------------------------------------------------------------------------ ##

  ## Replicate Object to From Domain Controller to Another ##

$myobject = Read-Host 'What is your AD Object Includes ?'
$sourcedc = Read-Host 'What is the Source DC ?'
$destinationdc = Read-Host 'What is the Destination DC ?'
$passobject = (Get-ADObject -Filter {Name -Like $myobject})
Sync-ADObject -object $passobject -source $sourcedc -destination $destinationdc
Write-Host "Given Object Replicated to" $destinationdc

  ## ------------------------------------------------------------------------------ ##

  ## Last login time ##

  $username = Read-Host 'What is the User account you looking for ?'
   $dcs = Get-ADDomainController -Filter {Name -like "*"}
      foreach($dc in $dcs)
   { 
     $hostname = $dc.HostName
     $user = Get-ADUser $userName -Server $hostname -Properties lastLogon
     $lngexpires = $user.lastLogon
     if (-not ($lngexpires)) {$lngexpires = 0 }
     If (($lngexpires -eq 0) -or ($lngexpires -gt [DateTime]::MaxValue.Ticks))
     {
       $LastLogon = "User Never Logged In"
     }
      Else
     {
       $Date = [DateTime]$lngexpires
       $LastLogon = $Date.AddYears(1600).ToLocalTime()
     }
  }
  Write-Host $username "last logged on at:" $LastLogon

    ## ------------------------------------------------------------------------------ ##

    ## Script For Filter user with Last logon Time ##

$htmlformat = "<style>BODY{background-color:LightBlue;}</style>"
Get-ADUser -Filter * -Properties "LastLogonDate" | sort-object -property lastlogondate -descending | Select-Object Name,LastLogonDate | ConvertTo-HTML -head $htmlformat -body "<H2>AD Accounts Last Login Date</H2>"| Out-File C:\lastlogon.html
Invoke-Expression C:\lastlogon.html

    ## ------------------------------------------------------------------------------ ##

    ## Report for DC login Failures ##

$failedevent = $null
$Date= Get-date 
$dc = Read-Host 'What is the Domain Controller ?'
$Report= "C:\auditreport.html"
$HTML=@"
<title>Failed Login Report for $dc</title>
<style>
BODY{background-color :LightBlue}
</style>
"@
 $failedevent = Get-Eventlog security -Computer $dc -InstanceId 4625 -After (Get-Date).AddDays(-7) |
 Select TimeGenerated,ReplacementStrings |
 % {
 New-Object PSObject -Property @{
 SourceComputer = $_.ReplacementStrings[13]
 UserName = $_.ReplacementStrings[5]
 SourceIPAddress = $_.ReplacementStrings[19]
 Date = $_.TimeGenerated
 }
 }
 $failedevent | ConvertTo-Html -Property SourceComputer,UserName,SourceIPAddress,Date -head $HTML -body "<H2>Failed Login Report for $dc</H2>"|
 Out-File $Report
 Invoke-Expression C:\auditreport.html

     ## ------------------------------------------------------------------------------ ##

## Locked Accounts ##

Search-ADAccount -Lockedout | Select name,samAccountName,Lockedout

## Unlock user account ##

Unlock-ADAccount tuser4

## Search and unlock ##

Search-ADAccount -Lockedout | Unlock-ADAccount

     ## ------------------------------------------------------------------------------ ##

## Password Expire Report ##
$passwordreport = $null
$dc = (Get-ADDomain | Select DNSRoot).DNSRoot
$Report= "C:\passwordreport.html"
$HTML=@"
<title>Password Expire Report For $dc</title>
<style>
BODY{background-color :LightBlue}
</style>
"@
$passwordreport = Get-ADUser -filter * –Properties "SamAccountName","pwdLastSet","msDS-UserPasswordExpiryTimeComputed" | Select-Object -Property "SamAccountName",@{Name="Last Password Change";Expression={[datetime]::FromFileTime($_."pwdLastSet")}},@{Name="Next Password Change";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
$passwordreport | ConvertTo-Html -Property "SamAccountName","Last Password Change","Next Password Change"-head $HTML -body "<H2>Password Expire Report For $dc</H2>"|
Out-File $Report
Invoke-Expression C:\passwordreport.html

     ## ------------------------------------------------------------------------------ ##

## Sensative Group Report ##

$HTML=@"
<title>Sensative Groups Memebrship Report</title>
<style>
BODY{background-color :LightBlue}
</style>
"@
$enterpiseadmins = Get-ADGroupMember -Identity "Enterprise Admins" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Enterprise Admins</h2>"
$schemaadmins = Get-ADGroupMember -Identity "Schema Admins" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Schema Admins</h2>"
$domainadmins = Get-ADGroupMember -Identity "Domain Admins" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Domain Admins</h2>" 
$accountoperators = Get-ADGroupMember -Identity "Account Operators" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Account Operators</h2>" 
$serveroperators = Get-ADGroupMember -Identity "Server Operators" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Server Operators</h2>"
$printoperators = Get-ADGroupMember -Identity "Print Operators" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Print Operators</h2>"
$dnsadmins = Get-ADGroupMember -Identity "DnsAdmins" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>DNS Admins</h2>"
$Reportvalues = ConvertTo-HTML -Body "$enterpiseadmins $schemaadmins $domainadmins $accountoperators $serveroperators $printoperators $dnsadmins" -Head $HTML
$Reportvalues | Out-File "C:\sensativegroupreport.html"

     ## ------------------------------------------------------------------------------ ##

## Sensative Group Members Inactive for 30 days ##

$30Days = (get-date).adddays(-30)
$HTML=@"
<title>Sensative Groups Memebrship Report : USers Inactive for 30 days</title>
<style>
BODY{background-color :LightBlue}
</style>
"@
$enterpiseadmins = Get-ADGroupMember -Identity "Enterprise Admins" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate |Where {$_.LastLogonDate -le $30Days}| select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Enterprise Admins</h2>"
$schemaadmins = Get-ADGroupMember -Identity "Schema Admins" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | Where {$_.LastLogonDate -le $30Days}| select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Schema Admins</h2>"
$domainadmins = Get-ADGroupMember -Identity "Domain Admins" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | Where {$_.LastLogonDate -le $30Days}| select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Domain Admins</h2>" 
$accountoperators = Get-ADGroupMember -Identity "Account Operators" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | Where {$_.LastLogonDate -le $30Days}| select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Account Operators</h2>" 
$serveroperators = Get-ADGroupMember -Identity "Server Operators" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | Where {$_.LastLogonDate -le $30Days}| select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Server Operators</h2>"
$printoperators = Get-ADGroupMember -Identity "Print Operators" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | Where {$_.LastLogonDate -le $30Days}| select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>Print Operators</h2>"
$dnsadmins = Get-ADGroupMember -Identity "DnsAdmins" | where {$_.objectclass -eq 'user'} | Get-ADUser -Properties LastLogonDate | Where {$_.LastLogonDate -le $30Days}| select Name,LastLogonDate | ConvertTo-Html -Property "Name","LastLogonDate" -Fragment -PreContent "<h2>DNS Admins</h2>"
$Reportvalues = ConvertTo-HTML -Body "$enterpiseadmins $schemaadmins $domainadmins $accountoperators $serveroperators $printoperators $dnsadmins" -Head $HTML
$Reportvalues | Out-File "C:\inactiveusers.html"

     ## ------------------------------------------------------------------------------ ##

## Dormant Accounts ##

$InactiveDate = (Get-Date).Adddays(-30)
$HTML=@"
<title>Dormant Accounts Report</title>
<style>
BODY{background-color :LightBlue}
</style>
"@
$disabledaccounts = Get-ADUser -Filter {Enabled -eq $false} | select samAccountName,GivenName,Surname | ConvertTo-Html -Property "samAccountName","GivenName","Surname" -Fragment -PreContent "<h2>Disabled Account</h2>"
$inactiveaccounts = Get-ADUser -Filter {LastLogonDate -lt $InactiveDate -and Enabled -eq $true} -Properties LastLogonDate | select samAccountName,GivenName,Surname,LastLogonDate | ConvertTo-Html -Property "samAccountName","GivenName","Surname","LastLogonDate" -Fragment -PreContent "<h2>Inactive Accounts</h2>"
$Reportvalues = ConvertTo-HTML -Body "$disabledaccounts $inactiveaccounts" -Head $HTML
$Reportvalues | Out-File "C:\dormantusers.html"

## Users with Password Never Expires Setting ##

Get-ADUser -Filter  {passwordNeverExpires -eq $true -and Enabled -eq $true } -Properties * | Select samAccountName,GivenName,Surname

## List down available commmand for module ###

Get-Command -module AzureAD

## view syntax help for the command ##

Get-Help Get-AzureADUser

## Get Azure domain info ##

Get-AzureADDomain | fl

## List DNS records for domain verification ##

Get-AzureADDomainVerificationDnsRecord -Name M365x562652.onmicrosoft.com | fl

## List tenant details ##

Get-AzureADTenantDetail | fl

## Last sync time ##

Get-AzureADTenantDetail | select CompanyLastDirSyncTime

## User details ##

Get-AzureADUser -ObjectId AdeleV@M365x562652.OnMicrosoft.com | fl

## Search for the users ##

Get-AzureADUser -Filter "startswith(GivenName,'Adele')"

## Search user ##

Get-AzureADUser -Filter "GivenName eq 'Adele'"

## List of disbaled accounts ##

Get-AzureADUser -All $true -Filter 'accountEnabled eq false'

## Filter data further for disabled accounts ##

Get-AzureADUser -All $true -Filter 'accountEnabled eq false' | select DisplayName,UserPrincipalName,Department

## Synced users ##

Get-AzureADUser -All $true -Filter 'DirSyncEnabled eq true'

## Last sync value ##

Get-AzureADUser  -All $true -Filter 'DirSyncEnabled eq true' | select DisplayName,UserPrincipalName,LastDirSyncTime

## Export filtered data to CSV ##

Get-AzureADUser  -All $true -Filter 'DirSyncEnabled eq true' | select DisplayName,UserPrincipalName,LastDirSyncTime | Export-CSV -Path .\syncaccount.csv

## immutableid value null ##

Get-AzureADUser -All $true | where-Object {$_.ImmutableId -eq $null}

## Export filtered data to CSV ##

Get-AzureADUser -All $true | where-Object {$_.ImmutableId -eq $null} | select DisplayName,UserPrincipalName | Export-CSV -Path .\cloudaccount.csv

## Licence associated with account ##

Get-AzureADUserLicenseDetail -ObjectId MeganB@M365x562652.OnMicrosoft.com | fl

## Subscribed sku ##

Get-AzureADSubscribedSku | fl

## SKU details ##

Get-AzureADSubscribedSku | select SkuPartNumber,ConsumedUnits -ExpandProperty PrepaidUnits

## Licence status of a synced user ##

Get-AzureADUserLicenseDetail -ObjectId ADJellison@M365x562652.onmicrosoft.com | fl

## Remove licences from a user ##

$licenseB = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
$licenseB.RemoveLicenses =  (Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq 'ENTERPRISEPREMIUM'}).SkuId
Set-AzureADUserLicense -ObjectId "ADJellison@M365x562652.onmicrosoft.com" -AssignedLicenses $licenseB

     ## ------------------------------------------------------------------------------ ##

#######Script to Assign Licences to Synced Users from On-Permises AD#############
Import-Module AzureAD
Connect-AzureAD
###Filter Synced Users who doesn't have licence assigned#######
$ADusers = Get-AzureADUser -All $true -Filter 'DirSyncEnabled eq true'
$notlicenced = Get-AzureADUser -All $true | Where-Object {$ADusers.AssignedLicenses -ne $null} | select ObjectId | Out-File -FilePath C:\users.txt
#####Set UsageLocation value to sync users#########
(Get-Content "C:\users.txt" | select-object -skip 3) | ForEach { Set-AzureADUser -ObjectId $_ -UsageLocation "US" }
#####Set User Licecnes############
$newlicence = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
$newlicenceadd = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
$newlicence.SkuId = (Get-
AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value "ENTERPRISEPREMIUM" -EQ).SkuId
$newlicenceadd.AddLicenses = $newlicence
(Get-Content "C:\users.txt" | select-object -skip 3) | ForEach { Set-AzureADUserLicense -ObjectId $_ -AssignedLicenses $newlicenceadd }

## Create new user ##

$Userpassword = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$Userpassword.Password = "London@1234"
New-AzureADUser -DisplayName "Andrew Xavier" -PasswordProfile $Userpassword -UserPrincipalName "Andrew.Xavier@M365x562652.onmicrosoft.com" -AccountEnabled $true -MailNickName "AndrewXavier"

## Create users from CSV ##

$Userpassword = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$Userpassword.Password = "London@1234"
Import-Csv -Path C:\newuser.csv | foreach {New-AzureADUser -UserPrincipalName $_.UserPrincipalName -DisplayName $_.DisplayName -MailNickName $_.MailNickName -PasswordProfile $Userpassword -AccountEnabled $true}

     ## ------------------------------------------------------------------------------ ##

########A Script to create new users and assign Azure AD licences#######
Import-Module AzureAD
Connect-AzureAD
###########Create New Users using CSV ###################
$Userpassword = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$Userpassword.Password = "London@1234"
Import-Csv -Path C:\newuser.csv | foreach {New-AzureADUser -UserPrincipalName $_.UserPrincipalName -DisplayName $_.DisplayName -MailNickName $_.MailNickName -PasswordProfile $Userpassword -UsageLocation "US" -AccountEnabled $true} | select ObjectId | Out-File -FilePath C:\users.txt
###########Assign Licences#################
$newlicence = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
$newlicenceadd = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
$newlicence.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value "ENTERPRISEPREMIUM" -EQ).SkuId
$newlicenceadd.AddLicenses = $newlicence
(Get-Content "C:\users.txt" | select-object -skip 3) | ForEach { Set-AzureADUserLicense -ObjectId $_ -AssignedLicenses $newlicenceadd }

## Remove Azure AD User ##

Remove-AzureADUser -ObjectId "JDAllen@M365x562652.onmicrosoft.com"

## Search user and delete ##

Get-AzureADUser -Filter "startswith(DisplayName,'Dishan')" | Remove-AzureADUser

## Search for group ##

Get-AzureADGroup -SearchString "sg"

## Filter group based on object id ##

Get-AzureADGroup -ObjectId 93291438-be19-472e-a1d6-9b178b7ac619 | fl

## Synced user groups ##

Get-AzureADGroup -Filter 'DirSyncEnabled eq true' | select ObjectId,DisplayName,LastDirSyncTime

## Cloud only groups ##

Get-AzureADGroup -All $true | where-Object {$_.OnPremisesSecurityIdentifier -eq $null}

## View group members ##

Get-AzureADGroupMember -ObjectId 2a11d5ee-8383-44d1-9fbd-85cb4dcc2d5a

## Add member to group ##

Add-AzureADGroupMember -ObjectId 2a11d5ee-8383-44d1-9fbd-85cb4dcc2d5a -RefObjectId a6aeced9-909e-4684-8712-d0f242451338

## Remove member from a group ##

Remove-AzureADGroupMember -ObjectId 2a11d5ee-8383-44d1-9fbd-85cb4dcc2d5a -MemberId a6aeced9-909e-4684-8712-d0f242451338

     ## ------------------------------------------------------------------------------ ##

#######Script to Add Multiple users to Security Group#############

Import-Module AzureAD
Connect-AzureAD
##### Search for users in Marketing Department ##########
Get-AzureADUser -All $true -Filter "Department eq 'Marketing'" | select ObjectId | Out-File -FilePath C:\salesusers.txt
#####Add Users to Sales Group#########
(Get-Content "C:\salesusers.txt" | select-object -skip 3) | ForEach { Add-AzureADGroupMember -ObjectId f9f51d29-e093-4e57-ad79-2fc5ae3517db -RefObjectId $_ }

## Create Cloud only group ##

New-AzureADGroup -DisplayName "REBELADMIN Sales Team" -MailEnabled $false -MailNickName "salesteam" -SecurityEnabled $true

## Remove a group ##

Remove-AzureADGroup -ObjectId 7592b555-343d-4f73-a6f1-2270d7cf014f

## List administrative roles ##

Get-AzureADDirectoryRoleTemplate

## List directory roles ##

Get-AzureADDirectoryRole

## Enable administrative role ##

Enable-AzureADDirectoryRole -RoleTemplateId e6d1a23a-da11-4be4-9570-befc86d067a7

## Assign administrative role to a user ##

Add-AzureADDirectoryRoleMember -ObjectId b63c1671-625a-4a80-8bae-6487423909ca -RefObjectId 581c7265-c8cc-493b-9686-771b2f10a77e

## Remove role from a user ##

Remove-AzureADDirectoryRoleMember -ObjectId 36b9ac02-9dfc-402a-8d44-ba2d8995dc06 -MemberId 165ebcb7-f07d-42d2-a52e-90f44e71e4a1