# Install ADFS Role

Install-WindowsFeature ADFS-Federation -IncludeManagementTools

# Configre ADFS Role

Import-Module ADFS
$credentials = Get-Credential
Install-AdfsFarm `
-CertificateThumbprint:"938E369FA88B2F884A5BBC495F2338BE9FA0E0BB" `
-FederationServiceDisplayName:"REBELADMIN INC" `
-FederationServiceName:"adfs.rebeladmin.com" `
-ServiceAccountCredential $credentials

# Install Web Application Proxy Feature

Install-WindowsFeature Web-Application-Proxy -IncludeManagementTools

# Configure the proxy

$credentials = Get-Credential
Install-WebApplicationProxy
-FederationServiceName "adfs.rebeladmin.com"
-FederationServiceTrustCredential $credentials
-CertificateThumbprint "3E0ED21E43BEB1E44AD9C252A92AD5AFB8E5722E"

# Add Application to Proxy

Add-WebApplicationProxyApplication 
-BackendServerUrl 'https://myapp.rebeladmin.com/myapp/' 
-ExternalCertificateThumbprint '3E0ED21E43BEB1E44AD9C252A92AD5AFB8E5722E' 
-ExternalUrl 'https://myapp.rebeladmin.com/myapp/' 
-Name 'MyApp' 
-ExternalPreAuthentication AD FS 
-ADFSRelyingPartyName 'myapp.rebeladmin.com'

# Create Cert for Azure MFA configuration

$certbase64 = New-AdfsAzureMfaTenantCertificate -TenantID 05c6f80c-61d9-44df-bd2d-4414a983c1d4

# Connect to Microsoft Services

Connect-MsolService

# Configure Principle Cred

New-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -Type asymmetric -Usage verify -Value $certbase64

# Enable Azure MFA for ADFS 

Set-AdfsAzureMfaTenant -TenantId 05c6f80c-61d9-44df-bd2d-4414a983c1d4 -ClientId 981f26a1-7f43-403b-a875-f8b09b8cd720