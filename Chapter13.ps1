# ADCS Role Install with MGMT Tools

Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

# Configre Standalone CA

Install-ADcsCertificationAuthority -CACommonName "REBELAdmin Root CA" -CAType StandaloneRootCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -HashAlgorithmName SHA256 -KeyLength 2048 -ValidityPeriod Years -ValidityPeriodUnits 20

# Install Web Server

Install-WindowsFeature Web-WebServer -IncludeManagementTools

# Setting up Issuing CA

Install-ADcsCertificationAuthority -CACommonName "REBELAdmin IssuingCA" -CAType EnterpriseSubordinateCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -HashAlgorithmName SHA256 -KeyLength 2048