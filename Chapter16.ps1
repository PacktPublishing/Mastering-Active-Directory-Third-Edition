# Find Memebers of a Group

Get-ADGroupMember "First Line Engineers"

# Create a new user

New-ADUser -Name "Dale" -Path "OU=Users,OU=Europe,DC=rebeladmin,DC=com"

# Remove user

Remove-ADUser -Identity "CN=Dishan Francis,OU=Users,OU=Europe,DC=rebeladmin,DC=com"

# Change Password

Set-ADAccountPassword -Identity difrancis

# Create a fine-grained password policy

New-ADFineGrainedPasswordPolicy -Name "Domain Admin Password Policy" -Precedence 1 `
-MinPasswordLength 12 -MaxPasswordAge "30" -MinPasswordAge "7" `
-PasswordHistoryCount 50 -ComplexityEnabled:$true `
-LockoutDuration "8:00" `
-LockoutObservationWindow "8:00" -LockoutThreshold 3 `
-ReversibleEncryptionEnabled:$false

# List Properties of a fine-grained password policy

Get-ADFineGrainedPasswordPolicy –Identity "Domain Admin Password Policy"

# Assign a fine-grained password policy

Add-ADFineGrainedPasswordPolicySubject -Identity "Domain Admin Password Policy" -Subjects "Domain Admins"

# List where policy is applying to

Get-ADFineGrainedPasswordPolicy -Identity "Domain Admin Password Policy" | Format-Table AppliesTo –AutoSize

Get-ADFineGrainedPasswordPolicy -Filter * | Format-Table Name,Precedence,AppliesTo –AutoSize

# Add user to protected user group

Get-ADGroup -Identity "Protected Users" | Add-ADGroupMember –Members "CN=Adam,CN=Users,DC=rebeladmin,DC=com"

# Create an authentication policy

New-ADAuthenticationPolicy -Name "AP_1hr_TGT" -UserTGTLifetimeMins 60 -Enforce

# Create Policy Silo

New-ADAuthenticationPolicySilo -Name Restricted_REBEL_PC01 -UserAuthenticationPolicy AP_1hr_TGT -ComputerAuthenticationPolicy AP_1hr_TGT -ServiceAuthenticationPolicy AP_1hr_TGT -Enforce

# Add objects to policy silos

Grant-ADAuthenticationPolicySiloAccess -Identity Restricted_REBEL_PC01 -Account Peter

Get-ADComputer -Filter 'Name -like "REBEL-PC01"' | Grant-ADAuthenticationPolicySiloAccess -Identity Restricted_REBEL_PC01

# Define access control condition

Set-ADAuthenticationPolicy -Identity AP_1hr_TGT -UserAllowedToAuthenticateFrom "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"Restricted_REBEL_PC01`"))"

# Install RSAT tools

Install-WindowsFeature RSAT-AD-Tools -IncludeAllSubFeature -IncludeManagementTools

# Change Object permissions

Set-AdmPwdComputerSelfPermission -OrgUnit RAServers

# Add extended rights

Set-AdmPwdReadPasswordPermission -Identity "RAServers" -AllowedPrincipals "ITAdmins"

# Register proxy with Azure AD

Import-Module AzureADPasswordProtection
Register-AzureADPasswordProtectionProxy -AccountUpn 'admin@rebeladm.onmicrosoft.com'

# Reigster AD forest

Import-Module AzureADPasswordProtection
Register-AzureADPasswordProtectionForest -AccountUpn 'admin@rebeladm.onmicrosoft.com'

# Set user password 

Set-ADAccountPassword -Identity testuser -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "rebeladmin@A123" -Force)



