# Schema Master Role Holder

Get-ADForest | select SchemaMaster

# Find DomainNamingMaster 

Get-ADForest | select DomainNamingMaster

# Find PDCEmulator

Get-ADDomain | select PDCEmulator

# Find RIDMaster

Get-ADDomain | select RIDMaster

# Find InfrastructureMaster

Get-ADDomain | select InfrastructureMaster

# Move Some FSMO roles

Move-ADDirectoryServerOperationMasterRole -Identity REBEL-SDC02 -OperationMasterRole PDCEmulator, RIDMaster, InfrastructureMaster

# Move All FSMO Roles

Move-ADDirectoryServerOperationMasterRole -Identity REBEL-SDC02 -OperationMasterRole SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster, InfrastructureMaster

# Seize FSMO Roles

Move-ADDirectoryServerOperationMasterRole -Identity REBEL-PDC-01 -OperationMasterRole SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster, InfrastructureMaster -Force