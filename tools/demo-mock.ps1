# Demo data generator: a fictional tenant (Contoso Ltd) behind the Graph calls the admin report makes.
# It replaces Invoke-MgGraphRequest, so no real tenant and no network are involved. All names, domains and IDs are made up.
# Use tools\Build-Demos.ps1 to build the three demo reports; run this file directly only for tests.
#
# Environment switches (all optional):
#   DEMO_BASELINE          Free, P1 or P2 (default P2)
#   DEMO_SECURITYDEFAULTS  on: security defaults are enabled (the Free demo uses it)
#   DEMO_SCENARIO          NoP1_SecurityDefaultsOn, NoP1_SecurityDefaultsOff or P1_SecurityDefaultsOn: no Conditional Access policies
#   DEMO_ZERO              no administrators at all (test)
#   DEMO_GUESTONLY         only guest administrators (test)
#   DEMO_NOSYNC            leave out the Entra Connect sync accounts (test)
# Fictional "Contoso Ltd" tenant for the demo report. Shadows the Graph and ARM calls the admin report makes.
param([string]$Script, [string]$Out)
$ErrorActionPreference = 'Stop'

function global:New-DemoId([string]$Name) {
    $h = [Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("demo-$Name"))
    ([guid]::new($h)).ToString()
}
function global:Ago([int]$Days) { (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('o') }
function global:Ahead([int]$Days) { (Get-Date).ToUniversalTime().AddDays($Days).ToString('o') }

$R = @{
    GA = '62e90394-69f5-4237-9190-012177145e10'; UA = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; EXO = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    SEC = '194ae4cb-b126-40b2-bd5b-6091b380977d'; HELP = '729827e3-9c14-49f7-bb1b-9608f156bbb8'; PRA = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
    CAA = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'; RR = '4a5d8f65-41da-4de4-8968-e035b65339cf'; INTUNE = '3a2c62db-5318-420d-8d74-23affee5d9d5'
    APP = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'; CAPP = '158c047a-c907-4556-b7ef-446551a6b5f7'; SYNC = 'd29b2b05-8046-44ba-8758-1e26182fcf32'
}
$global:RoleDefs = @(
    @{ id = $R.GA; displayName = 'Global Administrator'; isPrivileged = $true }, @{ id = $R.UA; displayName = 'User Administrator'; isPrivileged = $true }
    @{ id = $R.EXO; displayName = 'Exchange Administrator'; isPrivileged = $false }, @{ id = $R.SEC; displayName = 'Security Administrator'; isPrivileged = $true }
    @{ id = $R.HELP; displayName = 'Helpdesk Administrator'; isPrivileged = $true }, @{ id = $R.PRA; displayName = 'Privileged Role Administrator'; isPrivileged = $true }
    @{ id = $R.CAA; displayName = 'Conditional Access Administrator'; isPrivileged = $true }, @{ id = $R.RR; displayName = 'Reports Reader'; isPrivileged = $false }
    @{ id = $R.INTUNE; displayName = 'Intune Administrator'; isPrivileged = $true }, @{ id = $R.APP; displayName = 'Application Administrator'; isPrivileged = $true }
    @{ id = $R.CAPP; displayName = 'Cloud Application Administrator'; isPrivileged = $true }
    @{ id = $R.SYNC; displayName = 'Directory Synchronization Accounts'; isPrivileged = $true }
)

# key, display name, upn, mail, other mails, type, created (days ago), enabled, synced, sku, plans, last sign-in (days ago, $null = never)
$global:Users = @{}; $global:UserKeys = @{}
function global:Add-DemoUser($Key, $Name, $Upn, $Mail, $Other, $Type, $CreatedDays, $Enabled, $Synced, $Sku, $Plans, $LastDays) {
    $id = New-DemoId $Key
    $global:UserKeys[$Key] = $id
    $sign = if ($null -ne $LastDays) { @{ lastSuccessfulSignInDateTime = (Ago $LastDays); lastSignInDateTime = (Ago $LastDays); lastNonInteractiveSignInDateTime = (Ago ([Math]::Max(0, $LastDays - 1))) } } else { $null }
    $global:Users[$id] = @{
        id = $id; displayName = $Name; userPrincipalName = $Upn; mail = $Mail; otherMails = @($Other); userType = $Type; createdDateTime = (Ago $CreatedDays)
        accountEnabled = $Enabled; onPremisesSyncEnabled = $(if ($Synced) { $true } else { $null })
        assignedLicenses = @($Sku | Where-Object { $_ } | ForEach-Object { @{ skuId = $_ } }); assignedPlans = @($Plans | Where-Object { $_ } | ForEach-Object { @{ servicePlanId = $_; capabilityStatus = 'Enabled' } }); signInActivity = $sign
    }
}
Add-DemoUser 'alex' 'Alex Morgan' 'adm-amorgan@contoso.com' $null @('alex.morgan@contoso.com') 'Member' 900 $true $false $null $null 3
Add-DemoUser 'priya' 'Priya Nair' 'adm-pnair@contoso.com' $null @('priya.nair@contoso.com') 'Member' 700 $true $false $null $null 1
Add-DemoUser 'daniel' 'Daniel Brooks' 'dbrooks@contoso.com' 'dbrooks@contoso.com' @() 'Member' 2400 $true $true @('s1') @('p1', 'p2', 'p3', 'p4') 0
Add-DemoUser 'sofia' 'Sofia Rossi' 'srossi-admin@contoso.com' 'srossi-admin@contoso.com' @() 'Member' 1200 $true $false @('s3') @('p1', 'p2', 'p3', 'p4', 'p5') 5
Add-DemoUser 'tomasz' 'Tomasz Wolf' 'adm-twolf@contoso.com' $null @() 'Member' 500 $true $false @('s4') @('p6') 12
Add-DemoUser 'chen' 'Chen Li' 'adm-cli@contoso.com' $null @('chen.li@contoso.com') 'Member' 400 $true $false $null $null 8
Add-DemoUser 'marta' 'Marta Silva' 'adm-msilva@contoso.com' $null @('marta.silva@contoso.com') 'Member' 1500 $true $false $null $null 210
Add-DemoUser 'oliver' 'Oliver Grant' 'oliver.grant@contoso.com' 'oliver.grant@contoso.com' @() 'Member' 800 $true $false @('s2') @('p2') 1
Add-DemoUser 'emma' 'Emma Vogel' 'adm-evogel@contoso.com' $null @('emma.vogel@contoso.com') 'Member' 600 $true $false $null $null 20
Add-DemoUser 'ben' 'Ben Carter' 'ben.carter_fabrikam.com#EXT#@contoso.onmicrosoft.com' 'ben.carter@fabrikam.com' @() 'Guest' 250 $true $false $null $null $null
Add-DemoUser 'bg1' 'Emergency Access 01' 'emergency01@contoso.onmicrosoft.com' $null @() 'Member' 1800 $true $false $null $null 45
Add-DemoUser 'bg2' 'Emergency Access 02' 'emergency02@contoso.onmicrosoft.com' $null @() 'Member' 1800 $true $false $null $null 30
Add-DemoUser 'hannah' 'Hannah Weber' 'adm-hweber@contoso.com' $null @('hannah.weber@contoso.com') 'Member' 650 $true $false @('s4') @('p6') 2
Add-DemoUser 'luca' 'Luca Bianchi' 'adm-lbianchi@contoso.com' $null @('luca.bianchi@contoso.com') 'Member' 550 $true $false $null $null 4
Add-DemoUser 'nina' 'Nina Petrov' 'adm-npetrov@contoso.com' 'nina.petrov+admin@contoso.com' @() 'Member' 1000 $true $false @('s4') @('p6') 6
Add-DemoUser 'karl' 'Karl Neumann' 'adm-kneumann@contoso.com' $null @() 'Member' 2000 $false $false $null $null 400
Add-DemoUser 'yuki' 'Yuki Tanaka' 'adm-ytanaka@contoso.com' 'adm-ytanaka@contoso.com' @() 'Member' 900 $true $false @('s2') @('p2') 9
Add-DemoUser 'recovery' 'Recovery Admin' 'recovery01@contoso.onmicrosoft.com' $null @() 'Member' 1700 $true $false $null $null 150
# Entra Connect connector accounts (default display name, non-interactive sign-ins only) and a regular user who was given the sync role
Add-DemoUser 'sync1' 'On-Premises Directory Synchronization Service Account' 'Sync_CONTOSO-AADC01_3f9a1c27b8d4@contoso.onmicrosoft.com' $null @() 'Member' 1500 $true $false $null $null 0
Add-DemoUser 'sync2' 'On-Premises Directory Synchronization Service Account' 'ADToAADSyncServiceAccount@contoso.onmicrosoft.com' $null @() 'Member' 2100 $true $false $null $null 303
foreach ($k in 'sync1', 'sync2') { $global:Users[$global:UserKeys[$k]].signInActivity.lastSignInDateTime = $null }
Add-DemoUser 'rene' 'Rene Dubois' 'adm-rdubois@contoso.com' $null @('rene.dubois@contoso.com') 'Member' 350 $true $false @('s2') @('p2') 2
Add-DemoUser 'lena' 'Lena Ostrom' 'lena.ostrom_northwind.com#EXT#@contoso.onmicrosoft.com' 'lena.ostrom@northwind.com' @() 'Guest' 120 $true $false $null $null 6
# Azure-only users (developers): they only show up when all Azure roles are reported
Add-DemoUser 'tessa' 'Tessa Moore' 'tessa.moore_litware.com#EXT#@contoso.onmicrosoft.com' 'tessa.moore@litware.com' @() 'Guest' 90 $true $false $null $null 4
Add-DemoUser 'omar' 'Omar Haddad' 'omar.haddad_tailspin.com#EXT#@contoso.onmicrosoft.com' 'omar.haddad@tailspin.com' @() 'Guest' 80 $true $false $null $null 7
Add-DemoUser 'finn' 'Finn Larsen' 'finn.larsen_fabrikam.com#EXT#@contoso.onmicrosoft.com' 'finn.larsen@fabrikam.com' @() 'Guest' 50 $true $false $null $null 3
Add-DemoUser 'maya' 'Maya Ortiz' 'maya.ortiz_outlook.com#EXT#@contoso.onmicrosoft.com' 'maya.ortiz@outlook.com' @() 'Guest' 40 $true $false $null $null 5
Add-DemoUser 'gwen' 'Gwen Parker' 'gwen.parker_gmail.com#EXT#@contoso.onmicrosoft.com' 'gwen.parker@gmail.com' @() 'Guest' 70 $true $false $null $null 2
Add-DemoUser 'eli' 'Eli Kim' 'eli.kim_adatum.com#EXT#@contoso.onmicrosoft.com' 'eli.kim@adatum.com' @() 'Guest' 60 $true $false $null $null 11
foreach ($k in 'ben', 'lena', 'tessa', 'omar', 'finn') { $global:Users[$global:UserKeys[$k]].identities = ,@{ signInType = 'federated'; issuer = 'ExternalAzureAD'; issuerAssignedId = '00000000-0000-0000-0000-000000000001' } }
$global:Users[$global:UserKeys['maya']].identities = ,@{ signInType = 'federated'; issuer = 'MicrosoftAccount'; issuerAssignedId = '2002' }
$global:Users[$global:UserKeys['gwen']].identities = ,@{ signInType = 'federated'; issuer = 'google.com'; issuerAssignedId = '1001' }
$global:Users[$global:UserKeys['eli']].identities = ,@{ signInType = 'federated'; issuer = 'mail'; issuerAssignedId = 'eli.kim@adatum.com' }
Add-DemoUser 'jonas' 'Jonas Keller' 'jonas.keller@contoso.com' 'jonas.keller@contoso.com' @() 'Member' 300 $true $false $null $null 1
Add-DemoUser 'mira' 'Mira Horvat' 'mira.horvat@contoso.com' 'mira.horvat@contoso.com' @() 'Member' 420 $true $false $null $null 3
Add-DemoUser 'dana' 'Dana Fox' 'dana.fox@contoso.com' 'dana.fox@contoso.com' @() 'Member' 200 $true $false $null $null 2

$u = $global:UserKeys
$global:Groups = @{
    (New-DemoId 'g-help') = @{ displayName = 'Helpdesk Operators'; isAssignableToRole = $true; members = @($u.tomasz); owners = @($u.emma); eligible = @() }
    (New-DemoId 'g-pim')  = @{ displayName = 'PIM-Identity-Admins'; isAssignableToRole = $true; members = @(); owners = @(); eligible = @($u.chen) }
    (New-DemoId 'g-azure') = @{ displayName = 'Azure-Platform-Owners'; isAssignableToRole = $false; members = @($u.luca); owners = @(); eligible = @() }
    (New-DemoId 'g-dev') = @{ displayName = 'Dev-Team-Prod'; isAssignableToRole = $false; members = @($u.dana); owners = @(); eligible = @() }
}
$gHelp = New-DemoId 'g-help'; $gPim = New-DemoId 'g-pim'; $gAzure = New-DemoId 'g-azure'; $gDev = New-DemoId 'g-dev'
$gCaExcl = New-DemoId 'g-ca-excl'; $gCaAdmins = New-DemoId 'g-ca-admins'
$global:GroupMemberOf = @{ $u.tomasz = @($gCaExcl); $u.karl = @($gCaExcl); $u.alex = @($gCaAdmins); $u.priya = @($gCaAdmins); $u.chen = @($gCaAdmins) }

# Scope ids used by the role assignments below
$global:AuId = '6e0b5f7c-2d41-4a89-8f35-1c9d7e2a4b63'
$global:AppId = New-DemoId 'app-hrportal'
$global:DeletedAppId = New-DemoId 'app-deleted'
# Active assignments (principal, role, scope, assignmentType, end)
$global:Active = @(
    @($u.daniel, $R.GA, '/', 'Assigned', $null), @($u.daniel, $R.RR, '/', 'Assigned', $null), @($u.bg1, $R.GA, '/', 'Assigned', $null), @($u.bg2, $R.GA, '/', 'Assigned', $null), @($u.recovery, $R.GA, '/', 'Assigned', $null)
    @($u.sofia, $R.EXO, '/', 'Assigned', $null), @($gHelp, $R.HELP, '/', 'Assigned', $null), @($u.marta, $R.INTUNE, '/', 'Assigned', $null)
    @($u.oliver, $R.RR, '/administrativeUnits/6e0b5f7c-2d41-4a89-8f35-1c9d7e2a4b63', 'Assigned', (Ahead 60)), @($u.ben, $R.APP, '/', 'Assigned', $null)
    @($u.karl, $R.CAPP, '/', 'Assigned', $null), @($u.nina, $R.CAA, '/', 'Assigned', $null), @($u.yuki, $R.PRA, '/', 'Assigned', $null)
    @($u.priya, $R.SEC, '/', 'Activated', (Ahead 1)), @($gPim, $R.UA, '/', 'Assigned', $null)
    @($u.sync1, $R.SYNC, '/', 'Assigned', $null), @($u.sync2, $R.SYNC, '/', 'Assigned', $null), @($u.rene, $R.SYNC, '/', 'Assigned', $null)
    @($u.oliver, $R.UA, "/administrativeUnits/$($global:AuId)", 'Assigned', $null), @($u.sofia, $R.APP, "/$($global:AppId)", 'Assigned', $null), @($u.nina, $R.APP, "/$($global:DeletedAppId)", 'Assigned', $null), @($u.lena, $R.UA, "/administrativeUnits/$($global:AuId)", 'Assigned', $null), @($u.tessa, $R.RR, '/', 'Assigned', $null), @($u.omar, $R.RR, '/', 'Assigned', $null), @($u.gwen, $R.RR, '/', 'Assigned', $null), @($u.eli, $R.RR, '/', 'Assigned', $null), @($u.finn, $R.RR, '/', 'Assigned', $null), @($u.maya, $R.RR, '/', 'Assigned', $null)
)
if ($env:DEMO_ZERO) { $global:Active = @(); $global:Eligible = @() }
if ($env:DEMO_GUESTONLY) { $guestIds = @($u.ben, $u.lena, $u.tessa, $u.omar, $u.gwen, $u.eli, $u.finn, $u.maya); $global:Active = @($global:Active | Where-Object { $_[0] -in $guestIds }); $global:Eligible = @() }
if ($env:DEMO_NOSYNC) { $global:Active = @($global:Active | Where-Object { $_[1] -ne $R.SYNC }) }
$global:Eligible = @(@($u.alex, $R.GA), @($u.priya, $R.PRA), @($u.hannah, $R.SEC))

$global:Registration = @{
    alex = @('passKeyDeviceBound', 'microsoftAuthenticatorPush'); priya = @('passKeyDeviceBound', 'windowsHelloForBusiness'); daniel = @('windowsHelloForBusiness', 'mobilePhone', 'microsoftAuthenticatorPush')
    sofia = @('mobilePhone', 'microsoftAuthenticatorPush'); tomasz = @(); chen = @('passKeyDeviceBound'); marta = @('microsoftAuthenticatorPush', 'officePhone'); oliver = @('passKeyDeviceBound')
    emma = @('microsoftAuthenticatorPasswordless'); ben = @(); bg1 = @('passKeyDeviceBound'); bg2 = @(); hannah = @('passKeyDeviceBound', 'windowsHelloForBusiness'); luca = @('windowsHelloForBusiness')
    nina = @('passKeyDeviceBound'); yuki = @('passKeyDeviceBound', 'microsoftAuthenticatorPush'); recovery = @('passKeyDeviceBound')
    jonas = @('passKeyDeviceBound'); mira = @('windowsHelloForBusiness'); dana = @('microsoftAuthenticatorPush'); sync1 = @(); sync2 = @(); rene = @('microsoftAuthenticatorPush'); lena = @(); tessa = @(); omar = @(); gwen = @('microsoftAuthenticatorPush'); finn = @('microsoftAuthenticatorPush', 'mobilePhone'); maya = @('microsoftAuthenticatorPush'); eli = @()
}
$global:Passkeys = @{
    alex = @(@('YubiKey 5C NFC', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 600)); priya = @(@('YubiKey 5 NFC', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 420))
    chen = @(@('Security key', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 300)); marta = @(@('Security key', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 900))
    oliver = @(@('Passkey (Authenticator)', 'Microsoft Authenticator', '90a3ccdf-635c-4729-a248-9b709135078f', 120)); emma = @(@('Security key', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 350))
    bg1 = @(@('EA01 key (safe A)', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 800), @('EA01 key (safe B)', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 800))
    hannah = @(@('Security key', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 500)); nina = @(@('Security key', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 650))
    yuki = @(@('Passkey (Authenticator)', 'Microsoft Authenticator', '90a3ccdf-635c-4729-a248-9b709135078f', 200)); recovery = @(@('Recovery key', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 1000))
    jonas = @(@('Security key', 'YubiKey 5 Series', 'ee882879-721c-4913-9775-3dfcce97072a', 250))
}

$caUsers = { param($inc, $exc, $incRoles, $incGroups, $excGroups) @{ includeUsers = @($inc); excludeUsers = @($exc); includeRoles = @($incRoles); includeGroups = @($incGroups); excludeGroups = @($excGroups) } }
$prStrength = '00000000-0000-0000-0000-000000000004'
$global:LocIds = @{ hq = (New-DemoId 'loc-hq'); countries = (New-DemoId 'loc-countries'); gsa = (New-DemoId 'loc-gsa') }
$global:CaPolicies = @(
    @{ id = 'c1'; displayName = 'CA001 - Require MFA for all users'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; users = (& $caUsers @('All') @($u.bg1, $u.recovery) @() @() @($gCaExcl)) } }
    @{ id = 'c2'; displayName = 'CA010 - Require phishing-resistant MFA for administrators'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = $prStrength } }; sessionControls = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 4; frequencyInterval = 'timeBased' } }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; users = (& $caUsers @() @($u.bg1, $u.recovery) @($R.GA, $R.PRA, $R.SEC, $R.UA, $R.CAA) @($gCaAdmins) @()) } }
    @{ id = 'c3'; displayName = 'CA020 - Require MFA for Microsoft admin portals'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('MicrosoftAdminPortals') }; users = (& $caUsers @('All') @($u.bg1, $u.recovery) @() @() @()) } }
    @{ id = 'c5'; displayName = 'CA011 - Require compliant or hybrid joined device for administrators'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('compliantDevice', 'domainJoinedDevice') }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; users = (& $caUsers @() @($u.bg1, $u.recovery) @($R.GA, $R.SEC) @($gCaAdmins) @()) } }
    @{ id = 'c6'; displayName = 'CA012 - Block administrators outside trusted locations'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('block') }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; locations = @{ includeLocations = @('All'); excludeLocations = @('AllTrusted', $global:LocIds.gsa) }; users = (& $caUsers @() @($u.bg1, $u.recovery) @($R.GA, $R.UA) @() @()) } }
    @{ id = 'c10'; displayName = 'CA015 - Require phishing-resistant MFA for Global Administrators (backup policy)'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = $prStrength } }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; users = (& $caUsers @() @($u.bg1, $u.recovery) @($R.GA) @() @()) } }
    @{ id = 'c7'; displayName = 'CA030 - Sign-in frequency for service desk and device administrators (12 hours)'; state = 'enabled'; sessionControls = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 12; frequencyInterval = 'timeBased' } }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; users = (& $caUsers @() @($u.bg1, $u.recovery) @($R.EXO, $R.INTUNE, $R.HELP) @() @()) } }
    @{ id = 'c8'; displayName = 'CA013 - Compliant device, hybrid joined device or MFA for device and mail administrators'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice', 'domainJoinedDevice') }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; users = (& $caUsers @() @($u.bg1, $u.recovery) @($R.EXO, $R.INTUNE) @() @()) } }
    @{ id = 'c9'; displayName = 'CA014 - Block service desk outside allowed countries'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('block') }
       conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; locations = @{ includeLocations = @('All'); excludeLocations = @($global:LocIds.countries) }; users = (& $caUsers @() @($u.bg1, $u.recovery) @($R.HELP) @() @()) } }
    @{ id = 'c4'; displayName = 'CA040 - Block legacy authentication'; state = 'enabledForReportingButNotEnforced'; grantControls = @{ operator = 'OR'; builtInControls = @('block') }
       conditions = @{ clientAppTypes = @('exchangeActiveSync', 'other'); applications = @{ includeApplications = @('All') }; users = (& $caUsers @('All') @() @() @() @()) } }
)

# Azure
$global:TenantId = '3f1c9a7e-5d24-4b8a-9c61-72e0b4d8a135'
$sub1 = New-DemoId 'sub-prod'; $sub2 = New-DemoId 'sub-dev'
$AZ = @{ Owner = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; Contributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; UAA = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'; Reader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
         VMC = '9980e02c-c2be-4d73-94e8-173b1dc7cf3c'; SBDC = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'; Deployer = (New-DemoId 'role-deployer') }
$global:AzAssign = @{
    $sub1 = @(
        @($u.hannah, $AZ.Owner, "/subscriptions/$sub1"), @($u.marta, $AZ.Contributor, "/subscriptions/$sub1/resourceGroups/rg-app")
        @($u.jonas, $AZ.VMC, "/subscriptions/$sub1/resourceGroups/rg-app"), @($u.jonas, $AZ.Reader, "/subscriptions/$sub1"), @($u.jonas, $AZ.Deployer, "/subscriptions/$sub1/resourceGroups/rg-app")
        ,@($u.mira, $AZ.SBDC, "/subscriptions/$sub1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stcontosodata")
        ,@($gDev, $AZ.Reader, "/subscriptions/$sub1")
    )
    $sub2 = @(@($gAzure, $AZ.Owner, "/subscriptions/$sub2"))
}
$global:AzElig = @(@($u.luca, $AZ.UAA, '/providers/Microsoft.Management/managementGroups/mg-contoso'))
$global:AzSubs = @(@{ subscriptionId = $sub1; displayName = 'Production' }, @{ subscriptionId = $sub2; displayName = 'Development' })
$global:AzDefs = @(
    @{ name = $AZ.Owner; properties = @{ roleName = 'Owner'; type = 'BuiltInRole'; permissions = @(@{ actions = @('*'); notActions = @() }) } }
    @{ name = $AZ.Contributor; properties = @{ roleName = 'Contributor'; type = 'BuiltInRole'; permissions = @(@{ actions = @('*'); notActions = @('Microsoft.Authorization/*/Write') }) } }
    @{ name = $AZ.UAA; properties = @{ roleName = 'User Access Administrator'; type = 'BuiltInRole'; permissions = @(@{ actions = @('*/read', 'Microsoft.Authorization/*', 'Microsoft.Support/*'); notActions = @() }) } }
    @{ name = $AZ.Reader; properties = @{ roleName = 'Reader'; type = 'BuiltInRole'; permissions = @(@{ actions = @('*/read'); notActions = @() }) } }
    @{ name = $AZ.VMC; properties = @{ roleName = 'Virtual Machine Contributor'; type = 'BuiltInRole'; permissions = @(@{ actions = @('Microsoft.Compute/virtualMachines/*', 'Microsoft.Network/networkInterfaces/read'); notActions = @() }) } }
    @{ name = $AZ.SBDC; properties = @{ roleName = 'Storage Blob Data Contributor'; type = 'BuiltInRole'; permissions = @(@{ actions = @('Microsoft.Storage/storageAccounts/blobServices/containers/read', 'Microsoft.Storage/storageAccounts/blobServices/containers/write'); notActions = @() }) } }
    @{ name = $AZ.Deployer; properties = @{ roleName = 'Contoso App Deployer'; type = 'CustomRole'; permissions = @(@{ actions = @('Microsoft.Resources/deployments/*', 'Microsoft.Authorization/roleAssignments/write'); notActions = @() }) } }
)

# Scope demo: an administrative unit, an app registration, and an app registration that no longer exists
$global:AuId = '6e0b5f7c-2d41-4a89-8f35-1c9d7e2a4b63'
$global:AppId = New-DemoId 'app-hrportal'
$global:DeletedAppId = New-DemoId 'app-deleted'
$global:ScopeObjects = @{ $global:AppId = @{ '@odata.type' = '#microsoft.graph.application'; id = $global:AppId; displayName = 'HR Portal' } }
function global:Connect-MgGraph { param($Scopes, $TenantId, $AccessToken, $ClientId, $CertificateThumbprint, [switch]$Identity, [switch]$NoWelcome) }
function global:Get-MgContext { @{ TenantId = $global:TenantId } }
function global:Disconnect-MgGraph { }
# A one-element list of arrays collapses to a flat array in PowerShell; restore the nesting where the data is stored
foreach ($k in @($global:Passkeys.Keys)) { if ($global:Passkeys[$k][0] -is [string]) { $global:Passkeys[$k] = ,$global:Passkeys[$k] } }
foreach ($k in @($global:AzAssign.Keys)) { if ($global:AzAssign[$k][0] -is [string]) { $global:AzAssign[$k] = ,$global:AzAssign[$k] } }
if ($global:AzElig[0] -is [string]) { $global:AzElig = ,$global:AzElig }
# DEMO_LIMITED=1 simulates an Azure identity without Reader on the root management group and without access to the Development subscription
function global:Invoke-RestMethod { param($Method, $Uri, $Headers, $ErrorAction)
    $limited = [bool]$env:DEMO_LIMITED
    if ($Uri -like '*/providers/Microsoft.Management/managementGroups?api-version*') {
        if ($limited) { throw '403 Forbidden' }
        return @{ value = @(@{ name = $global:TenantId; properties = @{ displayName = 'Tenant Root Group' } }, @{ name = 'mg-contoso'; properties = @{ displayName = 'Contoso' } }) }
    }
    if ($Uri -like '*/subscriptions?api-version*') { return @{ value = $global:AzSubs } }
    if ($Uri -match '/providers/Microsoft\.Management/managementGroups/([^/]+)/providers/Microsoft\.Authorization/(roleDefinitions|roleAssignments|roleEligibilityScheduleInstances)') {
        $mg = $Matches[1]; $kind = $Matches[2]
        if ($limited -and $mg -eq $global:TenantId) { throw '403 Forbidden' }
        $mgScope = "/providers/Microsoft.Management/managementGroups/$mg"
        if ($kind -eq 'roleDefinitions') { return @{ value = $global:AzDefs } }
        if ($kind -eq 'roleAssignments') { return @{ value = @() } }
        return @{ value = @($global:AzElig | Where-Object { $_[2] -eq $mgScope } | ForEach-Object { @{ properties = @{ principalId = $_[0]; roleDefinitionId = "$mgScope/providers/Microsoft.Authorization/roleDefinitions/$($_[1])"; scope = $_[2]; endDateTime = $null } } }) }
    }
    if ($Uri -match '/subscriptions/([^/]+)/providers/Microsoft\.Authorization/roleDefinitions') { return @{ value = $global:AzDefs } }
    if ($Uri -match '/subscriptions/([^/]+)/providers/Microsoft\.Authorization/roleAssignments') {
        $s = $Matches[1]
        if ($limited -and $s -eq $sub2) { throw '403 Forbidden' }
        return @{ value = @($global:AzAssign[$s] | ForEach-Object { @{ properties = @{ principalId = $_[0]; roleDefinitionId = "/subscriptions/$s/providers/Microsoft.Authorization/roleDefinitions/$($_[1])"; scope = $_[2] } } }) }
    }
    if ($Uri -match '/subscriptions/([^/]+)/providers/Microsoft\.Authorization/roleEligibilityScheduleInstances') {
        $s = $Matches[1]
        return @{ value = @($global:AzElig | ForEach-Object { @{ properties = @{ principalId = $_[0]; roleDefinitionId = "/subscriptions/$s/providers/Microsoft.Authorization/roleDefinitions/$($_[1])"; scope = $_[2]; endDateTime = $null } } }) }
    }
    throw "Demo mock: unexpected ARM request $Uri"
}function global:Get-DemoBatchItem { param([string]$Url)
    $guid = '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    switch -Regex ($Url) {
        "^/users/$guid\?" { return @{ status = 200; body = $global:Users[$Matches[1]] } }
        "^/reports/authenticationMethods/userRegistrationDetails/$guid" {
            if ($env:DEMO_NOAUTH) { return @{ status = 403; body = @{} } }
            $key = ($global:UserKeys.GetEnumerator() | Where-Object { $_.Value -eq $Matches[1] }).Key
            if ($key -eq 'karl') { return @{ status = 404; body = @{} } }
            $m = @($global:Registration[$key])
            return @{ status = 200; body = @{ isMfaCapable = ($m.Count -gt 0); isPasswordlessCapable = (@($m | Where-Object { $_ -match 'passKey|windowsHello' }).Count -gt 0); methodsRegistered = $m; userPreferredMethodForSecondaryAuthentication = $(if ($m -contains 'microsoftAuthenticatorPush') { 'push' } elseif ($m -contains 'mobilePhone') { 'sms' } elseif ($m -contains 'officePhone') { 'voiceOffice' } else { 'none' }) } }
        }
        "^/users/$guid/authentication/fido2Methods" {
            $key = ($global:UserKeys.GetEnumerator() | Where-Object { $_.Value -eq $Matches[1] }).Key
            return @{ status = 200; body = @{ value = @($global:Passkeys[$key] | Where-Object { $_ } | ForEach-Object { @{ displayName = $_[0]; model = $_[1]; aaGuid = $_[2]; createdDateTime = (Ago $_[3]) } }) } }
        }
        "^/users/$guid/transitiveMemberOf" { return @{ status = 200; body = @{ value = @($global:GroupMemberOf[$Matches[1]] | Where-Object { $_ } | ForEach-Object { @{ id = $_ } }) } } }
        "^/groups/$guid/transitiveMembers" { return @{ status = 200; body = @{ value = @($global:Groups[$Matches[1]].members | ForEach-Object { @{ id = $_ } }) } } }
        "^/groups/$guid/owners" { return @{ status = 200; body = @{ value = @($global:Groups[$Matches[1]].owners | ForEach-Object { @{ '@odata.type' = '#microsoft.graph.user'; id = $_ } }) } } }
        "eligibilityScheduleInstances\?\`$filter=groupId%20eq%20%27$guid%27" { return @{ status = 200; body = @{ value = @($global:Groups[$Matches[1]].eligible | ForEach-Object { @{ principalId = $_; accessId = 'member'; endDateTime = $null } }) } } }
    }
    return @{ status = 400; body = @{} }
}
# Demo scenarios (DEMO_SCENARIO): NoP1_SecurityDefaultsOn, NoP1_SecurityDefaultsOff, P1_SecurityDefaultsOn. They have no Conditional Access policies.
function global:Finish-Skus { param($Skus)
    foreach ($sku in $Skus) {
        $sku.capabilityStatus = 'Enabled'; $sku.prepaidUnits = @{ enabled = 25 }
        $sku.servicePlans = @(@($sku.servicePlans) | Where-Object { -not ($env:DEMO_SCENARIO -like 'NoP1*' -and $_.servicePlanName -like 'AAD_PREMIUM*') } | ForEach-Object { $_.provisioningStatus = 'Success'; $_ })
    }
    return $Skus
}
function global:Invoke-MgGraphRequest { param($Method, $Uri, $Body, $ContentType, $Headers)
    if ($Uri -like '*$batch') {
        $requests = ($Body | ConvertFrom-Json).requests
        return @{ responses = @($requests | ForEach-Object { $r = Get-DemoBatchItem $_.url; $r.id = $_.id; $r }) }
    }
    switch -Wildcard ($Uri) {
        '*findTenantInformationByDomainName*' {
            if ($env:DEMO_NOCROSS) { throw '403 Forbidden: Insufficient privileges to complete the operation.' }
            $null = $Uri -match "domainName='([^']+)'"
            switch ($Matches[1]) { 'fabrikam.com' { return @{ tenantId = 'f0000000-0000-4000-8000-000000000001' } } 'northwind.com' { return @{ tenantId = 'f0000000-0000-4000-8000-000000000002' } } 'litware.com' { return @{ tenantId = 'f0000000-0000-4000-8000-000000000003' } } default { throw '400 BadRequest: tenant not found' } }
        }
        '*crossTenantAccessPolicy/partners/*' {
            if ($Uri -like '*000000000001') { return @{ inboundTrust = @{ isMfaAccepted = $true } } }
            if ($Uri -like '*000000000003') { return @{ inboundTrust = @{ isMfaAccepted = $false } } }
            throw '404 NotFound'
        }
        '*crossTenantAccessPolicy/default' { return @{ inboundTrust = @{ isMfaAccepted = $true } } }
        '*roleDefinitions*' { return @{ value = $global:RoleDefs } }
        '*roleAssignmentScheduleInstances*' { return @{ value = @($global:Active | ForEach-Object { @{ principalId = $_[0]; roleDefinitionId = $_[1]; directoryScopeId = $_[2]; assignmentType = $_[3]; endDateTime = $_[4] } }) } }
        '*roleAssignments' { return @{ value = @($global:Active | ForEach-Object { @{ principalId = $_[0]; roleDefinitionId = $_[1]; directoryScopeId = $_[2] } }) } }
        '*roleEligibilitySchedules' { return @{ value = @($global:Eligible | ForEach-Object { @{ principalId = $_[0]; roleDefinitionId = $_[1]; directoryScopeId = '/'; scheduleInfo = @{ expiration = @{ endDateTime = (Ahead 180) } } } }) } }
        '*administrativeUnits*' { if ($env:DEMO_SCOPEFAIL) { throw '403 Forbidden' }; return @{ value = @(@{ id = $global:AuId; displayName = 'Sales EMEA' }, @{ id = (New-DemoId 'au-finance'); displayName = 'Finance' }) } }
        '*getByIds' {
            if ($env:DEMO_SCOPEFAIL -and (($Body | ConvertFrom-Json).types -contains 'application')) { throw '403 Forbidden' }
            $ids = ($Body | ConvertFrom-Json).ids
            return @{ value = @($ids | ForEach-Object {
                if ($global:Users.ContainsKey($_)) { @{ '@odata.type' = '#microsoft.graph.user'; id = $_ } }
                elseif ($global:ScopeObjects.ContainsKey($_)) { $global:ScopeObjects[$_] }
                elseif ($global:Groups.ContainsKey($_)) { @{ '@odata.type' = '#microsoft.graph.group'; id = $_; displayName = $global:Groups[$_].displayName; isAssignableToRole = $global:Groups[$_].isAssignableToRole } }
            }) }
        }
        '*subscribedSkus' { return @{ value = (global:Finish-Skus @(
            @{ skuId = 's1'; skuPartNumber = 'SPE_E5'; servicePlans = @(@{ servicePlanId = 'p1'; servicePlanName = 'EXCHANGE_S_ENTERPRISE' }, @{ servicePlanId = 'p2'; servicePlanName = 'TEAMS1' }, @{ servicePlanId = 'p3'; servicePlanName = 'SHAREPOINTENTERPRISE' }, @{ servicePlanId = 'p4'; servicePlanName = 'OFFICESUBSCRIPTION' }) }
            @{ skuId = 's2'; skuPartNumber = 'Microsoft_Teams_Enterprise_New'; servicePlans = @(@{ servicePlanId = 'p2'; servicePlanName = 'TEAMS1' }) }
            @{ skuId = 's3'; skuPartNumber = 'SPE_E3'; servicePlans = @(@{ servicePlanId = 'p1'; servicePlanName = 'EXCHANGE_S_ENTERPRISE' }, @{ servicePlanId = 'p2'; servicePlanName = 'TEAMS1' }, @{ servicePlanId = 'p3'; servicePlanName = 'SHAREPOINTENTERPRISE' }, @{ servicePlanId = 'p4'; servicePlanName = 'OFFICESUBSCRIPTION' }, @{ servicePlanId = 'p5'; servicePlanName = 'AAD_PREMIUM' }, @{ servicePlanId = 'p7'; servicePlanName = 'EXCHANGE_S_FOUNDATION' }) }
            @{ skuId = 's4'; skuPartNumber = 'AAD_PREMIUM_P2'; servicePlans = @(@{ servicePlanId = 'p6'; servicePlanName = 'AAD_PREMIUM_P2' }, @{ servicePlanId = 'p5'; servicePlanName = 'AAD_PREMIUM' }) })) } }
        '*authenticationStrength/policies' { return @{ value = @(@{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA'; allowedCombinations = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor') }) } }
        '*conditionalAccess/namedLocations' { return @{ value = @(
            @{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; id = $global:LocIds.hq; displayName = 'Contoso HQ and branch offices'; isTrusted = $true }
            @{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; id = $global:LocIds.countries; displayName = 'Allowed countries (EU)' }
            @{ '@odata.type' = '#microsoft.graph.compliantNetworkNamedLocation'; id = $global:LocIds.gsa; displayName = 'All Compliant Network locations' }) } }
        '*conditionalAccess/policies' { return @{ value = $(if ($env:DEMO_SCENARIO) { @() } else { $global:CaPolicies }) } }
        '*identitySecurityDefaultsEnforcementPolicy' { return @{ isEnabled = ($env:DEMO_SECURITYDEFAULTS -eq 'on' -or $env:DEMO_SCENARIO -in @('NoP1_SecurityDefaultsOn', 'P1_SecurityDefaultsOn')) } }
        '*organization*' { return @{ value = @(@{ id = '3f1c9a7e-5d24-4b8a-9c61-72e0b4d8a135'; displayName = 'Contoso Ltd' }) } }
    }
    throw "Demo mock: unexpected Graph request $Uri"
}

# DEMO_BASELINE selects the license baseline (default P2). The simple demo uses Free; the scenarios use Free (no P1/P2) or P1.
$baseline = if ($env:DEMO_BASELINE) { $env:DEMO_BASELINE } elseif ($env:DEMO_SIMPLE) { 'Free' } elseif ($env:DEMO_SCENARIO -like 'NoP1*') { 'Free' } elseif ($env:DEMO_SCENARIO) { 'P1' } else { 'P2' }
if ($env:DEMO_SIMPLE) {
    & $Script -LicenseBaseline $baseline -NonInteractive -OutputPath $Out
} else {
    & $Script -LicenseBaseline $baseline -NonInteractive `
        -BreakGlassAccounts 'emergency01@contoso.onmicrosoft.com', 'emergency02@contoso.onmicrosoft.com' -OutputPath $Out
}