<#
.SYNOPSIS
    Generates an interactive HTML security report for administrator accounts in Microsoft Entra ID.
.DESCRIPTION
    This script connects to Microsoft Graph, finds every user that holds or is eligible for a Microsoft Entra
    role (directly, through a group, or through PIM for Groups), and checks each account against the Microsoft
    Learn recommendations for administrator accounts: cloud-only vs. on-premises synced, standing vs.
    just-in-time access, licenses and mailbox, notification address, sign-in activity and break-glass setup.
    -LicenseBaseline says which Microsoft Entra ID license level the report is assessed against; only the controls of
    that level are checked, recommended and summarised.
    The result is a filterable interactive HTML report with a severity and a list of findings per account.
.AUTHOR
    Matej Klemencic (www.matej.guru)
.NOTES
    Version:        v26.11.15

    Installation: Install the Microsoft Graph authentication module (v2.0.0 or later). The script talks to
    Microsoft Graph directly through Invoke-MgGraphRequest, so no other Graph module is required:
    Install-Module -Name Microsoft.Graph.Authentication -MinimumVersion '2.0.0' -Scope CurrentUser -AllowClobber
.OUTPUTS
    None. Writes an HTML report to the file specified by -OutputPath.
.PARAMETER LicenseBaseline
    Required. The Microsoft Entra ID license level to assess against: Free, P1 or P2. The script does not detect the
    tenant's licenses; it checks, recommends and summarises only what that level offers.
    Free: roles, owned groups, accounts (source, guests, sync accounts, break-glass), licenses and notification email,
          and security defaults (access protection is judged by security defaults). Conditional Access, sign-in
          activity, authentication methods and PIM are not assessed.
    P1:   everything in Free, plus Conditional Access (Access protection), sign-in activity and inactivity, and
          authentication methods (Auth methods, including the MFA trust of guests from Microsoft Entra tenants).
          PIM (eligible and activated assignments, standing privilege) is not assessed.
    P2:   everything in P1, plus Privileged Identity Management (eligible and activated assignments, standing privilege).
.PARAMETER BreakGlassAccounts
    Optional. User principal names or object IDs of the emergency access (break-glass) accounts. These
    accounts are checked against the emergency access recommendations instead of the regular ones.
.PARAMETER TenantId
    Optional. The Entra ID tenant ID to connect to. Required when using Service Principal authentication.
.PARAMETER OutputPath
    Path to save the generated HTML report. Defaults to "EntraIDAdminReport_{TenantName}_{Date}.html".
.PARAMETER InactiveDays
    Number of days without a sign-in after which an administrator account is flagged as inactive.
    Default is 90.
.PARAMETER MaxSignInFrequencyHours
    Maximum sign-in frequency, in hours, that counts as acceptable for administrators in the Conditional Access
    review. A policy that makes the administrator sign in again less often than this is flagged. Microsoft
    publishes no single value; the default of 4 hours is this report's own, and a shorter limit suits unmanaged devices.
.PARAMETER DryRun
    Optional. When set, skips writing the HTML report to disk and skips launching the browser.
.PARAMETER NonInteractive
    Optional. Suppress all interactive prompts. Required for unattended/pipeline runs.
    Also suppresses automatic browser launch after report generation.
.PARAMETER UseManagedIdentity
    Optional. Use the Azure Managed Identity of the hosting environment. Uses the system-assigned identity
    by default; combine with -ClientId to select a user-assigned Managed Identity.
.PARAMETER ClientId
    Optional. The Application (client) ID of a Service Principal for unattended/pipeline authentication.
    Must be combined with -CertificateThumbprint and -TenantId. Alternatively, combine with
    -UseManagedIdentity to select a user-assigned Managed Identity by its client ID.
.PARAMETER CertificateThumbprint
    Optional. Certificate thumbprint for Service Principal authentication. Use with -ClientId and -TenantId.
.PARAMETER AccessToken
    Optional. A pre-acquired Microsoft Graph access token (SecureString).
    Obtain with: (Get-AzAccessToken -ResourceTypeName MSGraph -AsSecureString).Token
.EXAMPLE
    # Interactive: report for the default tenant, assessed against the Free baseline
    .\Get-EntraIDAdminReport.ps1 -LicenseBaseline Free
.EXAMPLE
    # P1 baseline with break-glass accounts: Conditional Access, sign-in activity and authentication methods are assessed
    .\Get-EntraIDAdminReport.ps1 -LicenseBaseline P1 -BreakGlassAccounts "bg1@contoso.onmicrosoft.com","bg2@contoso.onmicrosoft.com"
.EXAMPLE
    # Azure DevOps with azureSubscription service connection
    $token = (Get-AzAccessToken -ResourceTypeName MSGraph -AsSecureString).Token
    .\Get-EntraIDAdminReport.ps1 -LicenseBaseline P2 -AccessToken $token -NonInteractive -OutputPath "report.html"
    #>

[CmdletBinding(PositionalBinding = $false)]
param(
    # The Microsoft Entra ID license level to assess against. There is no default.
    [Parameter(Mandatory)]
    [ValidateSet('Free', 'P1', 'P2')]
    [string]$LicenseBaseline,
    # Advanced details (opt-in)
    [string[]]$BreakGlassAccounts = @(),
    [string]$TenantId = "",
    [string]$OutputPath = "",
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,
    [ValidateRange(1, 720)]
    [int]$MaxSignInFrequencyHours = 4,
    [switch]$DryRun,
    # Unattended / pipeline authentication
    [switch]$NonInteractive,
    [switch]$UseManagedIdentity,
    [string]$ClientId = "",
    [string]$CertificateThumbprint = "",
    # Pre-acquired token (e.g. from Get-AzAccessToken in AzurePowerShell@5 task)
    [System.Security.SecureString]$AccessToken
)

# Validate mutually exclusive / dependent parameters
if ($CertificateThumbprint -and -not $ClientId) {
    Write-Error "-CertificateThumbprint requires -ClientId (Service Principal authentication)."
    exit 1
}
if ($ClientId -and -not $CertificateThumbprint -and -not $UseManagedIdentity) {
    Write-Error "-ClientId requires either -CertificateThumbprint (Service Principal authentication) or -UseManagedIdentity (user-assigned Managed Identity)."
    exit 1
}
if ($ClientId -and $CertificateThumbprint -and -not $TenantId) {
    Write-Error "-TenantId is required when using Service Principal authentication (-ClientId/-CertificateThumbprint)."
    exit 1
}

# Make all unhandled errors terminating. The main body below is wrapped in try/finally with
# no catch, so an unhandled error still flows through the finally block (guaranteeing
# Disconnect-MgGraph runs) before it terminates the script.
$ErrorActionPreference = 'Stop'

# Unattended runs: rendering Write-Progress is pure overhead and noise in pipeline logs
if ($NonInteractive) { $ProgressPreference = 'SilentlyContinue' }

# Script version - keep in sync with the .NOTES header above; surfaced in the report footer
$ScriptVersion = 'v26.11.15'

# A pipeline variable arrives as one comma-separated string; accept both forms
$BreakGlassAccounts = @($BreakGlassAccounts | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# Microsoft Learn: fewer than 5 Global Administrators, fewer than 10 privileged role assignments
$GlobalAdminLimit = 5
$PrivilegedAssignmentLimit = 10
$GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
# Tier-0 roles: Global Administrator, Privileged Role Administrator and Privileged Authentication Administrator can change who has any access
$Tier0RoleIds = @($GlobalAdminRoleId, 'e8611ab8-c189-46e8-94e1-60213ab1f814', '7be44c8a-adaf-4e2a-84d6-ab2649e08f0f')
# Roles that must do MFA on every sign-in under security defaults (Microsoft Learn: Security defaults in Microsoft Entra ID)
$SecurityDefaultsRoleNames = @('Global Administrator', 'Application Administrator', 'Authentication Administrator', 'Billing Administrator', 'Cloud Application Administrator', 'Conditional Access Administrator', 'Exchange Administrator', 'Helpdesk Administrator', 'Password Administrator', 'Privileged Authentication Administrator', 'Privileged Role Administrator', 'Security Administrator', 'SharePoint Administrator', 'User Administrator', 'Authentication Policy Administrator', 'Identity Governance Administrator')

# Microsoft Entra Connect creates a connector account for the sync service and gives it the Directory Synchronization
# Accounts role. Learn: the role is "not intended or supported for any other use" and can't be granted outside the Connect
# wizard. The account has a default display name and, by default, a Sync_<server>_<id> user principal name.
# A tenant allows at most 20 sync service accounts (each Connect server, including staging servers, has its own).
# Roles that Entra ID Protection and PIM send notifications to (Global Administrator, Security Administrator, Security Reader, Privileged Role Administrator)
$NotificationRoleIds = @($GlobalAdminRoleId, '194ae4cb-b126-40b2-bd5b-6091b380977d', '5d6b6bb7-de71-4623-b4af-96380a352509', 'e8611ab8-c189-46e8-94e1-60213ab1f814')
$SyncRoleId = 'd29b2b05-8046-44ba-8758-1e26182fcf32'
$SyncRoleName = 'Directory Synchronization Accounts'
$SyncDefaultDisplayName = 'On-Premises Directory Synchronization Service Account'
$SyncAccountLimit = 20

# Roles Microsoft Learn labels PRIVILEGED. Only used when the role definitions returned by Graph
# don't carry the isPrivileged flag.
$PrivilegedRoleNamesFallback = @(
    'Application Administrator', 'Application Developer', 'Attribute Provisioning Administrator', 'Authentication Administrator',
    'Authentication Extensibility Administrator', 'B2C IEF Keyset Administrator', 'Cloud Application Administrator',
    'Cloud Device Administrator', 'Conditional Access Administrator', 'Directory Synchronization Accounts', 'Directory Writers',
    'Domain Name Administrator', 'External Identity Provider Administrator', 'Global Administrator', 'Global Reader',
    'Helpdesk Administrator', 'Hybrid Identity Administrator', 'Intune Administrator', 'Lifecycle Workflows Administrator',
    'Partner Tier1 Support', 'Partner Tier2 Support', 'Password Administrator', 'Privileged Authentication Administrator',
    'Privileged Role Administrator', 'Security Administrator', 'Security Operator', 'Security Reader', 'User Administrator'
)

# Built-in "Phishing-resistant MFA" authentication strength, and the method combinations that count as phishing-resistant
$PhishingResistantStrengthId = '00000000-0000-0000-0000-000000000004'
$PhishingResistantCombinations = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')

$userSelectBase = 'id,displayName,userPrincipalName,mail,otherMails,userType,createdDateTime,accountEnabled,onPremisesSyncEnabled,assignedLicenses,assignedPlans,identities'
# The baseline decides what is assessed (P1/P2: Conditional Access, sign-in activity, authentication methods; P2: PIM)
$script:caBaseline  = $LicenseBaseline -ne 'Free'
$script:pimBaseline = $LicenseBaseline -eq 'P2'
$script:signInDataAvailable  = $script:caBaseline
$script:eligibilityAvailable = $true
$script:pimGroupsAvailable   = $true
$script:authDataAvailable    = $script:caBaseline
$script:caDataAvailable      = $true   # access protection is assessed for every baseline (security defaults, and policies with P1/P2)
$script:securityDefaults     = $false
$script:securityDefaultsKnown = $false   # false when the policy could not be read
$script:sdEffective           = $false   # security defaults on and no enabled Conditional Access policy (the two cannot both be active)
$script:sdConflict            = $false
$script:enabledCaPolicyCount  = 0


# Function to safely import modules
function Import-GraphModuleSafely {
    param([string]$ModuleName)

    # Reuse an already-loaded module if it meets the minimum version requirement
    $loaded = Get-Module -Name $ModuleName
    if ($loaded) {
        if ($loaded.Version -ge [version]'2.0.0') {
            Write-Verbose "$ModuleName $($loaded.Version) already loaded - skipping re-import"
            return
        }
        Write-Warning "$ModuleName $($loaded.Version) is loaded but v2.0.0+ is required - re-importing"
    }

    try {
        Import-Module $ModuleName -MinimumVersion '2.0.0' -ErrorAction Stop
        Write-Host "Successfully imported $ModuleName" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not import $ModuleName v2+. Attempting Microsoft.Graph umbrella module..."
        try {
            $umbrella = Get-Module -Name 'Microsoft.Graph'
            if (-not $umbrella -or $umbrella.Version -lt [version]'2.0.0') {
                Import-Module Microsoft.Graph -MinimumVersion '2.0.0' -ErrorAction Stop
            }
        }
        catch {
            Write-Error "Failed to import required Graph modules (v2.0.0+).`nRun: Install-Module Microsoft.Graph.Authentication -MinimumVersion '2.0.0' -Scope CurrentUser -AllowClobber"
            exit 1
        }
    }
}

# Retry wrapper for Graph API calls that may be throttled (HTTP 429).
# Reads the Retry-After response header when available; falls back to exponential back-off.
function Invoke-MgWithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3
    )
    $attempt = 0
    while ($true) {
        try {
            return (& $ScriptBlock)
        }
        catch {
            $attempt++
            $statusCode = $null
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { Write-Verbose 'No HTTP status code on this error.' }
            if ($statusCode -eq 429 -and $attempt -le $MaxRetries) {
                $retryAfter = $null
                try { $retryAfter = [int]$_.Exception.Response.Headers['Retry-After'] } catch { Write-Verbose 'No Retry-After header on this error.' }
                $delay = if ($retryAfter -gt 0) { $retryAfter } else { [Math]::Pow(2, $attempt) * 2 }
                Write-Warning "Graph API throttled (429). Retrying in $delay s (attempt $attempt/$MaxRetries)..."
                Start-Sleep -Seconds $delay
            } else {
                throw
            }
        }
    }
}

# GET a Graph collection and follow @odata.nextLink until every page is read
function Get-GraphCollection {
    param([string]$Uri, [hashtable]$Headers = @{})
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgWithRetry { Invoke-MgGraphRequest -Method GET -Uri $next -Headers $Headers -ErrorAction Stop }
        foreach ($item in @($page.value)) { if ($null -ne $item) { $items.Add($item) } }
        $next = $page.'@odata.nextLink'
    }
    return $items
}

# Send GET requests through the Graph JSON batching endpoint, 20 per call. Individual requests
# that are throttled (429) or fail transiently (5xx) are retried in later rounds, honouring the
# largest Retry-After seen. Returns a hashtable: request id -> batch response (status, headers, body).
function Invoke-GraphBatch {
    param(
        [System.Collections.Generic.List[hashtable]]$Requests,
        [string]$Label,
        [int]$MaxRounds = 5
    )
    $results = @{}
    $requestsById = @{}
    foreach ($r in $Requests) { $requestsById[$r.id] = $r }

    $pending = @($Requests)
    $round = 0
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($pending.Count -gt 0) {
        $round++
        $retry = [System.Collections.Generic.List[hashtable]]::new()
        $wait = 0
        $batchCount = [Math]::Ceiling($pending.Count / 20)
        # Unconditional heartbeat (~20 lines per round) so long unattended runs stay visible in logs
        $heartbeatInterval = [Math]::Max(1, [Math]::Ceiling($batchCount / 20))
        $batchNumber = 0

        for ($i = 0; $i -lt $pending.Count; $i += 20) {
            $batchNumber++
            $chunk = @($pending[$i..([Math]::Min($i + 19, $pending.Count - 1))])
            # A request can carry its own headers (e.g. ConsistencyLevel: eventual, which Graph requires for OData casts and $count)
            $body = @{ requests = @($chunk | ForEach-Object {
                $entry = @{ id = $_.id; method = 'GET'; url = $_.url }
                if ($_.headers) { $entry.headers = $_.headers }
                $entry
            }) } | ConvertTo-Json -Depth 5 -Compress
            $response = Invoke-MgWithRetry { Invoke-MgGraphRequest -Method POST -Uri 'v1.0/$batch' -Body $body -ContentType 'application/json' -ErrorAction Stop }

            foreach ($resp in @($response.responses)) {
                $status = [int]$resp.status
                if (($status -eq 429 -or $status -ge 500) -and $round -lt $MaxRounds) {
                    $retry.Add($requestsById[[string]$resp.id])
                    $retryAfter = 0
                    try { $retryAfter = [int]$resp.headers['Retry-After'] } catch { Write-Verbose 'No Retry-After header in this response.' }
                    if ($retryAfter -gt $wait) { $wait = $retryAfter }
                    continue
                }
                $results[[string]$resp.id] = $resp
            }

            Write-Progress -Activity "Reading $Label" -Status "Batch $batchNumber of $batchCount" -PercentComplete (($batchNumber / $batchCount) * 100)
            if ($batchNumber % $heartbeatInterval -eq 0 -or $batchNumber -eq $batchCount) {
                Write-Host "  ...$Label batch $batchNumber/$batchCount ($([Math]::Round($stopwatch.Elapsed.TotalSeconds))s elapsed)" -ForegroundColor DarkGray
            }
        }
        Write-Progress -Activity "Reading $Label" -Completed

        if ($retry.Count -gt 0) {
            $delay = if ($wait -gt 0) { $wait } else { [Math]::Pow(2, $round) * 2 }
            Write-Warning "$($retry.Count) $Label request(s) throttled or failed transiently. Retrying in $delay s (round $round/$MaxRounds)..."
            Start-Sleep -Seconds $delay
        }
        $pending = @($retry)
    }
    return $results
}

# Read every item of a collection returned in a batch response, following @odata.nextLink.
# Ok is $false when the request failed (missing response or HTTP status >= 400).
function Get-BatchItems {
    param($Response, [hashtable]$Headers = @{})
    $items = [System.Collections.Generic.List[object]]::new()
    if (-not $Response -or [int]$Response.status -ge 400) {
        return @{ Ok = $false; Items = $items }
    }
    foreach ($item in @($Response.body.value)) { if ($null -ne $item) { $items.Add($item) } }
    $next = $Response.body.'@odata.nextLink'
    if ($next) {
        foreach ($item in @(Get-GraphCollection $next -Headers $Headers)) { $items.Add($item) }
    }
    return @{ Ok = $true; Items = $items }
}


# Escape special HTML characters to prevent injection / markup breakage
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

# Encode a string as a JavaScript string literal for the embedded reportDetails object.
# Faster than ConvertTo-Json per value (many administrators x several modals), and also
# escapes every < so a value can never close or confuse the surrounding <script> block.
function ConvertTo-JsString {
    param([string]$Text)
    if (-not $Text) { return '""' }
    $t = $Text.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t').Replace('<', '\u003c')
    $t = $t.Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
    $t = [regex]::Replace($t, '[\x00-\x1F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
    return '"' + $t + '"'
}

# Graph dates arrive as ISO-8601 strings or, depending on PowerShell / SDK version, as already
# parsed DateTime values. Normalize both to UTC.
function ConvertTo-UtcDateTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }
    $text = [string]$Value
    if (-not $text) { return $null }
    try {
        return [datetime]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
    }
    catch {
        Write-Verbose "Could not parse date value '$text'"
        return $null
    }
}

# Whole days elapsed since a UTC date ($null when the date is unknown)
function Get-DaysSince {
    param($Date, [datetime]$Now)
    if ($null -eq $Date) { return $null }
    return [int][Math]::Max(0, [Math]::Floor(($Now - $Date).TotalDays))
}

function Format-ReportDate {
    param($Date)
    if ($null -eq $Date) { return '' }
    return $Date.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-ReportDateTime {
    param($Date)
    if ($null -eq $Date) { return '' }
    return $Date.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

# Classify the scope of a role assignment (directoryScopeId): tenant-wide, an administrative unit, or a single directory object.
# Names are resolved later, once for the whole tenant.
function Get-RoleScopeInfo {
    param([string]$DirectoryScopeId)
    $id = if ($DirectoryScopeId) { $DirectoryScopeId } else { '/' }
    if ($id -eq '/') { return @{ Id = '/'; Kind = 'tenant'; Ref = '' } }
    if ($id -like '/administrativeUnits/*') { return @{ Id = $id; Kind = 'au'; Ref = $id.Substring('/administrativeUnits/'.Length) } }
    return @{ Id = $id; Kind = 'object'; Ref = $id.TrimStart('/') }
}

# Scope cell of the roles modal: tenant-wide is bold on privileged roles, a limited scope is muted and carries its type
function Get-RoleScopeHtml {
    param($Role)
    if ($Role.ScopeKind -eq 'tenant') {
        if ($Role.Privileged) { return '<strong>Tenant-wide</strong>' }
        return 'Tenant-wide'
    }
    return "<span class='role-scope-limited'>$(ConvertTo-HtmlSafe $Role.ScopeType): $(ConvertTo-HtmlSafe $Role.ScopeName)</span>"
}

# Build the Microsoft Learn deep link for an Entra built-in role.
# The reference page uses GitHub-style anchors: role name lowercased, non-alphanumerics
# dropped, and spaces collapsed to single hyphens (e.g. 'Global Administrator' -> '#global-administrator').
function Get-EntraRoleLearnUrl {
    param([string]$RoleName)
    $anchor = (($RoleName.ToLower() -replace '[^a-z0-9 -]', '') -replace '\s+', '-')
    return "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#$anchor"
}

# Friendly names for the service plans that make an account a daily-use account
$script:PlanFriendlyNames = @{
    EXCHANGE_S_ENTERPRISE = 'Exchange Online (Plan 2)'; EXCHANGE_S_STANDARD = 'Exchange Online (Plan 1)'; EXCHANGE_S_DESKLESS = 'Exchange Online Kiosk'
    EXCHANGE_S_ARCHIVE_ADDON = 'Exchange Online Archiving'; TEAMS1 = 'Microsoft Teams'; SHAREPOINTENTERPRISE = 'SharePoint Online (Plan 2)'
    SHAREPOINTSTANDARD = 'SharePoint Online (Plan 1)'; SHAREPOINTDESKLESS = 'SharePoint Kiosk'; OFFICESUBSCRIPTION = 'Microsoft 365 Apps'
    OFFICE_BUSINESS = 'Microsoft 365 Apps for business'
}
# Product names from Microsoft Learn "Product names and service plan identifiers for licensing"; other SKUs show the part number
$script:LicenseFriendlyNames = @{
    SPB = 'Microsoft 365 Business Premium'; O365_BUSINESS_PREMIUM = 'Microsoft 365 Business Standard'; O365_BUSINESS_ESSENTIALS = 'Microsoft 365 Business Basic'
    SPE_E3 = 'Microsoft 365 E3'; SPE_E5 = 'Microsoft 365 E5'; ENTERPRISEPACK = 'Office 365 E3'; ENTERPRISEPREMIUM = 'Office 365 E5'; STANDARDPACK = 'Office 365 E1'
    AAD_PREMIUM = 'Microsoft Entra ID P1'; AAD_PREMIUM_P2 = 'Microsoft Entra ID P2'; EMS = 'Enterprise Mobility + Security E3'; EMSPREMIUM = 'Enterprise Mobility + Security E5'
    MCOEV = 'Microsoft Teams Phone Standard'; POWER_BI_PRO = 'Power BI Pro'; FLOW_FREE = 'Microsoft Power Automate Free'
    DYN365_BUSCENTRAL_PREMIUM = 'Dynamics 365 Business Central Premium'; Microsoft_Teams_Enterprise_New = 'Microsoft Teams Enterprise'
}
function Get-LicenseFriendlyName {
    param([string]$PartNumber)
    if ($script:LicenseFriendlyNames.ContainsKey($PartNumber)) { $script:LicenseFriendlyNames[$PartNumber] } else { $PartNumber }
}
# Notification roles held tenant-wide and directly (not through a group), active or eligible
function Get-DirectNotificationRoles {
    param($Admin)
    @($Admin.Roles | Where-Object { $_.Kind -eq 'Entra' -and $_.RoleId -in $NotificationRoleIds -and $_.Type -in @('Active', 'Eligible') -and $_.ScopeKind -eq 'tenant' -and -not $_.ViaGroupId })
}
# Does the account hold one of the roles that security defaults require MFA on every sign-in for?
function Test-SecurityDefaultsRole {
    param($Admin)
    @($Admin.Roles | Where-Object { $_.Kind -eq 'Entra' -and $_.Type -in @('Active', 'Eligible') -and $_.Role -in $SecurityDefaultsRoleNames }).Count -gt 0
}
# Access protection verdict: phishing-resistant MFA plus at least one extra control (trusted device or trusted location)
function Get-AccessVerdictKey {
    param($Admin)
    if (-not $Admin.CaCollected) { return 'nc' }
    if ($Admin.SyncAccount -eq 'connector') { return 'na' }
    # Security defaults cover every other account, break-glass accounts included
    if ($script:sdEffective) { return 'sd' }
    # A break-glass account should be excluded from the policies: an enabled policy that applies is a red verdict
    if ($Admin.IsBreakGlass) { return $(if ($Admin.CaKey -in @('excluded', 'na', 'nc')) { 'na' } else { 'policy' }) }
    if ($Admin.CaKey -in @('excluded', 'na')) { return 'na' }
    $trustedLocation = $Admin.LocKey -in @('gsa', 'ip')
    if ($Admin.CaKey -eq 'pr') {
        if ($Admin.DeviceKey -eq 'device' -and $trustedLocation) { return 'strong' }
        if ($Admin.DeviceKey -eq 'device' -or $trustedLocation) { return 'good' }
        return 'mfaonly'
    }
    if ($Admin.CaKey -in @('mfa', 'partial', 'activation')) { return 'weak' }
    if ($Admin.CaKey -eq 'none') { return 'none' }
    return 'nc'
}

# What an evaluated policy counts for: mfa (phishing-resistant, all resources), device, location. Same rules as the aggregation.
function Get-PolicyCounts {
    param($Policy)
    $counts = @()
    if ($Policy.State -ne 'enabled' -or $Policy.Result -ne 'yes') { return $counts }
    if ($Policy.Requirement -eq 'pr' -and $Policy.Full) { $counts += 'mfa' }
    if ($Policy.AllResources -and $Policy.DeviceMode -eq 'required' -and $Policy.Narrowed.Count -eq 0) { $counts += 'device' }
    if ($Policy.AllResources -and $Policy.LocationKind -in @('gsa', 'ip') -and $Policy.NarrowedOther.Count -eq 0) { $counts += 'location' }
    return $counts
}

# Why a policy that does not count is not counted, as a short phrase ("covers Microsoft Admin Portals only")
function Get-PolicyNotCountedPhrase {
    param($Policy)
    if ($Policy.State -ne 'enabled') { return 'is report-only' }
    if ($Policy.Result -eq 'activation') { return 'applies only after role activation' }
    if ($Policy.ScopeLabel -eq 'All resources, with exclusions') { return 'covers all resources with exclusions' }
    if (-not $Policy.AllResources) { return $(if ($Policy.ScopeDetail) { "covers $($Policy.ScopeDetail)" } else { "covers $($Policy.ScopeLabel.ToLower()) only" }) }
    $narrow = if ($Policy.LocationKind -ne 'none') { @($Policy.NarrowedOther) } else { @($Policy.Narrowed) }
    if ($narrow.Count -gt 0) { return "applies only to some sign-ins ($($narrow -join ', '))" }
    return $null
}

# The "Counts as" text of a policy that does not count
function Get-PolicyNotCountedText {
    param($Policy)
    if ($Policy.State -ne 'enabled') { return 'No - report-only' }
    if ($Policy.Result -eq 'activation') { return 'No - applies after role activation' }
    if ($Policy.Requirement -notin @('pr', 'mfa') -and $Policy.DeviceMode -eq 'none' -and $Policy.LocationKind -eq 'none') { return 'No - no MFA, device or location requirement' }
    if ($Policy.ScopeLabel -eq 'All resources, with exclusions') { return 'No - all resources with exclusions' }
    if (-not $Policy.AllResources) { return 'No - only some resources' }
    $narrow = if ($Policy.LocationKind -ne 'none') { @($Policy.NarrowedOther) } else { @($Policy.Narrowed) }
    if ($narrow.Count -gt 0) { return 'No - only some sign-ins' }
    if ($Policy.Requirement -eq 'mfa') { return 'No - not phishing-resistant' }
    if ($Policy.DeviceMode -eq 'optional') { return 'No - MFA is an alternative to the device' }
    if ($Policy.LocationKind -in @('country', 'other')) { return 'No - not a trusted IP range or GSA network' }
    return 'No - does not meet a requirement'
}

# Detail line for a requirement that is not met: names the best policy that exists but is not counted
function New-NotCountedDetail {
    param($Candidates, [string]$Lead, [string]$Fallback)
    $first = @($Candidates | Sort-Object @{ Expression = { $_.State -ne 'enabled' } }, Name | Select-Object -First 1)
    if ($first.Count -eq 0) { return (ConvertTo-HtmlSafe $Fallback) }
    $phrase = Get-PolicyNotCountedPhrase $first[0]
    if (-not $phrase) { return (ConvertTo-HtmlSafe $Fallback) }
    return "$(ConvertTo-HtmlSafe $Lead) $(ConvertTo-HtmlSafe $first[0].Name) $(ConvertTo-HtmlSafe $phrase) and is not counted."
}

# The three requirements behind the verdict: state (met / weaker / missing) and a detail line (HTML)
function Get-AccessRequirements {
    param($Admin)
    $policies = @($Admin.CaPolicies | Where-Object { $_.Result -ne 'excluded' })
    $countingFor = { param($kind) @($policies | Where-Object { @(Get-PolicyCounts $_) -contains $kind } | Sort-Object Name) }
    $withMore = { param($list) $list = @($list); "$(ConvertTo-HtmlSafe $list[0].Name)$(if ($list.Count -gt 1) { " <span class='muted'>(+$($list.Count - 1) more)</span>" })" }
    $none = 'No policy requires it for all resources.'

    # MFA
    $mfaPolicies = @($policies | Where-Object { $_.Requirement -in @('pr', 'mfa') })
    switch ($Admin.CaKey) {
        'pr' { $mfa = @{ State = 'met'; Detail = (& $withMore (& $countingFor 'mfa')) } }
        'mfa' {
            $full = @($policies | Where-Object { $_.State -eq 'enabled' -and $_.Result -eq 'yes' -and $_.Full -and $_.Requirement -eq 'mfa' } | Sort-Object Name | Select-Object -First 1)
            $mfa = @{ State = 'weaker'; Detail = $(if ($full.Count -gt 0) { "$(ConvertTo-HtmlSafe $full[0].Name) requires MFA for all resources, which is not phishing-resistant." } else { 'Security defaults require MFA, which is not phishing-resistant.' }) }
        }
        'partial' { $mfa = @{ State = 'weaker'; Detail = (New-NotCountedDetail @($mfaPolicies | Where-Object { $_.State -eq 'enabled' -and $_.Result -eq 'yes' -and -not $_.Full }) $none 'No policy requires it for all resources.') } }
        'activation' { $mfa = @{ State = 'weaker'; Detail = (New-NotCountedDetail @($mfaPolicies | Where-Object { $_.State -eq 'enabled' -and $_.Result -eq 'activation' }) 'MFA is not required at sign-in.' 'MFA is only required after role activation.') } }
        default { $mfa = @{ State = 'missing'; Detail = (New-NotCountedDetail $mfaPolicies 'No enabled policy requires MFA.' 'No enabled policy requires MFA') } }
    }

    # Device
    $devicePolicies = @($policies | Where-Object { $_.DeviceMode -ne 'none' })
    $device = switch ($Admin.DeviceKey) {
        'device' { @{ State = 'met'; Detail = (& $withMore (& $countingFor 'device')) } }
        'optional' {
            $opt = @($devicePolicies | Where-Object { $_.DeviceMode -eq 'optional' } | Sort-Object Name | Select-Object -First 1)
            @{ State = 'weaker'; Detail = "$(ConvertTo-HtmlSafe $opt[0].Name) accepts a compliant or hybrid joined device, but MFA is an alternative, so it is not guaranteed." }
        }
        default { @{ State = 'missing'; Detail = (New-NotCountedDetail $devicePolicies $none 'No policy requires it for all resources') } }
    }

    # Location
    $locationPolicies = @($policies | Where-Object { $_.LocationKind -ne 'none' })
    $location = switch ($Admin.LocKey) {
        { $_ -in @('gsa', 'ip') } { @{ State = 'met'; Detail = (& $withMore (& $countingFor 'location')) } }
        { $_ -in @('country', 'other') } { @{ State = 'weaker'; Detail = "Access is limited to $(ConvertTo-HtmlSafe $Admin.LocLabel) only, which is weaker than a trusted IP range or the GSA network." } }
        default { @{ State = 'missing'; Detail = (New-NotCountedDetail $locationPolicies $none 'No policy limits access to a trusted IP range or the GSA network') } }
    }
    return @(
        @{ Label = 'Phishing-resistant MFA'; Sub = ''; State = $mfa.State; Detail = $mfa.Detail }
        @{ Label = 'Compliant or hybrid joined device'; Sub = ''; State = $device.State; Detail = $device.Detail }
        @{ Label = 'Trusted location'; Sub = ' (trusted IP range or Global Secure Access)'; State = $location.State; Detail = $location.Detail }
    )
}

# Sign-in frequency as text ("8 hours")
function Format-FrequencyText {
    param($Hours)
    if ($null -eq $Hours) { return '' }
    if ($Hours -eq 0) { return 'every time' }
    if ($Hours -ge 24 -and ($Hours % 24) -eq 0) { $days = [int]($Hours / 24); return "$days day$(if ($days -ne 1) { 's' })" }
    $h = [Math]::Round([double]$Hours, 1)
    return "$h hour$(if ($h -ne 1) { 's' })"
}

# Body of the auth methods modal
function New-AuthModalHtml {
    param($Admin)
    $key = $Admin.AuthKey
    $chip = { param($class, $text) "<span class='auth-chip $class'>$(ConvertTo-HtmlSafe $text)</span>" }
    $row = { param($label, $valueHtml) "<div class='auth-kv'><span class='auth-k'>$label</span><span>$valueHtml</span></div>" }
    $weakFallback = $Admin.WeakFallback.Count -gt 0
    $recommendation = $null; $rows = ''; $groupsHtml = ''; $linkHtml = ''
    $learnLink = "<div class='modal-note'><a href='https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration#to-change-inbound-trust-settings-for-mfa-and-device-claims' target='_blank' rel='noopener noreferrer'>Where to configure: Cross-tenant access settings</a></div>"

    # Registered methods per tier; for a trusted guest they sit under a small label
    $groupDefs = @(
        @{ Key = 'pr'; Name = 'Phishing-resistant'; Dot = 'green' }
        @{ Key = 'pwl'; Name = 'Passwordless'; Dot = 'blue' }
        @{ Key = 'mfa'; Name = 'Multifactor'; Dot = 'amber' }
    )
    foreach ($group in $groupDefs) {
        $items = @($Admin.MethodGroups[$group.Key])
        if ($items.Count -eq 0) { continue }
        $itemClass = switch ($group.Key) { 'pr' { 'green' } 'pwl' { 'blue' } default { 'gray' } }
        $chips = ($items | ForEach-Object { & $chip $(if ($_.Weak) { 'amber' } else { $itemClass }) $_.Label }) -join ''
        $groupsHtml += "<div class='auth-group'><span class='auth-dot $($group.Dot)'></span><span class='auth-gname'>$($group.Name)</span><span class='auth-chips'>$chips</span></div>"
    }

    $trustVariant = $Admin.GuestKind -eq 'entra' -and ($key -eq 'trusted' -or ($key -eq 'sf' -and $Admin.GuestTrust -eq 'rejected') -or ($key -eq 'unknown' -and $Admin.GuestTrust -eq 'unknown'))
    if ($trustVariant) {
        # Entra guest: MFA from the home tenant
        $domain = if ($Admin.GuestDomain -and $Admin.GuestTrust -in @('accepted', 'rejected')) { ConvertTo-HtmlSafe $Admin.GuestDomain } else { 'Not resolved' }
        switch ($key) {
            'trusted' {
                $bannerClass = 'blue'; $bannerText = 'Guest account - MFA from the home tenant is trusted'
                $rows = (& $row 'Home tenant' $domain) + (& $row 'Setting' (ConvertTo-HtmlSafe $Admin.GuestTrustSource)) + (& $row 'MFA trust' (& $chip 'green' 'Accepted'))
                if ($groupsHtml) { $groupsHtml = "<div class='auth-label'>Registered in this tenant</div>$groupsHtml" }
            }
            'sf' {
                $bannerClass = 'red'; $bannerText = 'No MFA registered - home tenant MFA is not trusted'
                $rows = (& $row 'Home tenant' $domain) + (& $row 'Setting' (ConvertTo-HtmlSafe $Admin.GuestTrustSource)) + (& $row 'MFA trust' (& $chip 'red' 'Not accepted'))
                $recommendation = 'Trust MFA from this organization in cross-tenant access settings, or require the guest to register MFA here.'
            }
            default {
                $bannerClass = 'gray'; $bannerText = 'Guest account - MFA trust could not be read'
                $rows = (& $row 'Home tenant' 'Not resolved') + (& $row 'MFA trust' (& $chip 'gray' 'Unknown'))
            }
        }
        if ($key -ne 'trusted') { $groupsHtml = '' }
        $linkHtml = $learnLink
    }
    else {
        switch ($key) {
            'pr'      { if ($weakFallback) { $bannerClass = 'amber'; $bannerText = 'Phishing-resistant method registered, weaker methods remain' } else { $bannerClass = 'green'; $bannerText = 'Phishing-resistant method registered' } }
            'pwl'     { $bannerClass = 'blue'; $bannerText = 'Passwordless method registered - not phishing-resistant' }
            'mfa'     { $bannerClass = 'amber'; $bannerText = 'Multifactor only - no phishing-resistant method' }
            'sf'      { $bannerClass = 'red'; $bannerText = 'No multifactor method registered' }
            default   { $bannerClass = 'gray'; $bannerText = 'Not in the registration report, for example because the account is disabled.' }
        }
        if ($Admin.GuestKind -eq 'other') {
            $rows = (& $row 'Sign-in identity' (ConvertTo-HtmlSafe $Admin.GuestProviderLong)) + (& $row 'MFA is done in' 'This tenant')
        }
        if ($weakFallback -and $key -in @('pr', 'pwl', 'mfa')) { $recommendation = 'Remove SMS and voice, and require phishing-resistant MFA in Conditional Access.' }
        elseif ($key -eq 'sf' -and $Admin.GuestKind -eq 'other') { $recommendation = 'Require the guest to register MFA in this tenant.' }
        elseif ($key -in @('mfa', 'pwl', 'sf')) { $recommendation = 'Register a passkey (FIDO2) for this account.' }
    }
    $html = "<div class='modal-banner $bannerClass'><span class='modal-dot'></span><span>$bannerText</span></div>$rows$groupsHtml"
    if ($recommendation) { $html += "<div class='modal-rec'><strong>Recommended:</strong> $(ConvertTo-HtmlSafe $recommendation)</div>" }
    return $html + $linkHtml
}
# One requirement row of the access protection modal
function New-AccessRequirementRow {
    param([string]$Label, [string]$Sub, [string]$PillClass, [string]$PillText, [string]$Detail)
    "<div class='req-row'><span class='req-pill $PillClass'>$PillText</span><div><div class='req-label'>$Label<span class='muted' style='font-weight:400'>$Sub</span></div><div class='req-detail'>$Detail</div></div></div>"
}

# Modal for an account covered by security defaults (no Conditional Access policy applies)
function New-SecurityDefaultsModalHtml {
    param($Admin)
    $caNo = -not $script:caBaseline
    $holder = Test-SecurityDefaultsRole $Admin
    $banner = if ($holder) { 'Security defaults - MFA required on every sign-in' } else { 'Security defaults - MFA only when Microsoft Entra decides it is needed' }
    $html = "<div class='modal-banner blue'><span class='modal-dot'></span><span>$banner</span></div>"
    if ($holder) { $html += New-AccessRequirementRow 'MFA on every sign-in' '' 'met' 'Met' 'Required for this administrator role by security defaults. Not phishing-resistant.' }
    else { $html += New-AccessRequirementRow 'MFA on every sign-in' '' 'weaker' 'Weaker' 'Security defaults require it for 16 administrator roles. This account does not hold one of them.' }

    if ($Admin.IsBreakGlass) { $html += "<div class='modal-note'>Security defaults require this account to complete MFA, so it can be locked out if MFA is unavailable.</div>" }
    $html += "<div class='modal-note'>$(if ($caNo) { 'Conditional Access is not part of the Free baseline.' } else { 'No Conditional Access policy is in use.' })</div>"
    return $html
}
# Modal for an account without MFA enforcement in a tenant where Conditional Access is not available
function New-NoMfaNoCaModalHtml {
    $html = "<div class='modal-banner red'><span class='modal-dot'></span><span>No MFA is enforced for this account</span></div>"
    $html += New-AccessRequirementRow 'MFA on every sign-in' '' 'missing' 'Missing' 'Security defaults are disabled and no Conditional Access policy applies'
    $html += New-AccessRequirementRow 'Compliant or hybrid joined device' '' 'na' 'Not available' 'Requires Conditional Access'
    $html += New-AccessRequirementRow 'Trusted location' ' (trusted IP range or Global Secure Access)' 'na' 'Not available' 'Requires Conditional Access'
    $html += "<div class='modal-rec'><strong>Recommended:</strong> Enable security defaults. It requires MFA for administrators and blocks legacy authentication.</div>"
    return $html
}

# Body of the access protection modal
function New-AccessModalHtml {
    param($Admin, [string]$Verdict)
    if ($Verdict -eq 'sd') { return (New-SecurityDefaultsModalHtml $Admin) }
    if ($Verdict -eq 'none' -and -not $script:caBaseline -and $script:securityDefaultsKnown) { return (New-NoMfaNoCaModalHtml) }
    $bannerClass = switch ($Verdict) { 'strong' { 'green' } 'good' { 'green' } 'mfaonly' { 'amber' } 'weak' { 'amber' } 'none' { 'red' } 'policy' { 'red' } default { 'gray' } }
    $bannerText = switch ($Verdict) {
        'strong'  { 'Strong - phishing-resistant MFA, compliant device and trusted location' }
        'good'    { "Good - phishing-resistant MFA plus $(if ($Admin.DeviceKey -eq 'device') { 'compliant device' } else { 'trusted location' })" }
        'mfaonly' { 'Phishing-resistant MFA only - no device or location requirement' }
        'weak'    { 'MFA is not phishing-resistant or covers only some resources' }
        'none'    { 'No Conditional Access policy requires MFA for this account' }
        'policy'  { 'Break-glass account - an enabled Conditional Access policy applies' }
        default   { 'Break-glass account - does not apply' }
    }
    $html = ''
    if ($script:securityDefaults) { $html += "<div class='info-banner'>Security defaults are enabled in this tenant and require MFA for administrators.</div>" }
    $html += "<div class='modal-banner $bannerClass'><span class='modal-dot'></span><span>$bannerText</span></div>"

    if ($Verdict -eq 'policy') { $html += "<div class='modal-rec'><strong>Recommended:</strong> Exclude this account from every policy that blocks or restricts sign-in.</div>" }
    if ($Verdict -notin @('na', 'policy')) {
        $stateText = @{ met = 'Met'; weaker = 'Weaker'; missing = 'Missing' }
        foreach ($req in (Get-AccessRequirements $Admin)) {
            $html += "<div class='req-row'><span class='req-pill $($req.State)'>$($stateText[$req.State])</span><div><div class='req-label'>$($req.Label)<span class='muted' style='font-weight:400'>$($req.Sub)</span></div><div class='req-detail'>$($req.Detail)</div></div></div>"
        }
        # Recommendation
        $recommendation = switch ($Verdict) {
            'mfaonly' { 'Add a Conditional Access policy that requires a compliant or hybrid joined device, or limits sign-in to a trusted IP range or Global Secure Access, for administrators.' }
            'none'    { 'Create a Conditional Access policy that requires phishing-resistant MFA for administrators, then add a compliant or hybrid joined device or a trusted location requirement.' + $(if ($script:enabledCaPolicyCount -eq 0 -and $script:securityDefaultsKnown) { ' If no Conditional Access policies are in use, security defaults can serve as a temporary baseline.' } else { '' }) }
            'weak'    { switch ($Admin.CaKey) {
                            'mfa'     { 'Require a phishing-resistant authentication strength (passkey (FIDO2) or Windows Hello for Business) for administrators, then add a device or location requirement.' }
                            'partial' { 'Make the MFA policy cover all resources instead of selected resources or conditions, and require phishing-resistant MFA.' }
                            default   { 'MFA is only enforced when the role is activated. Require phishing-resistant MFA at sign-in for administrators.' } } }
            default   { $null }
        }
        if ($recommendation) { $html += "<div class='modal-rec'><strong>Recommended:</strong> $(ConvertTo-HtmlSafe $recommendation)</div>" }
        if ($Verdict -eq 'weak' -and $Admin.CaKey -eq 'mfa') { $html += "<div class='modal-note'><a href='https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' target='_blank' rel='noopener noreferrer'>Learn more: Conditional Access authentication strengths</a></div>" }

        # Sign-in frequency: the only place it is shown
        $freqClass = switch ($bannerClass) { 'red' { 'ap-red' } 'amber' { 'ap-amber' } default { '' } }
        $freqText = switch ($Admin.SifKey) {
            'ok'    { Format-FrequencyText $Admin.SifHours }
            'long'  { "$(Format-FrequencyText $Admin.SifHours) <span class='ap-amber'>(above the $MaxSignInFrequencyHours-hour limit)</span>" }
            default { "<span class='$freqClass'>Not set</span>" }
        }
        $html += "<div class='ap-freq'>Sign-in frequency $freqText</div>"
    }

    # Policies that target the account
    $policies = @($Admin.CaPolicies | Where-Object { $_.Result -ne 'excluded' })
    $countLabel = @{ mfa = 'phishing-resistant MFA'; device = 'compliant or hybrid joined device'; location = 'trusted location' }
    if ($policies.Count -gt 0) {
        $rows = ($policies | Sort-Object @{ Expression = { @(Get-PolicyCounts $_).Count -eq 0 } }, Name | ForEach-Object {
            $counts = @(Get-PolicyCounts $_)
            $narrowing = if ($_.LocationKind -ne 'none') { $_.NarrowedOther } else { $_.Narrowed }
            $scope = $_.ScopeLabel + $(if ($_.ScopeDetail) { " - $($_.ScopeDetail)" } else { '' }) + $(if (@($narrowing).Count -gt 0) { " (only: $(@($narrowing) -join ', '))" } else { '' })
            $adds = @()
            if ($_.DeviceMode -ne 'none') { $adds += "Device: $($_.DeviceLabel)$(if ($_.DeviceMode -eq 'optional') { ' (optional)' })" }
            if ($_.LocationKind -ne 'none') { $adds += "Location: only $($_.LocationLabels -join ', ')" }
            if ($null -ne $_.SifHours) { $adds += "Sign-in frequency: $(Format-Hours $_.SifHours)" }
            $requires = ConvertTo-HtmlSafe ((@($_.RequirementLabel) + $adds) -join '; ')
            $countsHtml = if ($counts.Count -gt 0) { "<span class='ap-yes'>Yes - $(ConvertTo-HtmlSafe (($counts | ForEach-Object { $countLabel[$_] }) -join ', '))</span>" } else { ConvertTo-HtmlSafe (Get-PolicyNotCountedText $_) }
            New-ModalRowHtml @((ConvertTo-HtmlSafe $_.Name), $requires, (ConvertTo-HtmlSafe $scope), $countsHtml)
        }) -join ''
        $noneCounted = @($policies | Where-Object { @(Get-PolicyCounts $_).Count -gt 0 }).Count -eq 0
        $summary = "Policies that apply ($($policies.Count)$(if ($noneCounted) { ', none counted' }))"
        $html += "<details class='ap-details'><summary>$summary</summary>$(New-ModalTableHtml 'mtCa' @('Policy', 'Requires', 'Scope', 'Counts as') $rows)</details>"
    }
    return $html
}

function Get-PlanFriendlyName {
    param([string]$Name)
    if ($script:PlanFriendlyNames.ContainsKey($Name)) { $script:PlanFriendlyNames[$Name] } else { $Name }
}
# mailbox = Exchange Online (not the foundation plan every license carries), productivity = Teams, SharePoint, Microsoft 365 Apps
function Get-PlanCategory {
    param([string]$Name)
    if ($Name -like 'EXCHANGE_S_*' -and $Name -ne 'EXCHANGE_S_FOUNDATION') { return 'mailbox' }
    if ($Name -match '^(TEAMS1|TEAMS_|SHAREPOINT(STANDARD|ENTERPRISE|DESKLESS)|OFFICESUBSCRIPTION|OFFICE_BUSINESS)') { return 'productivity' }
    return 'other'
}
# Notification email findings and licenses for one administrator (shared by the break-glass and the normal checks)
function Get-NotificationFindings {
    param($Admin)
    $out = [System.Collections.Generic.List[object]]::new()
    $notifyRoles = @($Admin.Roles | Where-Object { $_.Kind -eq 'Entra' -and $_.RoleId -in $NotificationRoleIds -and $_.Type -in @('Active', 'Eligible') -and $_.ScopeKind -eq 'tenant' })
    $directNotify = @($notifyRoles | Where-Object { -not $_.ViaGroupId })
    if (-not $Admin.Mail -and $Admin.OtherMails.Count -eq 0) {
        if ($directNotify.Count -gt 0) {
            $names = (@($directNotify | ForEach-Object { $_.Role }) | Sort-Object -Unique) -join ', '
            $out.Add((New-Reason 'medium' 'No Email or Alternate email set, so role alerts reach nobody. Set the Email attribute to a plus address.' -Detail "Holds $names. Use a plus address of the owner's personal mailbox."))
        } else {
            $out.Add((New-Reason 'low' 'No Email or Alternate email set, so alerts reach nobody. Set the Email attribute to a plus address.' -Detail "Use a plus address of the owner's personal mailbox."))
        }
    }
    $groupNotify = @($notifyRoles | Where-Object { $_.ViaGroupId } | ForEach-Object { $_.Role } | Sort-Object -Unique)
    if ($groupNotify.Count -gt 0) {
        $out.Add((New-Reason 'info' 'Notification role assigned through a group. Entra ID Protection sends no notifications for it.' -Detail "Roles: $($groupNotify -join ', ')."))
    }
    return $out
}

function New-Reason {
    param([string]$Level, [string]$Text, [string]$Detail = '', [string]$Filter = '')
    $filterGroup, $filterValue = if ($Filter) { $Filter -split ':', 2 } else { '', '' }
    [PSCustomObject]@{ Level = $Level; Text = $Text; Detail = $Detail; FilterGroup = $filterGroup; FilterValue = $filterValue }
}

function New-ModalTableHtml {
    param([string]$TableId, [string[]]$Headers, [string]$RowsHtml)
    $headerCells = for ($i = 0; $i -lt $Headers.Count; $i++) {
        "<th onclick=`"sortTable('$TableId',$i,'string')`" style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>$($Headers[$i])</th>"
    }
    "<table id='$TableId' style='width:100%;border-collapse:collapse;font-size:13px'><thead><tr>$($headerCells -join '')</tr></thead><tbody>$RowsHtml</tbody></table>"
}

function New-ModalRowHtml {
    param([string[]]$Cells)
    '<tr>' + (($Cells | ForEach-Object { "<td style='padding:4px 8px;border-bottom:1px solid var(--border-row)'>$_</td>" }) -join '') + '</tr>'
}

# One group of the roles modal: a header row with a count, then its rows, or a placeholder row when the group is empty
function New-RoleGroupHtml {
    param([string]$Label, [string[]]$RowsHtml, [bool]$Neutral, [string]$EmptyText)
    $count = @($RowsHtml).Count
    $class = if ($Neutral) { 'role-group neutral' } else { 'role-group' }
    $html = "<tr class='$class'><td colspan='5'><span class='role-group-label'><span class='dot'></span>$Label<span class='count'>$count</span></span></td></tr>"
    if ($count -eq 0) { $html += "<tr class='role-empty'><td colspan='5'>$EmptyText</td></tr>" }
    else { $html += ($RowsHtml -join '') }
    return $html
}

# Summary line under the title of the roles modal
function Get-RoleSummaryHtml {
    param([int]$Total, [int]$Privileged, [int]$PermanentPrivileged, [int]$TenantWide = 0, [int]$Scoped = 0)
    $summary = if ($Total -eq 0) { 'No roles assigned' }
               elseif ($Privileged -eq 0) { "<strong class='role-ok'>No privileged roles</strong> &middot; $Total role$(if ($Total -ne 1) { 's' }) assigned" }
               else {
                   $lead = if ($Privileged -eq $Total) { "All $Total role$(if ($Total -ne 1) { 's are' } else { ' is' }) privileged" } else { "$Privileged of $Total roles are privileged" }
                   # Only when a privileged role is limited to an administrative unit or object: the tenant-wide / scoped split
                   if ($Scoped -gt 0) { $lead += " &middot; $TenantWide tenant-wide &middot; $Scoped scoped" }
                   if ($PermanentPrivileged -gt 0) {
                       $title = if ($Scoped -gt 0) { " title='Permanently active tenant-wide privileged roles. Scoped roles are not counted.'" } else { '' }
                       $lead += " &middot; <strong class='role-risk'$title>$PermanentPrivileged permanently active</strong>"
                   }
                   $lead
               }
    "<p class='role-summary'>$summary</p>"
}

function Get-ModalOnClick {
    param([string]$Key, [string]$Name)
    "openDetailModal(reportDetails['$Key'].${Name}Title,reportDetails['$Key'].${Name}Html,reportDetails['$Key'].who)"
}

# POST directoryObjects/getByIds (1000 IDs per call). Returns a hashtable: object ID -> directory object.
function Get-DirectoryObjectsById {
    param([string[]]$Ids, [string[]]$Types = @('user', 'group', 'servicePrincipal'))
    $result = @{}
    for ($i = 0; $i -lt $Ids.Count; $i += 1000) {
        $chunk = @($Ids[$i..([Math]::Min($i + 999, $Ids.Count - 1))])
        $body = @{ ids = $chunk; types = @($Types) } | ConvertTo-Json -Compress
        $response = Invoke-MgWithRetry { Invoke-MgGraphRequest -Method POST -Uri 'v1.0/directoryObjects/getByIds' -Body $body -ContentType 'application/json' -ErrorAction Stop }
        foreach ($object in @($response.value)) { if ($object) { $result[[string]$object.id] = $object } }
    }
    return $result
}

# Registered method name -> tier and friendly label (names are the values of methodsRegistered in the registration report)
function Get-MethodInfo {
    param([string]$Name)
    switch -Regex ($Name) {
        '^windowsHelloForBusiness$'          { return @{ Group = 'pr'; Label = 'Windows Hello for Business' } }
        '^passKeyDeviceBoundAuthenticator$'  { return @{ Group = 'pr'; Label = 'Passkey (Microsoft Authenticator)' } }
        '^passKeyDeviceBound$'               { return @{ Group = 'pr'; Label = 'Passkey (device-bound)' } }
        '^passKeySynced'                     { return @{ Group = 'pr'; Label = 'Passkey (synced)' } }
        '^passKey'                           { return @{ Group = 'pr'; Label = 'Passkey' } }
        '^fido2'                             { return @{ Group = 'pr'; Label = 'Security key (FIDO2)' } }
        '^macOsSecureEnclaveKey$'            { return @{ Group = 'pr'; Label = 'Platform credential (macOS)' } }
        'certificate|x509'                   { return @{ Group = 'pr'; Label = 'Certificate-based authentication' } }
        '^microsoftAuthenticatorPasswordless$' { return @{ Group = 'pwl'; Label = 'Microsoft Authenticator (phone sign-in)' } }
        '^microsoftAuthenticatorPush$'       { return @{ Group = 'mfa'; Label = 'Microsoft Authenticator (push)' } }
        '^softwareOneTimePasscode$'          { return @{ Group = 'mfa'; Label = 'Software OATH token' } }
        '^hardwareOneTimePasscode$'          { return @{ Group = 'mfa'; Label = 'Hardware OATH token' } }
        '^temporaryAccessPass$'              { return @{ Group = 'mfa'; Label = 'Temporary Access Pass' } }
        '^(mobilePhone|alternateMobilePhone|sms)$' { return @{ Group = 'mfa'; Label = 'SMS'; Weak = $true } }
        '^officePhone$'                      { return @{ Group = 'mfa'; Label = 'Voice call'; Weak = $true } }
        '^externalAuthMethod$'               { return @{ Group = 'mfa'; Label = 'External authentication method' } }
    }
    return $null
}

# The registered methods per tier, as label lists: @{ pr = @(...); pwl = @(...); mfa = @(@{ Label; Weak }) }
function Get-MethodGroups {
    param([string[]]$Methods)
    $groups = @{ pr = @(); pwl = @(); mfa = @() }
    foreach ($name in $Methods) {
        $info = Get-MethodInfo $name
        if (-not $info) { continue }
        if (@($groups[$info.Group] | Where-Object { $_.Label -eq $info.Label }).Count -eq 0) { $groups[$info.Group] += [PSCustomObject]@{ Label = $info.Label; Weak = [bool]$info.Weak } }
    }
    return $groups
}

# SMS and voice are weak fallbacks; they only matter when the strongest registered method is a stronger one
function Get-WeakFallbackLabels {
    param([string[]]$Methods, [string]$StrongestLabel)
    if ($StrongestLabel -in @('SMS', 'Voice call')) { return @() }
    $labels = @()
    if (@($Methods | Where-Object { $_ -match '^(mobilePhone|alternateMobilePhone|sms)$' }).Count -gt 0) { $labels += 'SMS' }
    if (@($Methods | Where-Object { $_ -match '^officePhone$' }).Count -gt 0) { $labels += 'Voice' }
    return $labels
}


# Guest accounts: where does the guest sign in? Only guests from Microsoft Entra tenants can bring MFA from their home tenant.
# Kind: entra / other (MFA is done in this tenant). Without identities the guest is treated as an Entra guest.
function Get-GuestIdentityInfo {
    param($User)
    if (-not ($User.userType -eq 'Guest' -or $User.userPrincipalName -like '*#EXT#*')) { return $null }
    $identities = @(@($User.identities) | Where-Object { $_ })
    $issuers = @($identities | Where-Object { $_.signInType -eq 'federated' -and $_.issuer } | ForEach-Object { [string]$_.issuer })
    if ($identities.Count -eq 0 -or $issuers -contains 'ExternalAzureAD') { return @{ Kind = 'entra'; Short = 'Microsoft Entra'; Long = 'Microsoft Entra' } }
    if ($issuers -contains 'mail') { return @{ Kind = 'other'; Short = 'Email OTP'; Long = 'Email one-time passcode' } }
    if ($issuers -contains 'google.com') { return @{ Kind = 'other'; Short = 'Google'; Long = 'Google' } }
    if ($issuers -contains 'facebook.com') { return @{ Kind = 'other'; Short = 'Facebook'; Long = 'Facebook' } }
    if (@($issuers | Where-Object { $_ -in @('MicrosoftAccount', 'live.com') }).Count -gt 0) { return @{ Kind = 'other'; Short = 'Microsoft account'; Long = 'Microsoft account' } }
    if ($issuers.Count -gt 0) { return @{ Kind = 'other'; Short = 'SAML/WS-Fed'; Long = 'SAML/WS-Fed' } }
    return @{ Kind = 'other'; Short = 'Local account'; Long = 'Local account' }
}

# Home domain of a guest: the mail domain, else the part of the UPN before #EXT# with the last underscore turned into @
function Get-GuestDomain {
    param($User)
    $domain = ''
    if ([string]$User.mail -match '@([^@]+)$') { $domain = $Matches[1] }
    else {
        $local = ([string]$User.userPrincipalName -split '#EXT#')[0]
        $i = $local.LastIndexOf('_')
        if ($i -ge 0) { $domain = $local.Substring($i + 1) }
    }
    if ($domain -notmatch '^[A-Za-z0-9.-]+$') { return '' }
    return $domain
}

# Does this tenant trust MFA done in the guest's home tenant? Organization setting (partner) first, then the default.
$script:guestTenantByDomain = @{}
$script:guestPartnerTrust = @{}
$script:guestDefaultTrust = $null
$script:guestTrustDenied = $false
function Get-GuestMfaTrust {
    param([string]$Domain)
    $result = @{ Result = 'unknown'; Source = ''; Domain = $Domain }
    if (-not $Domain) { return $result }
    try {
        if (-not $script:guestTenantByDomain.ContainsKey($Domain)) {
            $info = Invoke-MgWithRetry { Invoke-MgGraphRequest -Method GET -Uri "v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='$Domain')" -ErrorAction Stop }
            $script:guestTenantByDomain[$Domain] = [string]$info.tenantId
        }
        $tenantId = $script:guestTenantByDomain[$Domain]
        if ($tenantId -notmatch '^[0-9a-fA-F-]{36}$') { return $result }
        if (-not $script:guestPartnerTrust.ContainsKey($tenantId)) {
            try {
                $partner = Invoke-MgWithRetry { Invoke-MgGraphRequest -Method GET -Uri "v1.0/policies/crossTenantAccessPolicy/partners/$tenantId" -ErrorAction Stop }
                $script:guestPartnerTrust[$tenantId] = $partner.inboundTrust.isMfaAccepted   # null: inherited from the default
            }
            catch {
                if ($_.Exception.Message -match '404|NotFound|ResourceNotFound') { $script:guestPartnerTrust[$tenantId] = $null } else { throw }
            }
        }
        $partnerValue = $script:guestPartnerTrust[$tenantId]
        if ($null -ne $partnerValue) { $result.Source = 'Organization'; $result.Result = $(if ([bool]$partnerValue) { 'accepted' } else { 'rejected' }); return $result }
        if ($null -eq $script:guestDefaultTrust) {
            $default = Invoke-MgWithRetry { Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/crossTenantAccessPolicy/default' -ErrorAction Stop }
            $script:guestDefaultTrust = [bool]$default.inboundTrust.isMfaAccepted
        }
        $result.Source = 'Default'; $result.Result = $(if ($script:guestDefaultTrust) { 'accepted' } else { 'rejected' })
    }
    catch {
        if ($_.Exception.Message -match '403|Forbidden|Authorization_RequestDenied|Insufficient privileges') { $script:guestTrustDenied = $true }
        Write-Verbose "Guest MFA trust for '$Domain' could not be read: $($_.Exception.Message)"
        $result.Result = 'unknown'; $result.Source = ''
    }
    return $result
}

# Strongest tier the registered authentication methods allow, in the order of the Microsoft Entra authentication strengths:
# phishing-resistant MFA (pr) > passwordless MFA (pwl) > multifactor authentication (mfa) > single factor (sf).
# Method names are the values of methodsRegistered in the registration report.
function Get-AuthStrength {
    param([string[]]$Methods)
    $tiers = @(
        @{ Key = 'pr'; Methods = @(
            @{ Pattern = '^windowsHelloForBusiness$'; Label = 'Windows Hello for Business' }
            @{ Pattern = '^passKey'; Label = 'Passkey' }
            @{ Pattern = '^fido2'; Label = 'Passkey (FIDO2 security key)' }
            @{ Pattern = '^macOsSecureEnclaveKey$'; Label = 'Platform credential (macOS)' }
            @{ Pattern = 'certificate|x509'; Label = 'Certificate-based authentication' }
        ) }
        @{ Key = 'pwl'; Methods = @(
            @{ Pattern = '^microsoftAuthenticatorPasswordless$'; Label = 'Microsoft Authenticator (phone sign-in)' }
        ) }
        @{ Key = 'mfa'; Methods = @(
            @{ Pattern = '^microsoftAuthenticatorPush$'; Label = 'Microsoft Authenticator (push)' }
            @{ Pattern = '^softwareOneTimePasscode$'; Label = 'Software OATH token' }
            @{ Pattern = '^hardwareOneTimePasscode$'; Label = 'Hardware OATH token' }
            @{ Pattern = '^temporaryAccessPass$'; Label = 'Temporary Access Pass' }
            @{ Pattern = '^(mobilePhone|alternateMobilePhone|sms)$'; Label = 'SMS' }
            @{ Pattern = '^officePhone$'; Label = 'Voice call' }
            @{ Pattern = '^externalAuthMethod$'; Label = 'External authentication method' }
        ) }
    )
    foreach ($tier in $tiers) {
        foreach ($method in $tier.Methods) {
            if (@($Methods | Where-Object { $_ -match $method.Pattern }).Count -gt 0) { return @{ Key = $tier.Key; Label = $method.Label } }
        }
    }
    return @{ Key = 'sf'; Label = 'No multifactor method registered' }
}

# Sign-in frequency as text: 0 is "every time"
function Format-Hours {
    param($Hours)
    if ($null -eq $Hours) { return '' }
    if ($Hours -eq 0) { return 'Every time' }
    if ($Hours -ge 24 -and ($Hours % 24) -eq 0) { return "$([int]($Hours / 24)) d" }
    return "$([Math]::Round([double]$Hours, 1)) h"
}

function Add-ToListMap {
    param([hashtable]$Map, [string]$Key, $Value)
    if (-not $Map.ContainsKey($Key)) { $Map[$Key] = [System.Collections.Generic.List[object]]::new() }
    $Map[$Key].Add($Value)
}

# What a Conditional Access policy requires and how broadly it applies, independent of the user
function Get-CaPolicySummary {
    param($Policy, [hashtable]$StrengthsById, [hashtable]$LocationsById = @{})
    $grant = $Policy.grantControls
    $builtIn = @(@($grant.builtInControls) | Where-Object { $_ })
    $strength = $grant.authenticationStrength
    $controls = [System.Collections.Generic.List[string]]::new()
    foreach ($control in $builtIn) { $controls.Add([string]$control) }
    $strengthIsPhishingResistant = $false
    if ($strength) {
        $combinations = @(@($strength.allowedCombinations) | Where-Object { $_ })
        if ($combinations.Count -eq 0 -and $StrengthsById.ContainsKey([string]$strength.id)) { $combinations = @($StrengthsById[[string]$strength.id].allowedCombinations) }
        $strengthIsPhishingResistant = ([string]$strength.id -eq $PhishingResistantStrengthId) -or
            ($combinations.Count -gt 0 -and @($combinations | Where-Object { $_ -notin $PhishingResistantCombinations }).Count -eq 0)
        $strengthName = if ($strength.displayName) { [string]$strength.displayName } elseif ($StrengthsById.ContainsKey([string]$strength.id)) { [string]$StrengthsById[[string]$strength.id].displayName } else { 'custom' }
        $controls.Add("authentication strength: $strengthName")
    }
    foreach ($extra in @($grant.customAuthenticationFactors) + @($grant.termsOfUse)) { if ($extra) { $controls.Add('custom control / terms of use') } }

    # With operator OR and several controls, the sign-in can satisfy any one of them, so MFA is not guaranteed
    $anyOf = ([string]$grant.operator -eq 'OR' -and $controls.Count -gt 1)
    $requirement = if ($builtIn -contains 'block') { 'block' }
                   elseif ($anyOf) { 'other' }
                   elseif ($strength -and $strengthIsPhishingResistant) { 'pr' }
                   elseif ($strength -or $builtIn -contains 'mfa') { 'mfa' }
                   else { 'other' }
    $requirementLabel = switch ($requirement) {
        'block' { 'Block access' }
        'pr'    { 'Phishing-resistant MFA' }
        'mfa'   { 'MFA' }
        default { if ($controls.Count -gt 0) { $(if ($anyOf) { 'One of: ' } else { '' }) + ($controls -join ', ') } else { 'Session controls only' } }
    }

    $conditions = $Policy.conditions
    $apps = $conditions.applications
    $allResources = (@($apps.includeApplications) -contains 'All') -and (@(@($apps.excludeApplications) | Where-Object { $_ }).Count -eq 0)
    $scopeLabel = if ($allResources) { 'All resources' }
                  elseif (@($apps.includeApplications) -contains 'All') { 'All resources, with exclusions' }
                  elseif (@(@($apps.includeUserActions) | Where-Object { $_ }).Count -gt 0) { 'User action' }
                  elseif (@(@($apps.includeAuthenticationContextClassReferences) | Where-Object { $_ }).Count -gt 0) { 'Authentication context' }
                  else { 'Selected resources' }

    # Display only: a policy that targets just the Microsoft Admin Portals
    $scopeDetail = if (-not $allResources -and @(@($apps.includeApplications) | Where-Object { $_ }).Count -gt 0 -and @(@($apps.includeApplications) | Where-Object { $_ -and $_ -ne 'MicrosoftAdminPortals' }).Count -eq 0) { 'Microsoft Admin Portals only' } else { '' }

    # Any extra condition means the policy only applies to some sign-ins
    $narrowed = [System.Collections.Generic.List[string]]::new()
    if ($conditions.locations -and (@($conditions.locations.includeLocations) -notcontains 'All' -or @(@($conditions.locations.excludeLocations) | Where-Object { $_ }).Count -gt 0)) { $narrowed.Add('location') }
    if ($conditions.platforms) { $narrowed.Add('device platform') }
    if (@(@($conditions.clientAppTypes) | Where-Object { $_ }).Count -gt 0 -and @($conditions.clientAppTypes) -notcontains 'all') { $narrowed.Add('client app') }
    if (@(@($conditions.userRiskLevels) | Where-Object { $_ }).Count -gt 0) { $narrowed.Add('user risk') }
    if (@(@($conditions.signInRiskLevels) | Where-Object { $_ }).Count -gt 0) { $narrowed.Add('sign-in risk') }
    if ($conditions.devices) { $narrowed.Add('device filter') }
    if ($conditions.authenticationFlows) { $narrowed.Add('authentication flow') }
    if (@(@($conditions.insiderRiskLevels) | Where-Object { $_ }).Count -gt 0) { $narrowed.Add('insider risk') }

    $other = [System.Collections.Generic.List[string]]::new()
    foreach ($control in $builtIn) { if ($control -notin @('mfa', 'block')) { $other.Add([string]$control) } }
    if ($Policy.sessionControls.signInFrequency.isEnabled) { $other.Add('sign-in frequency') }

    # Trusted device: a grant that guarantees a compliant or hybrid joined device. With "require one of" it only counts when
    # every selected control is a device control; MFA as an alternative makes the device optional.
    $deviceControls = @($builtIn | Where-Object { $_ -in @('compliantDevice', 'domainJoinedDevice') })
    $deviceMode = 'none'; $deviceLabel = ''
    if ($deviceControls.Count -gt 0 -and $builtIn -notcontains 'block') {
        $otherGrant = @($builtIn | Where-Object { $_ -notin @('compliantDevice', 'domainJoinedDevice') }).Count + $(if ($strength) { 1 } else { 0 })
        $deviceMode = if ([string]$grant.operator -eq 'OR' -and $otherGrant -gt 0) { 'optional' } else { 'required' }
        $deviceLabel = if ($deviceControls.Count -eq 2) { if ([string]$grant.operator -eq 'OR') { 'Compliant or hybrid joined' } else { 'Compliant and hybrid joined' } }
                       elseif ($deviceControls -contains 'compliantDevice') { 'Compliant' } else { 'Hybrid joined' }
    }

    # Trusted location: a block policy that covers all locations except the trusted ones, so access only works from there
    $locationKind = 'none'; $locationLabels = @()
    $locationCondition = $conditions.locations
    if ($builtIn -contains 'block' -and $locationCondition -and @($locationCondition.includeLocations) -contains 'All') {
        $kinds = [System.Collections.Generic.List[string]]::new(); $labels = [System.Collections.Generic.List[string]]::new()
        foreach ($excluded in @(@($locationCondition.excludeLocations) | Where-Object { $_ })) {
            if ($excluded -eq 'AllTrusted') { $kinds.Add('ip'); $labels.Add('Trusted locations') }
            elseif ($LocationsById.ContainsKey([string]$excluded)) { $named = $LocationsById[[string]$excluded]; $kinds.Add($named.Type); $labels.Add($named.Name) }
            else { $kinds.Add('other'); $labels.Add([string]$excluded) }
        }
        $locationKind = if ($kinds -contains 'gsa') { 'gsa' } elseif ($kinds -contains 'ip') { 'ip' } elseif ($kinds -contains 'country') { 'country' } elseif ($kinds.Count -gt 0) { 'other' } else { 'none' }
        $locationLabels = @($labels)
    }

    # Sign-in frequency in hours ("every time" is 0)
    $signInFrequency = $Policy.sessionControls.signInFrequency
    $signInFrequencyHours = $null
    if ($signInFrequency -and $signInFrequency.isEnabled) {
        if ([string]$signInFrequency.frequencyInterval -eq 'everyTime') { $signInFrequencyHours = 0 }
        elseif ($null -ne $signInFrequency.value) { $signInFrequencyHours = [double]$signInFrequency.value * $(if ([string]$signInFrequency.type -eq 'days') { 24 } else { 1 }) }
    }

    [PSCustomObject]@{
        DeviceMode       = $deviceMode
        DeviceLabel      = $deviceLabel
        LocationKind     = $locationKind
        LocationLabels   = $locationLabels
        SifHours         = $signInFrequencyHours
        NarrowedOther    = @($narrowed | Where-Object { $_ -ne 'location' })
        Id               = [string]$Policy.id
        Name             = [string]$Policy.displayName
        State            = [string]$Policy.state
        Requirement      = $requirement
        RequirementLabel = $requirementLabel
        AllResources     = $allResources
        ScopeLabel       = $scopeLabel
        ScopeDetail      = $scopeDetail
        Narrowed         = $narrowed
        OtherControls    = $other
        Users            = $conditions.users
    }
}

# Does a Conditional Access policy target this administrator?
# Result: yes / activation (only once an eligible role is activated) / excluded / no, with the reason.
function Test-CaPolicyForAdmin {
    param($Policy, $Admin)
    $users = $Policy.Users
    $includeUsers = @($users.includeUsers)
    $why = $null
    $result = 'no'
    if ($includeUsers -contains 'All') { $why = 'All users'; $result = 'yes' }
    elseif ($includeUsers -contains $Admin.Id) { $why = 'User included'; $result = 'yes' }
    elseif (@(@($users.includeGroups) | Where-Object { $Admin.GroupIds -contains $_ }).Count -gt 0) { $why = 'Member of included group'; $result = 'yes' }
    elseif (@(@($users.includeRoles) | Where-Object { $Admin.ActiveRoleIds -contains $_ }).Count -gt 0) { $why = 'Holds included role'; $result = 'yes' }
    elseif ($Admin.UserType -eq 'guest' -and ($includeUsers -contains 'GuestsOrExternalUsers' -or $users.includeGuestsOrExternalUsers)) { $why = 'Guests or external users'; $result = 'yes' }
    elseif (@(@($users.includeRoles) | Where-Object { $Admin.EligibleRoleIds -contains $_ }).Count -gt 0) { $why = 'Eligible for included role (applies after activation)'; $result = 'activation' }
    if ($result -eq 'no') { return @{ Result = 'no'; Why = '' } }

    if (@($users.excludeUsers) -contains $Admin.Id) { return @{ Result = 'excluded'; Why = 'User excluded' } }
    if (@(@($users.excludeGroups) | Where-Object { $Admin.GroupIds -contains $_ }).Count -gt 0) { return @{ Result = 'excluded'; Why = 'Member of excluded group' } }
    if (@(@($users.excludeRoles) | Where-Object { $Admin.ActiveRoleIds -contains $_ }).Count -gt 0) { return @{ Result = 'excluded'; Why = 'Holds excluded role' } }
    return @{ Result = $result; Why = $why }
}

# Findings for one administrator account, based on the Microsoft Learn recommendations for
# administrator accounts (or for emergency access accounts when the account is a break-glass account).
function Get-AdminAssessment {
    param($Admin)
    $findings = [System.Collections.Generic.List[object]]::new()
    $entraRoles = @($Admin.Roles | Where-Object { $_.Kind -eq 'Entra' })
    $privilegedRoles = @($entraRoles | Where-Object { $_.Privileged })
    # A privileged role limited to an administrative unit or a single object has a limited impact, so it is rated lower
    $tenantPrivileged = @($privilegedRoles | Where-Object { $_.ScopeKind -eq 'tenant' })
    $scopedPrivileged = @($privilegedRoles | Where-Object { $_.ScopeKind -ne 'tenant' })
    $standing = @($tenantPrivileged | Where-Object { $_.Type -eq 'Active' -and $_.Assignment -ne 'Activated (PIM)' })
    $standingScoped = @($scopedPrivileged | Where-Object { $_.Type -eq 'Active' -and $_.Assignment -ne 'Activated (PIM)' })
    $hasMailbox = $Admin.LicenseKey -eq 'mailbox'

    if ($Admin.IsBreakGlass) {
        $findings.Add((New-Reason 'info' 'Marked as an emergency access (break-glass) account with -BreakGlassAccounts. It is checked against the emergency access recommendations'))
        if ($Admin.OnPremisesSynced) { $findings.Add((New-Reason 'high' 'Emergency access account is synced from on-premises AD. Make it cloud-only so it works when on-premises is down')) }
        if ($Admin.UserPrincipalName -notlike '*.onmicrosoft.com') { $findings.Add((New-Reason 'medium' 'Emergency access account is not on *.onmicrosoft.com. A custom or federated domain can fail in an emergency. Use *.onmicrosoft.com')) }
        $permanentGa = @($entraRoles | Where-Object { $_.RoleId -eq $GlobalAdminRoleId -and $_.Type -eq 'Active' -and $_.Via -eq 'Direct' -and $_.Assignment -in @('Permanent', 'Active') })
        if ($permanentGa.Count -eq 0) { $findings.Add((New-Reason 'high' "Emergency access account is not a permanent active Global Administrator. Assign the role directly and permanently$(if ($script:pimBaseline) { ', not as eligible' })")) }
        if (-not $Admin.AccountEnabled) { $findings.Add((New-Reason 'high' 'Emergency access account is disabled and cannot be used in an emergency. Enable it')) }
        if ($Admin.LicenseKey -in @('mailbox', 'productivity')) { $findings.Add((New-Reason 'low' 'Emergency access account has a mailbox or productivity license. Remove it; the account is not for daily work')) }
        foreach ($f in (Get-NotificationFindings $Admin)) { $findings.Add($f) }
        if ($script:signInDataAvailable -and ($null -eq $Admin.LastActivity -or $Admin.DaysSinceActivity -ge 90)) { $findings.Add((New-Reason 'low' 'No sign-in in 90 days. Test that the emergency access account still works at least every 90 days')) }
        # Microsoft recommends a passkey (FIDO2) or certificate-based authentication; none registered is High, other methods only is Medium
        if ($Admin.AuthCollected -and $Admin.AuthKey -in @('sf', 'mfa', 'pwl', 'pr') -and @($Admin.Methods | Where-Object { $_ -match '^passKey|^fido2|certificate|x509' }).Count -eq 0) { $findings.Add((New-Reason $(if ($Admin.AuthKey -eq 'sf') { 'high' } else { 'medium' }) 'No passkey (FIDO2) or certificate is registered. Microsoft recommends one of them for emergency access accounts')) }
        if ($Admin.CaCollected) {
            $enforced = @($Admin.CaPolicies | Where-Object { $_.Result -eq 'yes' -and $_.State -eq 'enabled' })
            if ($enforced.Count -gt 0) {
                $findings.Add((New-Reason 'high' 'Enabled Conditional Access policies apply to this account. Exclude it from policies that block or restrict sign-in' -Detail "Policies: $((@($enforced | ForEach-Object { $_.Name }) | Select-Object -First 5) -join ', ')."))
            }
        }
        return $findings
    }

    # Entra Connect connector account: a service account, so the checks for human administrators do not apply
    if ($Admin.SyncAccount -eq 'connector') {
        $findings.Add((New-Reason 'info' "Entra Connect sync account, checked as a service account$(if ($script:caBaseline) { '. Exclude it from Conditional Access policies' })"))
        $otherRoles = @($Admin.Roles | Where-Object { $_.RoleId -ne $SyncRoleId -and $_.Role -ne $SyncRoleName })
        if ($otherRoles.Count -gt 0) {
            $findings.Add((New-Reason 'high' 'The sync account holds other roles. Remove them: whoever controls the Connect server controls this account' -Detail "Other roles: $((@($otherRoles | ForEach-Object { $_.Role }) | Sort-Object -Unique | Select-Object -First 5) -join ', ')."))
        }
        if ($Admin.Skus.Count -gt 0) { $findings.Add((New-Reason 'low' 'The sync account has a license. A service account needs none. Remove it' -Detail "Licenses: $($Admin.Skus -join ', ').")) }
        if (-not $Admin.AccountEnabled) {
            $findings.Add((New-Reason 'low' 'The sync account is disabled. Delete it if no Connect server uses it'))
        }
        elseif ($script:signInDataAvailable -and ($null -eq $Admin.LastActivity -or $Admin.DaysSinceActivity -ge $InactiveDays)) {
            $since = if ($null -eq $Admin.LastActivity) { 'No sign-in recorded' } else { "No sign-in for $($Admin.DaysSinceActivity) days" }
            $findings.Add((New-Reason 'low' "$since (threshold: $InactiveDays days). Remove the account if no Connect server uses it, otherwise check that sync is running"))
        }
        return $findings
    }
    if ($Admin.SyncAccount -eq 'unexpected') {
        $why = if ($Admin.SyncSignals.Count -gt 0) { " Why it stands out: $($Admin.SyncSignals -join '; ')." } else { '' }
        $findings.Add((New-Reason 'high' "Holds the $SyncRoleName role but is not a Connect account. Remove the assignment" -Detail "Microsoft says only the Connect wizard assigns this role. Check the audit log.$why"))
    }

    if ($Admin.LikelyBreakGlass) {
        $findings.Add((New-Reason 'info' 'Looks like an emergency access (break-glass) account. Pass it with -BreakGlassAccounts to check it as one' -Detail 'Cloud-only, *.onmicrosoft.com, permanent Global Administrator.'))
    }

    # Source of authority
    if ($Admin.OnPremisesSynced) {
        if ($tenantPrivileged.Count -gt 0) { $findings.Add((New-Reason 'high' 'Synced from on-premises AD with a privileged role, so an on-premises compromise reaches the cloud. Use a cloud-only account')) }
        elseif ($scopedPrivileged.Count -gt 0) { $findings.Add((New-Reason 'medium' 'Synced from on-premises AD with a scoped privileged role. Use a cloud-only account' -Detail 'The role is limited to an administrative unit or object. An on-premises compromise can still reach the cloud.')) }
        else { $findings.Add((New-Reason 'medium' 'Synced from on-premises AD. Use a cloud-only account for Microsoft Entra roles')) }
    }
    if ($Admin.UserType -eq 'guest') {
        $guestTier0 = @($entraRoles | Where-Object { $_.RoleId -in $Tier0RoleIds -and $_.Type -in @('Active', 'Eligible') -and $_.ScopeKind -eq 'tenant' }).Count -gt 0
        $findings.Add((New-Reason $(if ($guestTier0) { 'high' } else { 'medium' }) 'Guest or external account with administrator access. Confirm that this external identity still needs it'))
    }
    if (-not $Admin.AccountEnabled) {
        $findings.Add((New-Reason 'low' 'Account is disabled but still has role assignments. Remove the assignments or delete the account'))
    }

    # Standing access (PIM is part of the P2 baseline only)
    if ($script:pimBaseline -and $standing.Count -gt 0) {
        $names = (@($standing | ForEach-Object { $_.Role }) | Sort-Object -Unique) -join ', '
        if ($script:eligibilityAvailable) { $findings.Add((New-Reason 'medium' 'Privileged roles are always active. Use PIM to make them eligible and activate them only when needed' -Detail "Roles: $names.")) }
        else { $findings.Add((New-Reason 'low' 'Privileged roles are always active. PIM data is not available in this tenant' -Detail "Roles: $names.")) }
    }
    if ($script:pimBaseline -and $standingScoped.Count -gt 0) {
        $scopedNames = (@($standingScoped | ForEach-Object { "$($_.Role) ($($_.Scope))" }) | Sort-Object -Unique) -join ', '
        $findings.Add((New-Reason 'low' 'Scoped privileged roles are always active. Prefer PIM eligibility here too' -Detail "Roles: $scopedNames. The impact is limited to that scope."))
    }
    $ownerPaths = @($Admin.Roles | Where-Object { $_.Type -eq 'Owner' })
    if ($ownerPaths.Count -gt 0) {
        $findings.Add((New-Reason 'medium' 'Owns groups that hold roles. An owner can grant those roles to anyone. Review the ownership' -Detail "Groups: $((@($ownerPaths | ForEach-Object { $_.Via }) | Sort-Object -Unique) -join ', ')."))
    }

    # Activity
    if ($script:signInDataAvailable -and $Admin.AccountEnabled) {
        if ($null -eq $Admin.LastActivity) { $findings.Add((New-Reason 'medium' 'No sign-in recorded. Confirm that this administrator account is still needed')) }
        elseif ($Admin.DaysSinceActivity -ge $InactiveDays) { $findings.Add((New-Reason 'medium' "No sign-in for $($Admin.DaysSinceActivity) days (threshold: $InactiveDays days). Remove role assignments that are no longer needed")) }
    }

    # Licenses and notification email
    if ($hasMailbox) {
        $findings.Add((New-Reason 'medium' "Has an Exchange Online mailbox license. Remove it and use a plus address of the owner's mailbox as Email" -Detail "Plans: $($Admin.MailboxPlanLabels -join ', ')."))
    } elseif ($Admin.LicenseKey -eq 'productivity') {
        $findings.Add((New-Reason 'low' 'Has productivity service plans. Teams, SharePoint and Microsoft 365 Apps are not needed for administration. Remove them' -Detail "Plans: $($Admin.ProductivityPlanLabels -join ', ')."))
    }
    foreach ($f in (Get-NotificationFindings $Admin)) { $findings.Add($f) }

    # Authentication methods
    if ($Admin.AuthCollected) {
        switch ($Admin.AuthKey) {
            'sf'      { $findings.Add((New-Reason 'high' $(if ($Admin.GuestKind -eq 'entra') { 'No multifactor method registered and home tenant MFA not trusted. Register a passkey (FIDO2) here or trust that tenant' } else { 'No multifactor method registered, so the account relies on a password. Register a passkey (FIDO2)' }))) }
            'mfa'     { $findings.Add((New-Reason 'medium' 'Strongest method is MFA, not phishing-resistant. Register a passkey (FIDO2) or Windows Hello for Business' -Detail "Strongest method: $($Admin.AuthLabel).")) }
            'pwl'     { $findings.Add((New-Reason 'medium' 'Strongest method is passwordless MFA, not phishing-resistant. Register a passkey (FIDO2) or Windows Hello for Business' -Detail "Strongest method: $($Admin.AuthLabel).")) }
            'unknown' { $findings.Add((New-Reason 'info' $(if ($Admin.GuestKind -eq 'entra' -and $Admin.GuestTrust -eq 'unknown') { 'MFA trust for this guest could not be read' } else { 'Authentication methods could not be read for this account (the registration report does not cover disabled users)' }))) }
        }
        # Weaker methods only matter while nothing enforces phishing-resistant MFA
        if ($Admin.AuthKey -eq 'pr' -and $Admin.WeakMethods.Count -gt 0 -and $Admin.CaKey -ne 'pr') {
            $findings.Add((New-Reason 'low' 'Weaker methods remain next to the phishing-resistant method. Remove them or require phishing-resistant MFA' -Detail "Weaker methods: $((@($Admin.WeakMethods | ForEach-Object { (Get-MethodInfo $_).Label }) | Sort-Object -Unique) -join ', ')."))
        }
    }

    # Security defaults: no finding for the roles they cover; other roles get a Low finding
    if ($Admin.CaCollected -and (Get-AccessVerdictKey $Admin) -eq 'sd' -and -not (Test-SecurityDefaultsRole $Admin)) {
        $findings.Add((New-Reason 'low' "Security defaults require MFA for this role only when needed$(if ($script:caBaseline) { '. Add a Conditional Access policy that requires MFA' })"))
    }
    # Conditional Access (accounts covered by security defaults get no finding)
    if ($Admin.CaCollected -and (Get-AccessVerdictKey $Admin) -ne 'sd') {
        switch ($Admin.CaKey) {
            'none'       { $findings.Add((New-Reason $(if ($script:caBaseline) { 'high' } else { 'medium' }) $(if ($script:caBaseline) { 'No Conditional Access policy requires MFA. Require phishing-resistant MFA for administrators, plus a device or location' } else { 'MFA is not enforced. Enable security defaults to require MFA for administrators' }))) }
            'partial'    { $findings.Add((New-Reason 'medium' 'MFA is only required for some resources or conditions. Cover all resources and require phishing-resistant MFA')) }
            'activation' { $findings.Add((New-Reason 'low' 'MFA is only required after role activation. Require phishing-resistant MFA at sign-in for administrators' -Detail 'Role-targeted policies apply after an eligible role is activated. Also check that the PIM role settings require MFA on activation.')) }
            'mfa'        { $findings.Add((New-Reason 'medium' 'MFA is required, but not phishing-resistant. Require a phishing-resistant authentication strength, then add a device or location')) }
        }
        # With phishing-resistant MFA enforced, Microsoft pairs it with a compliant or hybrid joined device and/or trusted
        # locations, and a bounded session
        if ($Admin.CaKey -eq 'pr') {
            if ($Admin.DeviceKey -ne 'device' -and $Admin.LocKey -notin @('gsa', 'ip')) {
                $note = if ($Admin.DeviceKey -eq 'optional') { ' A device requirement exists, but MFA is an alternative to it, so it is not guaranteed.' } elseif ($Admin.LocKey -in @('country', 'other')) { ' Only a country or other location restriction applies, which is weaker than a trusted IP range or the Global Secure Access compliant network.' } else { '' }
                $findings.Add((New-Reason 'medium' 'Phishing-resistant MFA, but no device or location requirement. Add a policy that requires a compliant device or a trusted location' -Detail $note.Trim()))
            }
            if ($Admin.SifKey -eq 'none') { $findings.Add((New-Reason 'low' "No sign-in frequency set, so sessions are not bounded. Set one of at most $MaxSignInFrequencyHours hours" -Detail $(if ($script:pimBaseline) { 'For the Azure portal and the Entra admin center you can also require re-authentication on PIM activation.' } else { '' }))) }
            elseif ($Admin.SifKey -eq 'long') { $findings.Add((New-Reason 'low' "Sign-in frequency is $(Format-Hours $Admin.SifHours), above the $MaxSignInFrequencyHours-hour limit. Shorten it, especially for unmanaged devices")) }
        }
    }

    return $findings
}

function New-BadgeHtml {
    param([string]$Color, [string]$Text, [string]$Title = '', [string]$Group = '', [string]$Value = '', [string]$OnClick = '')
    $attributes = "class='badge $Color clickable-badge'"
    if ($Group)   { $attributes += " data-fg='$Group' data-fv='$Value'" }
    if ($OnClick) { $attributes += " onclick=`"$OnClick`"" }
    if ($Title)   { $attributes += " title='$(ConvertTo-HtmlSafe $Title)'" }
    "<span $attributes>$(ConvertTo-HtmlSafe $Text)</span>"
}

# Import required modules
Write-Host "Importing Microsoft Graph modules..." -ForegroundColor Green
Import-GraphModuleSafely "Microsoft.Graph.Authentication"

# Connect to Microsoft Graph. The opt-in switches add the permissions they need.
$scopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "Policy.Read.All"
)
if ($script:caBaseline) { $scopes += "AuditLog.Read.All"; $scopes += "CrossTenantInformation.ReadBasic.All" }
if ($script:pimBaseline) { $scopes += "PrivilegedEligibilitySchedule.Read.AzureADGroup" }
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Green
try {
    if ($AccessToken) {
        # Token passed in - e.g. from AzurePowerShell@5 azureSubscription task
        Write-Host "  Auth method: Pre-acquired access token" -ForegroundColor Cyan
        Connect-MgGraph -AccessToken $AccessToken -NoWelcome -ErrorAction Stop
    } elseif ($ClientId -and $CertificateThumbprint) {
        # Service Principal with certificate - recommended for pipelines
        Write-Host "  Auth method: Service Principal (certificate)" -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    } elseif ($UseManagedIdentity) {
        # Managed Identity - for Azure-hosted automation.
        # -ClientId selects a user-assigned Managed Identity; omit it for the system-assigned one.
        if ($ClientId) {
            Write-Host "  Auth method: Managed Identity (user-assigned)" -ForegroundColor Cyan
            Connect-MgGraph -Identity -ClientId $ClientId -NoWelcome -ErrorAction Stop
        } else {
            Write-Host "  Auth method: Managed Identity" -ForegroundColor Cyan
            Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
        }
    } elseif ($TenantId) {
        Connect-MgGraph -Scopes $scopes -TenantId $TenantId -NoWelcome -ErrorAction Stop
    } else {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    }
    if (-not (Get-MgContext)) {
        throw 'Connect-MgGraph returned no context - authentication may have been cancelled or denied.'
    }
}
catch {
    Write-Error "Authentication failed: $($_.Exception.Message)"
    exit 1
}

try {

# BULK PRE-FETCH: role definitions, active and eligible role assignments are read once tenant-wide.
Write-Host "Reading Microsoft Entra role definitions and assignments..." -ForegroundColor Green
$roleDefinitionsById = @{}
foreach ($definition in (Get-GraphCollection 'v1.0/roleManagement/directory/roleDefinitions')) {
    $roleDefinitionsById[[string]$definition.id] = $definition
}
$privilegedFlagAvailable = @($roleDefinitionsById.Values | Where-Object { $null -ne $_.isPrivileged }).Count -gt 0
if (-not $privilegedFlagAvailable) { Write-Warning "Role definitions carry no isPrivileged flag. Using the built-in list of privileged role names instead." }

# PIM schedule instances tell a permanent assignment from an activated or time-bound one
$assignmentInstances = @{}
try {
    foreach ($instance in $(if ($script:pimBaseline) { Get-GraphCollection 'v1.0/roleManagement/directory/roleAssignmentScheduleInstances' })) {
        $assignmentInstances["$($instance.principalId)|$($instance.roleDefinitionId)|$($instance.directoryScopeId)"] = $instance
    }
}
catch {
    Write-Verbose "Role assignment schedule instances are not available: $($_.Exception.Message)"
}

# Raw role entries, one per assignment: principal (user or group), role, type and scope
$rawEntries = [System.Collections.Generic.List[object]]::new()
foreach ($assignment in (Get-GraphCollection 'v1.0/roleManagement/directory/roleAssignments')) {
    $instance = $assignmentInstances["$($assignment.principalId)|$($assignment.roleDefinitionId)|$($assignment.directoryScopeId)"]
    $assignmentType = if (-not $instance) { 'Active' }
                      elseif ([string]$instance.assignmentType -eq 'Activated') { 'Activated (PIM)' }
                      elseif ($instance.endDateTime) { 'Time-bound' }
                      else { 'Permanent' }
    $scopeInfo = Get-RoleScopeInfo $assignment.directoryScopeId
    $rawEntries.Add([PSCustomObject]@{
        Kind = 'Entra'; PrincipalId = [string]$assignment.principalId; RoleId = [string]$assignment.roleDefinitionId
        Type = 'Active'; Assignment = $assignmentType; ScopeId = $scopeInfo.Id; ScopeKind = $scopeInfo.Kind; ScopeRef = $scopeInfo.Ref
        Ends = ConvertTo-UtcDateTime $instance.endDateTime
    })
}
try {
    foreach ($schedule in $(if ($script:pimBaseline) { Get-GraphCollection 'v1.0/roleManagement/directory/roleEligibilitySchedules' })) {
        $scopeInfo = Get-RoleScopeInfo $schedule.directoryScopeId
        $rawEntries.Add([PSCustomObject]@{
            Kind = 'Entra'; PrincipalId = [string]$schedule.principalId; RoleId = [string]$schedule.roleDefinitionId
            Type = 'Eligible'; Assignment = ''; ScopeId = $scopeInfo.Id; ScopeKind = $scopeInfo.Kind; ScopeRef = $scopeInfo.Ref
            Ends = ConvertTo-UtcDateTime $schedule.scheduleInfo.expiration.endDateTime
        })
    }
}
catch {
    $script:eligibilityAvailable = $false
    Write-Warning "Could not read eligible (PIM) role assignments ($($_.Exception.Message)). Only active roles will be reported."
}
foreach ($entry in $rawEntries) {
    $definition = $roleDefinitionsById[$entry.RoleId]
    $roleName = if ($definition) { [string]$definition.displayName } else { $entry.RoleId }
    $privileged = if ($privilegedFlagAvailable) { [bool]$definition.isPrivileged } else { $roleName -in $PrivilegedRoleNamesFallback }
    $entry | Add-Member -NotePropertyName Role -NotePropertyValue $roleName
    $entry | Add-Member -NotePropertyName Privileged -NotePropertyValue $privileged
    $entry | Add-Member -NotePropertyName BuiltIn -NotePropertyValue $(if ($definition -and $null -ne $definition.isBuiltIn) { [bool]$definition.isBuiltIn } else { $true })
}

# Scope names. A role can be limited to an administrative unit or to a single object, so the scope is shown by name.
# A failed lookup never stops the report: the ID is shown instead.
$auNames = @{}
$auLookupOk = $true
if (@($rawEntries | Where-Object { $_.ScopeKind -eq 'au' }).Count -gt 0) {
    try {
        foreach ($au in (Get-GraphCollection 'v1.0/directory/administrativeUnits?$select=id,displayName')) { $auNames[[string]$au.id] = [string]$au.displayName }
    }
    catch { $auLookupOk = $false; Write-Warning "Could not read administrative units ($($_.Exception.Message)). Scopes will be shown by ID." }
}
$scopeObjects = @{}
$objectLookupOk = $true
$objectIds = @($rawEntries | Where-Object { $_.ScopeKind -eq 'object' } | ForEach-Object { $_.ScopeRef } | Sort-Object -Unique)
if ($objectIds.Count -gt 0) {
    try { $scopeObjects = Get-DirectoryObjectsById $objectIds -Types @('application', 'servicePrincipal', 'group', 'user', 'device') }
    catch { $objectLookupOk = $false; Write-Warning "Could not resolve scope objects ($($_.Exception.Message)). Scopes will be shown by ID." }
}
foreach ($entry in $rawEntries) {
    $scopeType = 'Tenant-wide'; $scopeName = ''
    switch ($entry.ScopeKind) {
        'au' {
            $scopeType = 'Admin unit'
            $scopeName = if ($auNames.ContainsKey($entry.ScopeRef)) { $auNames[$entry.ScopeRef] } elseif ($auLookupOk) { "$($entry.ScopeRef) (not found)" } else { $entry.ScopeRef }
        }
        'object' {
            $object = $scopeObjects[$entry.ScopeRef]
            $scopeType = if ($object) {
                switch ([string]$object.'@odata.type') {
                    '#microsoft.graph.application' { 'App' }
                    '#microsoft.graph.servicePrincipal' { 'Service principal' }
                    '#microsoft.graph.group' { 'Group' }
                    '#microsoft.graph.user' { 'User' }
                    '#microsoft.graph.device' { 'Device' }
                    default { 'Object' }
                }
            } else { 'Object' }
            $scopeName = if ($object -and $object.displayName) { [string]$object.displayName } elseif ($objectLookupOk) { "$($entry.ScopeRef) (not found)" } else { $entry.ScopeRef }
        }
    }
    $entry | Add-Member -NotePropertyName ScopeType -NotePropertyValue $scopeType
    $entry | Add-Member -NotePropertyName ScopeName -NotePropertyValue $scopeName
    # Plain text for the CSV detail and the search
    $entry | Add-Member -NotePropertyName Scope -NotePropertyValue $(if ($entry.ScopeKind -eq 'tenant') { 'Tenant-wide' } else { "${scopeType}: $scopeName" })
}
Write-Host "  Found $($rawEntries.Count) $(if ($script:pimBaseline) { 'active and eligible' } else { 'active' }) Microsoft Entra role assignments" -ForegroundColor Cyan

# Tenant information
$tenantInfo = @((Invoke-MgWithRetry { Invoke-MgGraphRequest -Method GET -Uri 'v1.0/organization?$select=id,displayName' -ErrorAction Stop }).value)[0]
$tenantName = [string]$tenantInfo.displayName
$tenantId = [string]$tenantInfo.id

# Resolve the principals: users become rows, groups are expanded to their members, service principals are out of scope
$principalIds = @($rawEntries | ForEach-Object { $_.PrincipalId } | Where-Object { $_ } | Sort-Object -Unique)
$principals = if ($principalIds.Count -gt 0) { Get-DirectoryObjectsById $principalIds } else { @{} }
$groupIds = @($principals.Values | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { [string]$_.id })

# Group paths: who gets (or can get) the roles of a group. Members, owners, and PIM for Groups eligible members and owners.
$groupPaths = @{}
$eventualHeaders = @{ ConsistencyLevel = 'eventual' }
if ($groupIds.Count -gt 0) {
    Write-Host "Expanding $($groupIds.Count) group(s) that hold roles..." -ForegroundColor Green
    $groupRequests = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($groupId in $groupIds) {
        $groupRequests.Add(@{ id = "gm_$groupId"; url = "/groups/$groupId/transitiveMembers/microsoft.graph.user?`$count=true&`$select=id&`$top=999"; headers = $eventualHeaders })
        $groupRequests.Add(@{ id = "go_$groupId"; url = "/groups/$groupId/owners?`$select=id" })
        if ($script:pimBaseline) { $groupRequests.Add(@{ id = "ge_$groupId"; url = "/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=$([uri]::EscapeDataString("groupId eq '$groupId'"))" }) }
    }
    $groupResults = Invoke-GraphBatch -Requests $groupRequests -Label 'group members'
    foreach ($groupId in $groupIds) {
        foreach ($member in (Get-BatchItems $groupResults["gm_$groupId"] -Headers $eventualHeaders).Items) {
            Add-ToListMap $groupPaths $groupId @{ UserId = [string]$member.id; Path = 'member'; Ends = $null }
        }
        foreach ($owner in (Get-BatchItems $groupResults["go_$groupId"]).Items) {
            if ($owner.'@odata.type' -and $owner.'@odata.type' -ne '#microsoft.graph.user') { continue }
            Add-ToListMap $groupPaths $groupId @{ UserId = [string]$owner.id; Path = 'owner'; Ends = $null }
        }
        $eligible = if ($script:pimBaseline) { Get-BatchItems $groupResults["ge_$groupId"] } else { [PSCustomObject]@{ Ok = $true; Items = @() } }
        if (-not $eligible.Ok) { $script:pimGroupsAvailable = $false }
        foreach ($instance in $eligible.Items) {
            $path = if ([string]$instance.accessId -eq 'owner') { 'eligible owner' } else { 'eligible member' }
            Add-ToListMap $groupPaths $groupId @{ UserId = [string]$instance.principalId; Path = $path; Ends = ConvertTo-UtcDateTime $instance.endDateTime }
        }
    }
    if (-not $script:pimGroupsAvailable) { Write-Warning "Could not read PIM for Groups eligibility for one or more groups. Users who are only eligible members of a group that holds roles may be missing." }
}

# Attach every role entry to the users it reaches
$rolesByUser = @{}
foreach ($entry in $rawEntries) {
    $principal = $principals[$entry.PrincipalId]
    if (-not $principal) { continue }
    switch ($principal.'@odata.type') {
        '#microsoft.graph.user' {
            Add-ToListMap $rolesByUser $entry.PrincipalId ([PSCustomObject]@{
                Kind = $entry.Kind; Role = $entry.Role; RoleId = $entry.RoleId; Privileged = $entry.Privileged; BuiltIn = $entry.BuiltIn; Type = $entry.Type
                Assignment = $entry.Assignment; Via = 'Direct'; ViaGroupId = ''; GroupRoleAssignable = $false
                Scope = $entry.Scope; ScopeId = $entry.ScopeId; ScopeKind = $entry.ScopeKind; ScopeType = $entry.ScopeType; ScopeName = $entry.ScopeName; Ends = $entry.Ends
            })
        }
        '#microsoft.graph.group' {
            foreach ($path in @($groupPaths[$entry.PrincipalId])) {
                if (-not $path) { continue }
                # Eligible group membership makes the role eligible; ownership is a path to the role, not the role itself
                $type = if ($path.Path -like '*owner') { 'Owner' } elseif ($path.Path -eq 'eligible member') { 'Eligible' } else { $entry.Type }
                $via = "Group: $($principal.displayName)" + $(if ($path.Path -ne 'member') { " ($($path.Path))" } else { '' })
                Add-ToListMap $rolesByUser $path.UserId ([PSCustomObject]@{
                    Kind = $entry.Kind; Role = $entry.Role; RoleId = $entry.RoleId; Privileged = $entry.Privileged; BuiltIn = $entry.BuiltIn; Type = $type
                    Assignment = $(if ($type -eq 'Active') { $entry.Assignment } else { '' }); Via = $via; ViaGroupId = $entry.PrincipalId
                    GroupRoleAssignable = [bool]$principal.isAssignableToRole
                    Scope = $entry.Scope; ScopeId = $entry.ScopeId; ScopeKind = $entry.ScopeKind; ScopeType = $entry.ScopeType; ScopeName = $entry.ScopeName; Ends = $(if ($path.Ends) { $path.Ends } else { $entry.Ends })
                })
            }
        }
    }
}

# Read the administrator accounts through $batch. signInActivity needs Entra ID P1/P2 and AuditLog.Read.All;
# when the tenant can't return it, the accounts are read again without it.
$adminIds = @($rolesByUser.Keys)
Write-Host "Reading $($adminIds.Count) administrator account(s)..." -ForegroundColor Green
$rawUsers = @{}
foreach ($select in $(if ($script:caBaseline) { @("$userSelectBase,signInActivity", $userSelectBase) } else { @($userSelectBase) })) {
    if ($adminIds.Count -eq 0) { break }
    $userRequests = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($id in $adminIds) { $userRequests.Add(@{ id = "u_$id"; url = "/users/$($id)?`$select=$select" }) }
    $userResults = Invoke-GraphBatch -Requests $userRequests -Label 'administrator accounts'
    $forbidden = @($userResults.Values | Where-Object { [int]$_.status -eq 403 }).Count
    if ($forbidden -gt 0 -and $select -like '*signInActivity*') {
        Write-Warning "Sign-in activity is not available. Reading it requires an Entra ID P1/P2 license and AuditLog.Read.All. Continuing without sign-in data."
        $script:signInDataAvailable = $false
        continue
    }
    foreach ($result in $userResults.Values) {
        # A 404 is a principal that is not a user (e.g. a service principal that owns a group)
        if ([int]$result.status -eq 200) { $rawUsers[[string]$result.body.id] = $result.body }
        elseif ([int]$result.status -ne 404) { Write-Warning "Could not read user '$($result.id.Substring(2))' (HTTP $($result.status))." }
    }
    break
}

# License names: subscribedSkus maps SKU and service plan IDs to their names
$skuNamesById = @{}
$planNamesById = @{}
$skuPlanIdsById = @{}
try {
    foreach ($sku in (Get-GraphCollection 'v1.0/subscribedSkus')) {
        $skuNamesById[[string]$sku.skuId] = [string]$sku.skuPartNumber
        $skuPlanIdsById[[string]$sku.skuId] = @(@($sku.servicePlans) | Where-Object { $_ } | ForEach-Object { [string]$_.servicePlanId })
        foreach ($plan in @($sku.servicePlans)) { if ($plan) { $planNamesById[[string]$plan.servicePlanId] = [string]$plan.servicePlanName } }
    }
}
catch {
    Write-Warning "Could not read the tenant's license list ($($_.Exception.Message)). License names will be shown as IDs and mailbox detection is limited."
}

# Authentication methods: the registration report, one request per administrator
$authResults = @{}
if ($script:authDataAvailable -and $rawUsers.Count -gt 0) {
    Write-Host "Reading authentication methods..." -ForegroundColor Green
    $authRequests = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($id in $rawUsers.Keys) {
        $authRequests.Add(@{ id = "r_$id"; url = "/reports/authenticationMethods/userRegistrationDetails/$id" })
    }
    $authResults = Invoke-GraphBatch -Requests $authRequests -Label 'authentication methods'
    if (@($authResults.Keys | Where-Object { $_ -like 'r_*' -and [int]$authResults[$_].status -eq 200 }).Count -eq 0) {
        $script:authDataAvailable = $false
        Write-Warning "Authentication method registration could not be read. It requires an Entra ID P1/P2 license and AuditLog.Read.All."
    }
}

# Access protection: security defaults for every baseline; with P1 or P2 also the Conditional Access policies, authentication
# strengths, named locations and the administrators' group memberships
$caPolicies = @()
$memberOfResults = @{}
Write-Host $(if ($script:caBaseline) { 'Reading Conditional Access policies...' } else { 'Reading security defaults...' }) -ForegroundColor Green
try {
    if ($script:caBaseline) {
        $strengthsById = @{}
        try {
            foreach ($strength in (Get-GraphCollection 'v1.0/identity/conditionalAccess/authenticationStrength/policies')) { $strengthsById[[string]$strength.id] = $strength }
        }
        catch { Write-Verbose "Authentication strength policies could not be read: $($_.Exception.Message)" }
        # Named locations: an excluded location tells whether a block policy restricts access to an IP range, a country
        # or the Global Secure Access compliant network
        $namedLocationsById = @{}
        try {
            foreach ($location in (Get-GraphCollection 'v1.0/identity/conditionalAccess/namedLocations')) {
                $locationType = switch ([string]$location.'@odata.type') {
                    '#microsoft.graph.ipNamedLocation' { 'ip' }
                    '#microsoft.graph.countryNamedLocation' { 'country' }
                    '#microsoft.graph.compliantNetworkNamedLocation' { 'gsa' }
                    default { 'other' }
                }
                $namedLocationsById[[string]$location.id] = @{ Name = [string]$location.displayName; Type = $locationType }
            }
        }
        catch { Write-Verbose "Named locations could not be read: $($_.Exception.Message)" }
        $caPolicies = @(Get-GraphCollection 'v1.0/identity/conditionalAccess/policies' | Where-Object { $_.state -ne 'disabled' } | ForEach-Object { Get-CaPolicySummary $_ $strengthsById $namedLocationsById })
    }
    try {
        $script:securityDefaults = [bool](Invoke-MgWithRetry { Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -ErrorAction Stop }).isEnabled
        $script:securityDefaultsKnown = $true
    }
    catch { Write-Verbose "Security defaults state could not be read: $($_.Exception.Message)" }
    # Security defaults and enabled Conditional Access policies cannot both be active: when the data shows both, the Conditional Access logic wins
    $script:enabledCaPolicyCount = @($caPolicies | Where-Object { $_.State -eq 'enabled' }).Count
    $script:sdEffective = $script:securityDefaultsKnown -and $script:securityDefaults -and $script:enabledCaPolicyCount -eq 0
    $script:sdConflict = $script:securityDefaultsKnown -and $script:securityDefaults -and $script:enabledCaPolicyCount -gt 0
    if ($script:caBaseline -and $rawUsers.Count -gt 0) {
        $memberOfRequests = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($id in $rawUsers.Keys) {
            $memberOfRequests.Add(@{ id = "tg_$id"; url = "/users/$id/transitiveMemberOf/microsoft.graph.group?`$count=true&`$select=id&`$top=999"; headers = $eventualHeaders })
        }
        $memberOfResults = Invoke-GraphBatch -Requests $memberOfRequests -Label 'group memberships'
    }
    if ($script:caBaseline) { Write-Host "  Found $($caPolicies.Count) enabled or report-only Conditional Access policies" -ForegroundColor Cyan }
}
catch {
    $script:caDataAvailable = $false
    Write-Warning "Could not read the access protection data ($($_.Exception.Message)). Access protection will not be reported."
}
Write-Host "`nProceeding with analysis..." -ForegroundColor Green

$now = [DateTime]::UtcNow
$report = [System.Collections.Generic.List[object]]::new()
$severityRank = @{ high = 3; medium = 2; low = 1; info = 0 }

foreach ($u in $rawUsers.Values) {
    $roles = @($rolesByUser[[string]$u.id] | Sort-Object Kind, Role, Type, Via, Scope, ScopeId -Unique)
    $entraRoles = @($roles | Where-Object { $_.Kind -eq 'Entra' })

    # Sign-in activity: lastSuccessfulSignInDateTime is authoritative; older activity falls back to
    # the last sign-in attempt, which may have failed (flagged as approximate).
    $signIn             = $u.signInActivity
    $lastSuccess        = ConvertTo-UtcDateTime $signIn.lastSuccessfulSignInDateTime
    $lastInteractive    = ConvertTo-UtcDateTime $signIn.lastSignInDateTime
    $lastNonInteractive = ConvertTo-UtcDateTime $signIn.lastNonInteractiveSignInDateTime
    $lastActivity = $lastSuccess
    $isApproximate = $false
    if (-not $lastActivity) {
        $lastActivity = @($lastInteractive, $lastNonInteractive) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
        $isApproximate = [bool]$lastActivity
    }
    $daysSinceActivity = Get-DaysSince $lastActivity $now
    $activityBucket = if (-not $script:caBaseline) { 'notassessed' }
                      elseif (-not $script:signInDataAvailable) { 'unknown' }
                      elseif (-not $lastActivity) { 'never' }
                      elseif ($daysSinceActivity -lt $InactiveDays) { 'active' }
                      else { 'inactive' }

    # Licenses: SKUs for display, enabled service plans to spot a mailbox or daily-use workloads
    $skus = @(@($u.assignedLicenses) | Where-Object { $_ } | ForEach-Object { if ($skuNamesById.ContainsKey([string]$_.skuId)) { $skuNamesById[[string]$_.skuId] } else { [string]$_.skuId } } | Sort-Object -Unique)
    $enabledPlans = @(@($u.assignedPlans) | Where-Object { $_ -and $_.capabilityStatus -eq 'Enabled' })
    $planNames = @($enabledPlans | ForEach-Object { $planNamesById[[string]$_.servicePlanId] } | Where-Object { $_ } | Sort-Object -Unique)
    $mailboxPlans = @($planNames | Where-Object { $_ -like 'EXCHANGE_S_*' -and $_ -ne 'EXCHANGE_S_FOUNDATION' })
    $productivityPlans = @($planNames | Where-Object { $_ -match '^(TEAMS1|TEAMS_|SHAREPOINT(STANDARD|ENTERPRISE|DESKLESS)|OFFICESUBSCRIPTION|OFFICE_BUSINESS)' })
    # Per license: its category (mailbox > productivity > other) and the enabled service plans that caused it
    $enabledPlanIds = @($enabledPlans | ForEach-Object { [string]$_.servicePlanId })
    $licenses = @(@($u.assignedLicenses) | Where-Object { $_ } | ForEach-Object {
        $skuId = [string]$_.skuId
        $skuPlans = if ($skuPlanIdsById.ContainsKey($skuId)) { @($skuPlanIdsById[$skuId] | Where-Object { $enabledPlanIds -contains $_ } | ForEach-Object { $planNamesById[$_] } | Where-Object { $_ }) } else { @() }
        $cat = if (@($skuPlans | Where-Object { (Get-PlanCategory $_) -eq 'mailbox' }).Count -gt 0) { 'mailbox' } elseif (@($skuPlans | Where-Object { (Get-PlanCategory $_) -eq 'productivity' }).Count -gt 0) { 'productivity' } else { 'other' }
        [PSCustomObject]@{
            Sku      = $(if ($skuNamesById.ContainsKey($skuId)) { $skuNamesById[$skuId] } else { $skuId })
            Category = $cat
            Flagged  = @($skuPlans | Where-Object { (Get-PlanCategory $_) -in @('mailbox', 'productivity') } | Sort-Object -Unique | ForEach-Object { Get-PlanFriendlyName $_ })
        }
    } | Sort-Object Sku)
    $licenseKey = if ($mailboxPlans.Count -gt 0) { 'mailbox' } elseif ($productivityPlans.Count -gt 0) { 'productivity' } elseif ($skus.Count -gt 0) { 'other' } else { 'none' }

    # Authentication methods
    $authCollected = $script:authDataAvailable
    $methods = @(); $weakMethods = @(); $authKey = 'nc'; $authLabel = ''; $registration = $null
    $guestInfo = Get-GuestIdentityInfo $u
    $guestDomain = ''; $guestTrust = ''; $guestTrustSource = ''; $weakFallback = @(); $methodGroups = @{ pr = @(); pwl = @(); mfa = @() }
    if ($authCollected) {
        $registrationResponse = $authResults["r_$($u.id)"]
        if ($registrationResponse -and [int]$registrationResponse.status -eq 200) { $registration = $registrationResponse.body }
        $methods = @(@($registration.methodsRegistered) | Where-Object { $_ })
        $weakMethods = @($methods | Where-Object { $_ -match '^(mobilePhone|alternateMobilePhone|sms|officePhone)$' })
        $strength = Get-AuthStrength $methods
        $authKey = if (-not $registration) { 'unknown' } else { $strength.Key }
        $authLabel = if ($authKey -in @('unknown', 'sf')) { '' } else { $strength.Label }
        # An Entra guest without a registered method may bring MFA from its home tenant. Other guests (Google, Email OTP, ...) do MFA here
        # and are assessed like members.
        if ($guestInfo -and $guestInfo.Kind -eq 'entra') {
            $guestDomain = Get-GuestDomain $u
            if ($script:caBaseline -and $script:caDataAvailable) {
                $trust = Get-GuestMfaTrust $guestDomain
                $guestTrust = $trust.Result; $guestTrustSource = $trust.Source
            }
            # Trusted home tenant MFA wins. Otherwise the registered methods decide; without any, the trust result (or its absence) does.
            if ($guestTrust -eq 'accepted') { $authKey = 'trusted' }
            elseif ($authKey -in @('unknown', 'sf')) { $authKey = if ($guestTrust -eq 'rejected') { 'sf' } else { 'unknown' } }
        }
        if ($authKey -in @('pr', 'pwl', 'mfa')) { $weakFallback = @(Get-WeakFallbackLabels $methods $strength.Label) }
        $methodGroups = Get-MethodGroups $methods
    }

    $activeRoleIds = @($entraRoles | Where-Object { $_.Type -eq 'Active' } | ForEach-Object { $_.RoleId } | Sort-Object -Unique)
    $admin = [PSCustomObject]@{
        Id                        = [string]$u.id
        DisplayName               = [string]$u.displayName
        UserPrincipalName         = [string]$u.userPrincipalName
        Mail                      = [string]$u.mail
        OtherMails                = @(@($u.otherMails) | Where-Object { $_ })
        UserType                  = if ($u.userType -eq 'Guest' -or $u.userPrincipalName -like '*#EXT#*') { 'guest' } else { 'member' }
        Created                   = ConvertTo-UtcDateTime $u.createdDateTime
        AccountEnabled            = [bool]$u.accountEnabled
        OnPremisesSynced          = [bool]$u.onPremisesSyncEnabled
        LastSuccessfulSignIn      = $lastSuccess
        LastInteractiveSignIn     = $lastInteractive
        LastNonInteractiveSignIn  = $lastNonInteractive
        LastActivity              = $lastActivity
        LastActivityIsApproximate = $isApproximate
        DaysSinceActivity         = $daysSinceActivity
        ActivityBucket            = $activityBucket
        Roles                     = $roles
        ActiveRoleIds             = $activeRoleIds
        EligibleRoleIds           = @($entraRoles | Where-Object { $_.Type -eq 'Eligible' } | ForEach-Object { $_.RoleId } | Sort-Object -Unique)
        GroupIds                  = @()
        Skus                      = $skus
        MailboxPlans              = $mailboxPlans
        ProductivityPlans         = $productivityPlans
        LicenseKey                = $licenseKey
        MailboxPlanLabels         = @($mailboxPlans | ForEach-Object { Get-PlanFriendlyName $_ })
        ProductivityPlanLabels    = @($productivityPlans | ForEach-Object { Get-PlanFriendlyName $_ })
        Licenses                  = $licenses
        AuthCollected             = $authCollected
        AuthKey                   = $authKey
        AuthLabel                 = $authLabel
        Methods                   = $methods
        WeakMethods               = $weakMethods
        WeakFallback              = $weakFallback
        MethodGroups              = $methodGroups
        GuestKind                 = $(if ($guestInfo) { $guestInfo.Kind } else { '' })
        GuestProvider             = $(if ($guestInfo) { $guestInfo.Short } else { '' })
        GuestProviderLong         = $(if ($guestInfo) { $guestInfo.Long } else { '' })
        GuestDomain               = $guestDomain
        GuestTrust                = $guestTrust
        GuestTrustSource          = $guestTrustSource
        Registration              = $registration
        CaCollected               = $script:caDataAvailable
        CaKey                     = 'nc'
        DeviceKey                 = 'nc'
        DeviceLabel               = ''
        LocKey                    = 'nc'
        LocLabel                  = ''
        SifKey                    = 'nc'
        SifHours                  = $null
        CaPolicies                = @()
        IsBreakGlass              = ($BreakGlassAccounts -contains [string]$u.userPrincipalName) -or ($BreakGlassAccounts -contains [string]$u.id)
        LikelyBreakGlass          = $false
        SyncAccount               = ''
        SyncSignals               = @()
        Findings                  = $null
        Severity                  = 'ok'
    }

    # Conditional Access coverage: the strongest requirement among the enabled policies that target this account
    if ($admin.CaCollected) {
        if ($script:caBaseline) { $admin.GroupIds = @((Get-BatchItems $memberOfResults["tg_$($u.id)"] -Headers $eventualHeaders).Items | ForEach-Object { [string]$_.id }) }
        $evaluated = foreach ($policy in $caPolicies) {
            $test = Test-CaPolicyForAdmin $policy $admin
            if ($test.Result -eq 'no') { continue }
            [PSCustomObject]@{
                Name = $policy.Name; State = $policy.State; Requirement = $policy.Requirement; RequirementLabel = $policy.RequirementLabel
                Full = ($policy.AllResources -and $policy.Narrowed.Count -eq 0); ScopeLabel = $policy.ScopeLabel; ScopeDetail = $policy.ScopeDetail; Narrowed = $policy.Narrowed
                OtherControls = $policy.OtherControls; Result = $test.Result; Why = $test.Why
                AllResources = $policy.AllResources; DeviceMode = $policy.DeviceMode; DeviceLabel = $policy.DeviceLabel
                LocationKind = $policy.LocationKind; LocationLabels = $policy.LocationLabels; SifHours = $policy.SifHours; NarrowedOther = $policy.NarrowedOther
            }
        }
        $admin.CaPolicies = @($evaluated)
        $enforcedMfa = @($admin.CaPolicies | Where-Object { $_.State -eq 'enabled' -and $_.Result -eq 'yes' -and $_.Requirement -in @('pr', 'mfa') })
        $onActivation = @($admin.CaPolicies | Where-Object { $_.State -eq 'enabled' -and $_.Result -eq 'activation' -and $_.Requirement -in @('pr', 'mfa') })
        $admin.CaKey = if (@($enforcedMfa | Where-Object { $_.Full -and $_.Requirement -eq 'pr' }).Count -gt 0) { 'pr' }
                       elseif (@($enforcedMfa | Where-Object { $_.Full }).Count -gt 0 -or $script:sdEffective) { 'mfa' }
                       elseif ($enforcedMfa.Count -gt 0) { 'partial' }
                       elseif ($onActivation.Count -gt 0) { 'activation' }
                       else { 'none' }
        # For an emergency access account, no enforced policy is the intended state
        if ($admin.IsBreakGlass -and @($admin.CaPolicies | Where-Object { $_.State -eq 'enabled' -and $_.Result -eq 'yes' }).Count -eq 0) { $admin.CaKey = 'excluded' }

        # Trusted device, trusted location and sign-in frequency: what the enabled, all-resources policies that apply add.
        # Emergency access accounts are meant to be left out of these policies.
        if ($admin.IsBreakGlass) { $admin.DeviceKey = 'na'; $admin.LocKey = 'na'; $admin.SifKey = 'na' }
        else {
            $applying = @($admin.CaPolicies | Where-Object { $_.State -eq 'enabled' -and $_.Result -eq 'yes' -and $_.AllResources })
            $devicePolicies = @($applying | Where-Object { $_.DeviceMode -eq 'required' -and $_.Narrowed.Count -eq 0 })
            $admin.DeviceKey = if ($devicePolicies.Count -gt 0) { 'device' } elseif (@($applying | Where-Object { $_.DeviceMode -eq 'optional' }).Count -gt 0) { 'optional' } else { 'none' }
            $admin.DeviceLabel = (@($devicePolicies | ForEach-Object { $_.DeviceLabel }) | Sort-Object -Unique) -join ', '
            $locationRank = @{ gsa = 4; ip = 3; country = 2; other = 1 }
            $bestLocation = @($applying | Where-Object { $_.LocationKind -ne 'none' -and $_.NarrowedOther.Count -eq 0 } | Sort-Object @{ Expression = { $locationRank[$_.LocationKind] }; Descending = $true }) | Select-Object -First 1
            $admin.LocKey = if ($bestLocation) { $bestLocation.LocationKind } else { 'none' }
            $admin.LocLabel = if ($bestLocation) { $bestLocation.LocationLabels -join ', ' } else { '' }
            $frequencies = @($applying | Where-Object { $null -ne $_.SifHours -and $_.Narrowed.Count -eq 0 } | ForEach-Object { $_.SifHours })
            if ($frequencies.Count -gt 0) {
                $admin.SifHours = ($frequencies | Measure-Object -Minimum).Minimum
                $admin.SifKey = if ($admin.SifHours -le $MaxSignInFrequencyHours) { 'ok' } else { 'long' }
            }
            else { $admin.SifKey = 'none' }
        }
    }

    # Break-glass hint: cloud-only, *.onmicrosoft.com, permanent Global Administrator assigned directly,
    # and (when Conditional Access was reviewed) no enabled policy applies
    if (-not $admin.IsBreakGlass -and -not $admin.OnPremisesSynced -and $admin.UserPrincipalName -like '*.onmicrosoft.com' -and $admin.UserType -eq 'member') {
        $permanentGa = @($entraRoles | Where-Object { $_.RoleId -eq $GlobalAdminRoleId -and $_.Type -eq 'Active' -and $_.Via -eq 'Direct' -and $_.Assignment -in @('Permanent', 'Active') })
        $enforcedPolicies = @($admin.CaPolicies | Where-Object { $_.State -eq 'enabled' -and $_.Result -eq 'yes' })
        $admin.LikelyBreakGlass = $permanentGa.Count -gt 0 -and $admin.LicenseKey -ne 'mailbox' -and (-not $admin.CaCollected -or ($caPolicies.Count -gt 0 -and $enforcedPolicies.Count -eq 0))
    }

    # Entra Connect sync account: holds the Directory Synchronization Accounts role. It is a connector account when it
    # also looks like one (default display name or Sync_ user principal name) and holds the role directly and actively.
    # Any other holder is unexpected, because the role is only meant for the Connect service.
    $syncRoles = @($entraRoles | Where-Object { $_.RoleId -eq $SyncRoleId -or $_.Role -eq $SyncRoleName })
    if ($syncRoles.Count -gt 0) {
        $looksLikeConnector = ($admin.DisplayName -eq $SyncDefaultDisplayName) -or ($admin.UserPrincipalName -like 'Sync_*')
        $directActive = @($syncRoles | Where-Object { $_.Type -eq 'Active' -and $_.Via -eq 'Direct' }).Count -gt 0
        $admin.SyncAccount = if ($looksLikeConnector -and $directActive) { 'connector' } else { 'unexpected' }
        $signals = [System.Collections.Generic.List[string]]::new()
        if (-not $looksLikeConnector) { $signals.Add("display name and user principal name are not the Connect defaults ('$SyncDefaultDisplayName', 'Sync_...')") }
        if (-not $directActive) { $signals.Add('the role is not assigned directly and actively (' + ((@($syncRoles | ForEach-Object { if ($_.Type -eq 'Active') { $_.Via } else { "$($_.Type), $($_.Via)" } }) | Sort-Object -Unique) -join '; ') + ')') }
        if ($admin.UserType -eq 'guest') { $signals.Add('it is a guest account') }
        if ($admin.OnPremisesSynced -and -not $looksLikeConnector) { $signals.Add('it is synchronized from on-premises Active Directory') }
        if ($admin.Skus.Count -gt 0 -and -not $looksLikeConnector) { $signals.Add('it has a license') }
        if ($admin.Methods.Count -gt 0 -and -not $looksLikeConnector) { $signals.Add('it has authentication methods registered') }
        if ($admin.LastInteractiveSignIn -and -not $looksLikeConnector) { $signals.Add("an interactive sign-in is recorded ($(Format-ReportDate $admin.LastInteractiveSignIn))") }
        $admin.SyncSignals = @($signals)
    }

    $admin.Findings = @(Get-AdminAssessment $admin | Sort-Object @{ Expression = { $severityRank[$_.Level] }; Descending = $true })
    $top = @($admin.Findings | Where-Object { $_.Level -ne 'info' } | Select-Object -First 1)
    if ($top.Count -gt 0) { $admin.Severity = $top[0].Level }
    $report.Add($admin)
}

Write-Host "Final report contains $($report.Count) administrator accounts" -ForegroundColor Green

# Calculate summary statistics
# Note: wrap pipelines in @(...) so .Count is reliable in Windows PowerShell 5.1
$totalAdmins     = @($report).Count
$highCount       = @($report | Where-Object { $_.Severity -eq 'high' }).Count
$mediumCount     = @($report | Where-Object { $_.Severity -eq 'medium' }).Count
$lowCount        = @($report | Where-Object { $_.Severity -eq 'low' }).Count
$okCount         = @($report | Where-Object { $_.Severity -eq 'ok' }).Count
$globalAdmins    = @($report | Where-Object { @($_.Roles | Where-Object { $_.RoleId -eq $GlobalAdminRoleId -and $_.Type -in @('Active', 'Eligible') }).Count -gt 0 })
$globalAdminCount = $globalAdmins.Count
# Entra Connect connector accounts are service accounts: they are left out of the signals about human administrators
$humanReport     = @($report | Where-Object { $_.SyncAccount -ne 'connector' })
$connectorCount  = @($report | Where-Object { $_.SyncAccount -eq 'connector' }).Count
$unexpectedSyncCount = @($report | Where-Object { $_.SyncAccount -eq 'unexpected' }).Count
$onPremCount     = @($humanReport | Where-Object { $_.OnPremisesSynced }).Count
$standingCount   = @($humanReport | Where-Object { -not $_.IsBreakGlass -and @($_.Roles | Where-Object { $_.Kind -eq 'Entra' -and $_.Privileged -and $_.ScopeKind -eq 'tenant' -and $_.Type -eq 'Active' -and $_.Assignment -ne 'Activated (PIM)' }).Count -gt 0 }).Count
$mailboxCount    = @($humanReport | Where-Object { $_.LicenseKey -eq 'mailbox' }).Count
$inactiveCount   = @($humanReport | Where-Object { $_.ActivityBucket -in @('inactive', 'never') }).Count
$breakGlassCount = @($report | Where-Object { $_.IsBreakGlass }).Count
$likelyBreakGlassCount = @($report | Where-Object { $_.LikelyBreakGlass }).Count
$noPhishingResistantCount = @($humanReport | Where-Object { $_.AuthCollected -and $_.AuthKey -in @('pwl', 'mfa', 'sf') }).Count
# No compliant or hybrid joined device and no trusted IP or compliant network required (break-glass accounts are meant to be excluded)
foreach ($r in $report) { $r | Add-Member -NotePropertyName AccessKey -NotePropertyValue (Get-AccessVerdictKey $r) -Force }
# Privileged role assignments as Microsoft Entra counts them: one per assignment, groups counted once
$privilegedAssignmentCount = @($rawEntries | Where-Object { $_.Kind -eq 'Entra' -and $_.Privileged -and $_.ScopeKind -eq 'tenant' -and $_.Type -eq 'Active' -and $_.RoleId -ne $SyncRoleId }).Count
# Privileged assignments limited to an administrative unit or object are not counted against the limit
$scopedPrivilegedAssignmentCount = @($rawEntries | Where-Object { $_.Kind -eq 'Entra' -and $_.Privileged -and $_.ScopeKind -ne 'tenant' -and $_.Type -eq 'Active' -and $_.RoleId -ne $SyncRoleId }).Count
$unmatchedBreakGlass = @($BreakGlassAccounts | Where-Object { $name = $_; @($report | Where-Object { $_.UserPrincipalName -eq $name -or $_.Id -eq $name }).Count -eq 0 })
foreach ($name in $unmatchedBreakGlass) { Write-Warning "-BreakGlassAccounts: '$name' was not found among the administrator accounts (no role assignment, or the name does not match)." }

# Tenant-level findings (Microsoft Learn: best practices for Microsoft Entra roles, emergency access accounts)
$tenantFindings = [System.Collections.Generic.List[object]]::new()
$gaText = "Global Administrators ($(if ($script:pimBaseline) { 'active or eligible' } else { 'active' })): $globalAdminCount, recommended: fewer than $GlobalAdminLimit"
$tenantFindings.Add((New-Reason $(if ($globalAdminCount -ge $GlobalAdminLimit) { 'medium' } else { 'ok' }) $gaText -Filter 'access:ga'))
$scopedDetail = if ($scopedPrivilegedAssignmentCount -gt 0) { "$scopedPrivilegedAssignmentCount more privileged assignments limited to an administrative unit or object are not counted." } else { '' }
$tenantFindings.Add((New-Reason $(if ($privilegedAssignmentCount -ge $PrivilegedAssignmentLimit) { 'medium' } else { 'ok' }) "Active privileged role assignments: $privilegedAssignmentCount (recommended: fewer than $PrivilegedAssignmentLimit)" -Detail $scopedDetail -Filter $(if ($script:pimBaseline) { 'access:standing' } else { '' })))
# Entra Connect sync accounts: Entra ID allows 20, each Connect server (including staging) has its own, unused ones should be removed
if ($connectorCount -gt 0) {
    $staleSync = @($report | Where-Object { $_.SyncAccount -eq 'connector' -and ($_.ActivityBucket -in @('inactive', 'never') -or -not $_.AccountEnabled) }).Count
    $syncDetail = "Limit: $SyncAccountLimit sync accounts per tenant, one per Connect server including staging servers."
    if ($staleSync -gt 0) { $tenantFindings.Add((New-Reason 'low' "Entra Connect sync accounts: $connectorCount. $staleSync without a recent sign-in or disabled, remove the ones no Connect server uses." -Detail $syncDetail -Filter 'sync:connector')) }
    else { $tenantFindings.Add((New-Reason 'ok' "Entra Connect sync accounts: $connectorCount." -Detail $syncDetail -Filter 'sync:connector')) }
}
# Notification addresses: Microsoft recommends at least two Global Administrators with an Email or Alternate email
$gaWithEmail = @($globalAdmins | Where-Object { $_.SyncAccount -ne 'connector' -and ($_.Mail -or $_.OtherMails.Count -gt 0) }).Count
$gaHuman = @($globalAdmins | Where-Object { $_.SyncAccount -ne 'connector' }).Count
if ($gaHuman -gt 0) {
    $emailDetail = "$gaWithEmail of $gaHuman Global Administrators have an Email or Alternate email. Microsoft recommends that notification addresses exist for at least two Global Administrators, so notifications are not lost if one account or mailbox is unavailable. Set the Email attribute (for example a plus address of the owner's personal mailbox) on more Global Administrator accounts."
    $tenantFindings.Add((New-Reason $(if ($gaWithEmail -lt 2) { 'medium' } else { 'ok' }) "Global Administrators with an Email or Alternate email: $gaWithEmail (recommended: at least two)" -Detail $emailDetail -Filter 'access:ga'))
}
if ($unexpectedSyncCount -gt 0) { $tenantFindings.Add((New-Reason 'high' "Accounts with the $SyncRoleName role that do not look like Connect accounts: $unexpectedSyncCount. The role is only for the Connect service." -Filter 'sync:unexpected')) }
if ($breakGlassCount -ge 2) { $tenantFindings.Add((New-Reason 'ok' "Emergency access accounts identified: $breakGlassCount (recommended: at least two)" -Filter 'bg:yes')) }
elseif ($breakGlassCount -eq 1) { $tenantFindings.Add((New-Reason 'medium' 'Only one emergency access account identified. Microsoft recommends at least two' -Filter 'bg:yes')) }
else { $tenantFindings.Add((New-Reason 'info' "No emergency access accounts were passed with -BreakGlassAccounts, so the emergency access checks were skipped$(if ($likelyBreakGlassCount -gt 0) { ". Break-glass accounts detected: $likelyBreakGlassCount. Pass them with -BreakGlassAccounts" })")) }
# License-aware access protection: what the tenant can enforce (Conditional Access needs Entra ID P1 or P2) and whether security defaults are on
$tenantAccessBanner = ''
$caAvailCsv = if ($script:caBaseline) { 'Yes' } else { 'No' }
$sdCsv = if (-not $script:caDataAvailable -or -not $script:securityDefaultsKnown) { 'Unknown' } elseif ($script:securityDefaults) { 'Yes' } else { 'No' }
if ($script:caDataAvailable -and $script:securityDefaultsKnown) {
    $bannerKind = $null
    if (-not $script:caBaseline -and $script:sdEffective) {
        $bannerKind = 'blue'; $bannerText = 'Security defaults are the MFA baseline of this assessment (Free). Conditional Access, device and location requirements are not assessed.'

    }
    elseif (-not $script:caBaseline -and -not $script:securityDefaults) {
        $bannerKind = 'red'; $bannerText = 'Security defaults are disabled and the Free baseline does not assess Conditional Access. No baseline MFA enforcement is active.'
        $tenantFindings.Add((New-Reason 'high' 'No baseline MFA enforcement is active. Security defaults are disabled. Enable security defaults'))
    }
    elseif ($script:caBaseline -and $script:sdEffective) {
        $bannerKind = 'gray'; $bannerText = 'Security defaults are enabled and no Conditional Access policy is in use.'
        $tenantFindings.Add((New-Reason 'info' $bannerText))
    }
    if ($bannerKind) { $tenantAccessBanner = "<div class='modal-banner $bannerKind page-banner'><span class='modal-dot'></span><span>$bannerText</span></div>" }
}
if (-not $script:pimBaseline) { $tenantFindings.Add((New-Reason 'info' 'Privileged Identity Management is not part of the assessment baseline. Role assignments are shown as assigned.')) }
if ($script:sdConflict) { $tenantAccessBanner += '<!-- debug: security defaults are reported as enabled while Conditional Access policies are enabled; the Conditional Access logic was used -->' }

if (-not $OutputPath) {
    $safeName = $tenantName -replace '[^\w]', '_'
    $OutputPath = "EntraIDAdminReport_${safeName}_$(Get-Date -Format 'yyyy-MM-dd').html"
}

# Resolve a relative output path against the current PowerShell location.
# .NET file APIs (WriteAllText / Path.GetFullPath) resolve relative paths against
# [Environment]::CurrentDirectory (the process start directory, e.g. C:\Windows\System32
# for elevated shells), NOT PowerShell's $PWD. Making the path absolute here ensures the
# report is written where the user expects - next to their current location.
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path (Get-Location).Path $OutputPath
}

# Ensure output directory exists
$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Cyan
}

# Verify the output path is writable before spending time on HTML generation
$_writeTestDir  = if ($outputDir) { $outputDir } else { '.' }
$_writeTestFile = Join-Path $_writeTestDir ([System.IO.Path]::GetRandomFileName())
try {
    [System.IO.File]::WriteAllText($_writeTestFile, '')
    Remove-Item $_writeTestFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Error "Output path '$OutputPath' is not writable: $($_.Exception.Message)"
    exit 1
}

# Generate HTML report
$sb = [System.Text.StringBuilder]::new()

[void]$sb.Append(@'
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra ID Administrator Report</title>
    <style>
        /* -- Light Theme Variables -- */
        :root {
            --blue:        #0078d4;
            --blue-dark:   #005a9e;
            --blue-light:  #cce4f6;
            --blue-xs:     #f0f6fc;
            --text:        #1a1a1a;
            --text-muted:  #595959;
            --gray:        #666;
            --gray-dark:   #444;
            --bg-page:     #edf2f7;
            --bg-panel:    #ffffff;
            --bg-header:   #0078d4;
            --bg-input:    #ffffff;
            --bg-subtle:   #f7fafc;
            --border:      #ddd;
            --border-row:  #e2e8f0;
            --shadow:      0 2px 10px rgba(0,0,0,0.08);
            --radius:      8px;

            --rec-remove-bg:   #fed7d7;
            --rec-remove-text: #9b2c2c;
            --rec-review-bg:   #fefcbf;
            --rec-review-text: #8a5a00;
            --rec-keep-bg:     #c6f6d5;
            --rec-keep-text:   #276749;

            --good:          #2f855a;
            --bad:           #c53030;
            --warn:          #8a5a00;
            --pill-warn-text:   #7d5200;
            --pill-none-border: #9ca3af;
            --pill-none-text:   #4b5563;
        }

        /* -- Dark Theme Variables -- */
        [data-theme="dark"] {
            --blue:        #3aa0f3;
            --blue-dark:   #2b8fd4;
            --blue-light:  #1a3a55;
            --blue-xs:     #152030;
            --text:        #e2e8f0;
            --text-muted:  #9aa5b3;
            --gray:        #9aa5b3;
            --gray-dark:   #c8d0da;
            --bg-page:     #111520;
            --bg-panel:    #1c1f2e;
            --bg-header:   #0d1117;
            --bg-input:    #252840;
            --bg-subtle:   #232738;
            --border:      #343848;
            --border-row:  #2a2e3e;
            --shadow:      0 2px 12px rgba(0,0,0,0.35);

            --rec-remove-bg:   #3a1518;
            --rec-remove-text: #f98a8a;
            --rec-review-bg:   #332b0d;
            --rec-review-text: #e6c45c;
            --rec-keep-bg:     #122a1a;
            --rec-keep-text:   #6ee7a0;

            --good:          #68d391;
            --bad:           #f98a8a;
            --warn:          #e6c45c;
            --pill-warn-text:   #e6c45c;
            --pill-none-border: #7b8494;
            --pill-none-text:   #c8d0da;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            font-size: 14px;
            color: var(--text);
            background: var(--bg-page);
            min-height: 100vh;
            transition: background 0.25s, color 0.25s;
        }

        a { color: var(--blue); }

        /* -- Header -- */
        header {
            background: var(--bg-header);
            color: #fff;
            padding: 16px 32px;
            display: flex;
            align-items: center;
            gap: 16px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.3);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        header .header-text { flex: 1; }
        header h1 { font-size: 16px; font-weight: 600; letter-spacing: 0.2px; }
        header .meta { font-size: 11px; opacity: 0.75; margin-top: 1px; line-height: 1.7; }
        header .meta strong { font-weight: 600; }

        #themeToggle {
            background: rgba(255,255,255,0.12);
            border: 1px solid rgba(255,255,255,0.25);
            color: #fff;
            font-size: 17px;
            width: 36px; height: 36px;
            border-radius: 50%;
            cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            transition: background 0.2s, transform 0.2s;
            flex-shrink: 0;
            line-height: 1;
        }
        #themeToggle:hover { background: rgba(255,255,255,0.25); transform: rotate(20deg); }
        .github-link {
            background: rgba(255,255,255,0.12);
            border: 1px solid rgba(255,255,255,0.25);
            width: 36px; height: 36px;
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0;
            transition: background 0.2s, transform 0.2s;
            line-height: 0;
        }
        .github-link:hover { background: rgba(255,255,255,0.25); transform: scale(1.1); }

        /* -- Layout -- */
        .container { max-width: 1600px; margin: 24px auto; padding: 0 24px 48px; }

        /* -- Summary cards -- */
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        @media (max-width: 900px) { .summary { grid-template-columns: repeat(2, 1fr) !important; } }
        .summary-card {
            background: var(--bg-panel);
            padding: 18px 20px;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border-top: 4px solid var(--blue);
            text-align: center;
            cursor: pointer;
            transition: background 0.25s, box-shadow 0.25s, transform 0.15s;
        }
        .summary-card:hover { transform: translateY(-2px); box-shadow: 0 4px 14px rgba(0,0,0,0.12); }
        .summary-card h3 { margin: 0 0 6px; color: var(--gray-dark); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .summary-card .number { font-size: 30px; font-weight: 700; color: var(--blue); margin: 6px 0; }
        /* Number and border colors per card type */
        .summary-card.k-red .number    { color: #c50f1f; }
        .summary-card.k-amber .number  { color: #b06000; }
        .summary-card.k-green .number  { color: #107c10; }
        .summary-card.k-purple .number { color: #7054a0; }
        .summary-card.k-red    { border-top-color: #c50f1f; }
        .summary-card.k-amber  { border-top-color: #b06000; }
        .summary-card.k-green  { border-top-color: #107c10; }
        .summary-card.k-purple { border-top-color: #7054a0; }
        [data-theme="dark"] .summary-card.k-red .number    { color: #f2677a; }
        [data-theme="dark"] .summary-card.k-amber .number  { color: #e08a10; }
        [data-theme="dark"] .summary-card.k-green .number  { color: #2a9d2a; }
        [data-theme="dark"] .summary-card.k-purple .number { color: #9070c0; }
        [data-theme="dark"] .summary-card.k-red    { border-top-color: #e3223a; }
        [data-theme="dark"] .summary-card.k-amber  { border-top-color: #c87000; }
        [data-theme="dark"] .summary-card.k-green  { border-top-color: #2a9d2a; }
        [data-theme="dark"] .summary-card.k-purple { border-top-color: #9070c0; }
        .summary-card .subtitle { color: var(--text-muted); font-size: 12.5px; }

        /* -- Controls -- */
        .controls {
            background: var(--bg-panel);
            padding: 20px;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            margin-bottom: 24px;
            transition: background 0.25s, box-shadow 0.25s;
        }

        /* -- Tag filters -- */
        .filter-bar { display: flex; align-items: center; gap: 12px; margin: 4px 0 8px; }
        .filter-toggle-btn {
            display: inline-flex; align-items: center; gap: 8px;
            background: var(--bg-panel); border: 1px solid var(--border); color: var(--text);
            padding: 8px 16px; border-radius: 6px;
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s;
        }
        .filter-toggle-btn:hover { border-color: var(--blue); background: var(--blue-xs); }
        .filter-toggle-btn[aria-expanded="true"] { border-color: var(--blue); }
        .filter-toggle-btn .caret { font-size: 10px; color: var(--gray); transition: transform 0.15s; }
        .export-csv-btn {
            display: inline-flex; align-items: center; gap: 8px;
            background: var(--bg-panel); border: 1px solid var(--border); color: var(--text);
            padding: 8px 16px; border-radius: 6px;
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            cursor: pointer; margin-left: auto;
            transition: background 0.15s, border-color 0.15s;
        }
        .export-csv-btn:hover { border-color: var(--blue); background: var(--blue-xs); }
        .export-csv-btn + .export-csv-btn { margin-left: 0; }
        .filter-summary { font-size: 13px; font-weight: 600; color: var(--text); }

        .clickable-badge { cursor: pointer; transition: filter 0.15s, box-shadow 0.15s; }

        .filter-search {
            width: 100%;
            margin: 4px 0 28px;
            padding: 11px 14px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 14px;
            color: var(--text);
            background: var(--bg-input);
            transition: border-color 0.15s, box-shadow 0.15s;
        }
        .filter-search:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 2px var(--blue-light); }

        .filter-group { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
        .filter-group-label {
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            color: var(--gray); width: 130px; flex-shrink: 0;
        }
        .filter-tag {
            display: inline-flex; align-items: center; gap: 5px;
            padding: 4px 12px; border: 1px solid var(--border); border-radius: 14px;
            background: var(--bg-panel); color: var(--text); font-size: 12px; font-weight: 600;
            cursor: pointer; user-select: none;
            transition: background 0.15s, border-color 0.15s, color 0.15s;
        }
        .filter-tag:hover { border-color: var(--blue); background: var(--blue-xs); }
        .filter-tag .cnt { font-size: 10px; font-weight: 600; color: var(--text-muted); }
        .filter-tag.active { color: #fff; border-color: transparent; }
        .filter-tag.active .cnt { color: rgba(255,255,255,0.85); }

        .filter-tag.active.c-blue   { background: #0078d4; }
        .filter-tag.active.c-amber  { background: #b06000; }
        .filter-tag.active.c-red    { background: #c50f1f; }
        .filter-tag.active.c-green  { background: #107c10; }
        .filter-tag.active.c-purple { background: #7054a0; }
        .filter-tag.active.c-gray   { background: #767676; }

        .filter-results {
            display: flex; align-items: center; flex-wrap: wrap; gap: 8px;
            margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--border);
        }
        .result-count { font-size: 13px; font-weight: 600; color: var(--gray-dark); margin-right: 4px; }
        .active-chips { display: inline-flex; flex-wrap: wrap; gap: 6px; }
        .chip {
            display: inline-flex; align-items: center; gap: 4px;
            background: #0078d4; color: #fff; border: none;
            padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; cursor: pointer;
        }
        .chip.c-green  { background: #107c10; }
        .chip.c-red    { background: #c50f1f; }
        .chip.c-amber  { background: #b06000; }
        .chip.c-purple { background: #7054a0; }
        .chip.c-gray   { background: #767676; }
        .chip:hover { filter: brightness(1.15); }
        .clear-all {
            display: inline-flex; align-items: center; gap: 8px;
            background: var(--bg-panel); border: 1px solid var(--border); color: var(--text);
            padding: 8px 16px; border-radius: 6px;
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            cursor: pointer; margin-left: auto;
            transition: background 0.15s, border-color 0.15s;
        }
        .clear-all:hover { border-color: var(--blue); background: var(--blue-xs); }

        /* -- Table -- */
        .table-wrap {
            background: var(--bg-panel);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            overflow: auto;
            transition: background 0.25s, box-shadow 0.25s;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 11px 12px; text-align: left; border-bottom: 1px solid var(--border-row); vertical-align: top; }
        td { font-size: 11px; font-weight: 400; color: var(--gray-dark); letter-spacing: 0.5px; }
        th {
            background: var(--bg-subtle); font-weight: 700; cursor: pointer; user-select: none;
            position: sticky; top: 0; z-index: 1; color: var(--gray-dark);
            text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px;
        }
        th:hover { background: var(--blue-xs); }
        th.sort-asc::after  { content: ' \25B2'; font-size: 0.8em; opacity: 0.7; }
        th.sort-desc::after { content: ' \25BC'; font-size: 0.8em; opacity: 0.7; }
        tbody tr { transition: background 0.12s; }
        tbody tr:hover { background: var(--bg-subtle); }
        .csv-only { display: none; }

        /* -- Recommendation row tints -- */
        .rec-remove { background: var(--rec-remove-bg) !important; color: var(--rec-remove-text); }
        .rec-review { background: var(--rec-review-bg) !important; color: var(--rec-review-text); }
        .rec-keep   { background: var(--rec-keep-bg) !important; color: var(--rec-keep-text); }

        /* -- Badges -- */
        .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: #767676;
            color: #fff;
            font-size: 9px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            vertical-align: middle;
            text-align: center;
            line-height: 1.3;
            white-space: nowrap;
        }
        .badge.green   { background: #107c10; }
        .badge.red     { background: #c50f1f; }
        .badge.amber   { background: #b06000; }
        .badge.blue    { background: #0078d4; }
        .badge.purple  { background: #7054a0; }
        .badge.gray    { background: #767676; }


        .perm-badges { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; }

        .activity-inactive { color: var(--pill-warn-text); font-weight: 700; }
        .activity-stale    { color: #c50f1f; font-weight: 700; }
        [data-theme="dark"] .activity-stale    { color: #e3223a; }
        .activity-link { cursor: pointer; }
        .activity-link:hover { text-decoration: underline; }

        /* -- Recommendation modal -- */
        .reason-list { margin: 5px 0; padding-left: 4px; list-style: none; }
        .reason-list li { display: flex; gap: 10px; align-items: baseline; margin: 6px 0; font-size: 13px; }
        .reason-list li .badge { flex: 0 0 64px; }
        .info-banner {
            background: rgba(176, 96, 0, 0.08); border: 1px solid #b06000; border-left: 3px solid #b06000;
            border-radius: 6px; padding: 8px 12px; margin: 0 0 14px 0; font-size: 12.5px; color: var(--text-muted);
        }
        [data-theme="dark"] .info-banner {
            background: rgba(200, 112, 0, 0.14); border-color: #c87000;
        }
        .page-banner { margin-bottom: 24px; font-size: 13px; }
        .modal-note { margin-top: 12px; font-size: 12px; color: var(--text-muted); }
        .modal-note a { color: var(--blue); }
        .modal-banner { display: flex; align-items: center; gap: 10px; border-radius: 8px; padding: 10px 14px; font-size: 13px; font-weight: 600; margin: 0 0 4px 0; }
        .modal-dot { flex: 0 0 9px; width: 9px; height: 9px; border-radius: 50%; }
        .modal-banner.red   { background: var(--rec-remove-bg); color: var(--rec-remove-text); }
        .modal-banner.red .modal-dot   { background: var(--bad); }
        .modal-banner.amber { background: var(--rec-review-bg); color: var(--rec-review-text); }
        .modal-banner.amber .modal-dot { background: var(--warn); }
        .modal-banner.green { background: var(--rec-keep-bg); color: var(--rec-keep-text); }
        .modal-banner.green .modal-dot { background: var(--good); }
        .modal-banner.gray  { background: var(--bg-subtle); color: var(--gray-dark); }
        .modal-banner.gray .modal-dot  { background: var(--gray); }
        .lic-plan-mailbox { color: var(--bad); font-weight: 700; }
        .lic-plan-productivity { color: var(--warn); font-weight: 700; }
        .lic-emails { margin-top: 12px; font-size: 12px; color: var(--text-muted); word-break: break-word; }
        .modal-rec { margin-top: 14px; border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; font-size: 13px; }
        .modal-rec code { font-family: Consolas, "Courier New", monospace; font-size: 12px; }
        .badge.guest-idp { white-space: normal; text-align: left; max-width: 100%; }
        .auth-chip { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; margin: 2px 4px 2px 0; white-space: nowrap; }
        .auth-chip.green { background: var(--rec-keep-bg);   color: var(--rec-keep-text); }
        .auth-chip.amber { background: var(--rec-review-bg); color: var(--rec-review-text); }
        .auth-chip.red   { background: var(--rec-remove-bg); color: var(--rec-remove-text); }
        .auth-chip.blue  { background: var(--blue-light);    color: var(--blue-dark); }
        [data-theme="dark"] .auth-chip.blue { color: var(--blue); }
        .auth-chip.gray  { background: var(--bg-subtle);     color: var(--gray-dark); }
        .auth-group { display: flex; align-items: center; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--border-row); }
        .auth-dot { flex: 0 0 9px; width: 9px; height: 9px; border-radius: 50%; }
        .auth-dot.green { background: var(--good); } .auth-dot.blue { background: var(--blue); } .auth-dot.amber { background: var(--warn); }
        .auth-gname { flex: 0 0 140px; font-size: 13px; font-weight: 600; }
        .auth-chips { display: flex; flex-wrap: wrap; }
        .auth-label { margin: 12px 0 2px 0; font-size: 11px; color: var(--text-muted); }
        .auth-kv { display: flex; gap: 12px; padding: 7px 0; border-bottom: 1px solid var(--border-row); font-size: 13px; align-items: center; }
        .auth-k { flex: 0 0 140px; font-weight: 600; color: var(--text-muted); }
        .ap-strip { display: flex; flex-wrap: wrap; gap: 4px; }
        .ap-pill { display: inline-block; padding: 1px 7px; border-radius: 999px; background: var(--bg-panel); border: 1px solid var(--pill-none-border); font-size: 10px; font-weight: 700; white-space: nowrap; cursor: pointer; }
        .ap-pill.ok   { border-color: var(--good); color: var(--rec-keep-text); }
        .ap-pill.warn { border-color: var(--warn); color: var(--pill-warn-text); }
        .ap-pill.none { border-color: var(--pill-none-border); color: var(--pill-none-text); }
        .req-row { display: flex; gap: 12px; align-items: flex-start; padding: 10px 0; border-bottom: 1px solid var(--border-row); }
        .modal-banner.blue { background: var(--blue-light); color: var(--blue-dark); }
        [data-theme="dark"] .modal-banner.blue, [data-theme="dark"] .auth-chip.blue { color: #7cc2f8; }
        .modal-banner.blue .modal-dot { background: var(--blue); }
        .req-pill.na { background: var(--bg-subtle); color: var(--gray-dark); }
        .req-pill { flex: 0 0 100px; text-align: center; padding: 2px 0; border-radius: 999px; font-size: 11px; font-weight: 700; }
        .req-pill.met     { background: var(--rec-keep-bg);   color: var(--rec-keep-text); }
        .req-pill.weaker  { background: var(--rec-review-bg); color: var(--rec-review-text); }
        .req-pill.missing { background: var(--bg-subtle);     color: var(--gray-dark); }
        .req-label { font-size: 13px; font-weight: 600; }
        .req-detail { margin-top: 2px; font-size: 12px; color: var(--text-muted); }
        .ap-freq { margin-top: 12px; font-size: 13px; }
        .ap-amber { color: var(--warn); font-weight: 700; }
        .ap-red { color: var(--bad); font-weight: 700; }
        .ap-yes { color: var(--good); font-weight: 700; }
        .ap-details { margin-top: 14px; }
        .ap-details summary { cursor: pointer; margin-bottom: 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); list-style: none; }
        .ap-details summary::-webkit-details-marker { display: none; }
        .ap-details summary::before { content: ""; display: inline-block; width: 6px; height: 6px; margin: 0 8px 1px 2px; border-right: 2px solid currentColor; border-bottom: 2px solid currentColor; transform: rotate(-45deg); transition: transform 0.15s; }
        .ap-details[open] summary::before { transform: rotate(45deg); }

        .mono { font-family: 'Inter', sans-serif; font-size: 11px; font-weight: 400; color: var(--gray-dark); letter-spacing: 0.5px; }
        .muted { color: var(--text-muted); }
        .guest-name { font-family: 'Inter', sans-serif; font-size: 11px; font-weight: 600; color: var(--gray-dark); letter-spacing: 0.5px; text-decoration: none; }
        .guest-name:hover { text-decoration: underline; color: var(--blue); }
        .cell-sm { font-size: 11px; }

        /* -- Modal -- */
        .modal-overlay {
            display: none; position: fixed; inset: 0;
            background: rgba(0,0,0,0.55); z-index: 1000;
            align-items: center; justify-content: center;
        }
        .modal-overlay.active { display: flex; }
        .modal-box {
            position: relative;
            background: var(--bg-panel); color: var(--text);
            border: 1px solid var(--border); border-radius: 10px;
            max-width: 720px; width: 90%; max-height: 80vh;
            overflow-y: auto; padding: 24px 28px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.35);
        }
        .modal-heading { margin: 0 0 14px 0; padding-right: 30px; }
        .modal-eyebrow { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--gray); }
        .modal-box h3 { color: var(--text); margin: 4px 0 0 0; font-size: 19px; font-weight: 700; line-height: 1.25; word-break: break-word; }
        .modal-sub { margin-top: 2px; font-size: 12px; color: var(--gray); word-break: break-all; }
        .modal-sub[hidden] { display: none; }
        .modal-close {
            position: absolute; top: 12px; right: 14px;
            background: none; border: none; color: var(--text-muted);
            font-size: 22px; cursor: pointer; line-height: 1; padding: 0;
        }
        .modal-close:hover { color: var(--text); }
        @media (max-width: 600px) { .modal-box { width: 95%; max-height: 90vh; padding: 18px; } }

        /* -- Footer -- */
        footer.report-footer {
            text-align: center;
            background: var(--bg-header);
            color: rgba(255,255,255,0.85);
            font-size: 11px;
            padding: 16px 24px;
            margin-top: 0;
        }
        footer.report-footer a { color: rgba(255,255,255,0.85); text-decoration: none; }
        footer.report-footer a:hover { text-decoration: underline; }

        /* -- Roles modal: grouped privileged layout -- */
        .role-summary { font-size: 12px; color: var(--gray); margin: 0 0 12px; }
        .role-group td { padding: 10px 10px 6px; border-bottom: 1px solid var(--border-row); }
        .role-group-label {
            display: inline-flex; align-items: center; gap: 8px;
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            color: #5b3f8f;
        }
        .role-group-label .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
        .role-group-label .count {
            background: rgba(112, 84, 160, 0.12); color: inherit;
            border-radius: 10px; padding: 0 7px; font-size: 10px;
        }
        /* neutral variant: the non-privileged group, and the privileged group when it is empty */
        .role-group.neutral .role-group-label { color: var(--gray); }
        .role-group.neutral .role-group-label .count { background: rgba(128, 128, 128, 0.15); }
        .role-empty td { padding: 9px 10px 11px; border-bottom: 1px solid var(--border-row); color: var(--gray); font-style: italic; }
        .role-risk { color: #b10e1c; font-weight: 700; }
        .role-ok   { color: #107c10; font-weight: 700; }
        .role-scope-limited { color: var(--gray); }
        [data-theme="dark"] .role-group-label { color: #c9b2f2; }
        [data-theme="dark"] .role-group-label .count { background: rgba(144, 112, 192, 0.20); }
        [data-theme="dark"] .role-group.neutral .role-group-label { color: var(--gray); }
        [data-theme="dark"] .role-group.neutral .role-group-label .count { background: rgba(128, 128, 128, 0.15); }
        [data-theme="dark"] .role-risk { color: #ff8a97; }
        [data-theme="dark"] .role-ok   { color: #5fd35f; }

        /* -- Severity row tints and tenant findings -- */
        .sev-high   { background: var(--rec-remove-bg) !important; color: var(--rec-remove-text); }
        .sev-medium { background: var(--rec-review-bg) !important; color: var(--rec-review-text); }
        .tenant-findings {
            background: var(--bg-panel); border-radius: var(--radius); box-shadow: var(--shadow);
            padding: 16px 20px; margin-bottom: 24px;
        }
        .tenant-count { font-weight: 400; text-transform: none; letter-spacing: 0; color: var(--text-muted); margin-left: 6px; }
        .tenant-line.clickable { cursor: pointer; }
        .tenant-line.clickable:hover > span:last-child { text-decoration: underline; }
        .tenant-ok { margin-top: 6px; }
        .tenant-ok summary { cursor: pointer; font-size: 12px; color: var(--text-muted); }
        .tenant-findings h2 { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--gray-dark); margin-bottom: 6px; }
        .not-collected { margin: 0 0 6px 18px; }
    </style>
</head>
'@)

# Notes about data that is missing from this run: opt-in switches that were not used, and data the tenant could not return
$notCollected = [System.Collections.Generic.List[string]]::new()
if ($BreakGlassAccounts.Count -eq 0) { $notCollected.Add('<strong>Emergency access (break-glass) accounts</strong> were not named. Pass them with -BreakGlassAccounts so they are checked against the emergency access recommendations instead of the regular ones.') }
$notCollectedBanner = if ($notCollected.Count -gt 0) {
    "<div class='info-banner page-banner'><strong>This is not the full report.</strong> Some data was not collected because the matching parameters were not used:<ul class='not-collected'>$(($notCollected | ForEach-Object { "<li>$_</li>" }) -join '')</ul>Findings that depend on this data are missing, so an account shown as OK may still have gaps in these areas.</div>"
} else { '' }

$unavailable = [System.Collections.Generic.List[string]]::new()
if ($script:guestTrustDenied) { $unavailable.Add('Guest MFA trust was not checked (needs CrossTenantInformation.ReadBasic.All).') }
if ($script:caDataAvailable -and -not $script:securityDefaultsKnown) { $unavailable.Add($(if ($script:caBaseline) { 'Security defaults state could not be read. The verdicts below follow the Conditional Access policies only.' } else { 'Security defaults state could not be read.' })) }
if ($script:caBaseline -and -not $script:signInDataAvailable)  { $unavailable.Add('<strong>Sign-in activity</strong> could not be read (requires an Entra ID P1/P2 license and AuditLog.Read.All). Inactive accounts are not flagged.') }
if ($script:pimBaseline -and -not $script:eligibilityAvailable) { $unavailable.Add('<strong>Eligible (PIM) role assignments</strong> could not be read. Users who are only eligible for a role are missing from this report.') }
if ($script:pimBaseline -and -not $script:pimGroupsAvailable)   { $unavailable.Add('<strong>PIM for Groups eligibility</strong> could not be read for one or more groups (needs PrivilegedEligibilitySchedule.Read.AzureADGroup). Users who are only eligible members of a group that holds roles may be missing.') }
if ($script:caBaseline -and -not $script:authDataAvailable)    { $unavailable.Add('<strong>Authentication strength</strong> could not be read (the registration report requires an Entra ID P1/P2 license and AuditLog.Read.All).') }
if (-not $script:caDataAvailable)   { $unavailable.Add('<strong>Access protection</strong> could not be read (requires Policy.Read.All).') }
foreach ($name in $unmatchedBreakGlass) { $unavailable.Add("<strong>-BreakGlassAccounts:</strong> '$(ConvertTo-HtmlSafe $name)' was not found among the administrator accounts.") }
$unavailableBanner = if ($unavailable.Count -gt 0) {
    "<div class='info-banner page-banner'><strong>Some data could not be read.</strong><ul class='not-collected'>$(($unavailable | ForEach-Object { "<li>$_</li>" }) -join '')</ul></div>"
} else { '' }

$reasonBadge = @{ high = 'red'; medium = 'amber'; low = 'blue'; info = 'gray'; ok = 'green' }
$reasonLabel = @{ high = 'High'; medium = 'Medium'; low = 'Low'; info = 'Info'; ok = 'OK' }
# Tenant-level checks: by severity (high, medium, low, info) in the existing order, passed checks collapsed, clickable lines filter the table
$tenantLine = {
    param($reason)
    $clickable = [bool]($reason.FilterGroup -and $reason.FilterValue)
    $tip = (@($reason.Detail, $(if ($clickable) { 'Click to filter.' })) | Where-Object { $_ }) -join ' '
    $attrs = "$(if ($tip) { " title='$(ConvertTo-HtmlSafe $tip)'" })$(if ($clickable) { " class='tenant-line clickable' data-fg='$($reason.FilterGroup)' data-fv='$($reason.FilterValue)'" } else { " class='tenant-line'" })"
    "<li$attrs><span class='badge $($reasonBadge[$reason.Level])'>$($reasonLabel[$reason.Level])</span><span>$(ConvertTo-HtmlSafe $reason.Text)</span></li>"
}
$tenantRank = @{ high = 0; medium = 1; low = 2; info = 3 }
$tenantIndexed = @(for ($i = 0; $i -lt $tenantFindings.Count; $i++) { [PSCustomObject]@{ Reason = $tenantFindings[$i]; Index = $i } })
$tenantShown = @($tenantIndexed | Where-Object { $_.Reason.Level -ne 'ok' } | Sort-Object @{ Expression = { $tenantRank[$_.Reason.Level] } }, Index | ForEach-Object { $_.Reason })
$tenantPassed = @($tenantFindings | Where-Object { $_.Level -eq 'ok' })
$tenantCounts = @(foreach ($level in 'high', 'medium', 'low') { $n = @($tenantShown | Where-Object { $_.Level -eq $level }).Count; if ($n -gt 0) { "$n $level" } }) -join ' &middot; '
$tenantFindingsHtml = ($tenantShown | ForEach-Object { & $tenantLine $_ }) -join ''
$tenantPassedHtml = if ($tenantPassed.Count -gt 0) {
    $passedLabel = if ($tenantShown.Count -eq 0) { "All $($tenantPassed.Count) checks passed" } else { "$($tenantPassed.Count) checks passed" }
    "<details class='tenant-ok'><summary>$passedLabel</summary><ul class='reason-list'>$((($tenantPassed | ForEach-Object { & $tenantLine $_ }) -join ''))</ul></details>"
} else { '' }

# Cards and filter rows for the opt-in areas only make sense when that data was collected
# Summary cards: only the cards the baseline can fill are rendered
$memberCount = @($report | Where-Object { $_.UserType -eq 'member' }).Count
$guestCount = @($report | Where-Object { $_.UserType -eq 'guest' }).Count
$accessGapCount = @($humanReport | Where-Object { -not $_.IsBreakGlass -and $_.AccessKey -in @('none', 'weak', 'mfaonly') }).Count
$summaryCards = [System.Collections.Generic.List[string]]::new()
$addCard = { param($class, $fg, $fv, $tip, $heading, $number, $subtitle) $summaryCards.Add("<div class='summary-card $class' data-fg='$fg' data-fv='$fv' title='$(ConvertTo-HtmlSafe $tip)'><h3>$heading</h3><div class='number'>$number</div><div class='subtitle'>$subtitle</div></div>") }
$summaryCards.Add("<div class='summary-card' data-clear='1' title='All administrator accounts. Click to clear all filters.'><h3>Administrators</h3><div class='number'>$totalAdmins</div><div class='subtitle'>$memberCount members &middot; $guestCount guests</div></div>")
& $addCard 'k-red' 'sev' 'high' 'Accounts with at least one high-severity finding. Click to filter.' 'High' $highCount 'Fix first'
& $addCard 'k-amber' 'sev' 'medium' 'Accounts whose most severe finding is medium. Click to filter.' 'Medium' $mediumCount 'Plan a fix'
& $addCard 'k-green' 'sev' 'low,ok' 'Accounts with only low-severity findings or none. Click to filter.' 'Low / OK' ($lowCount + $okCount) "$lowCount low &middot; $okCount without findings"
& $addCard 'k-red' 'access' 'ga' "Users who hold$(if ($script:pimBaseline) { ' or are eligible for' }) Global Administrator. Microsoft recommends fewer than $GlobalAdminLimit. Click to filter." 'Global Administrators' $globalAdminCount "$(if ($script:pimBaseline) { 'Active or eligible' } else { 'Active' }) &middot; fewer than $GlobalAdminLimit recommended"
& $addCard 'k-red' 'source' 'onprem' 'Administrator accounts synchronized from on-premises Active Directory. Click to filter.' 'On-Premises Synced' $onPremCount 'Should be cloud-only accounts'
if ($script:pimBaseline) { & $addCard 'k-amber' 'access' 'standing' 'Users with a tenant-wide privileged Microsoft Entra role that is always active, not through PIM (break-glass accounts not counted). Click to filter.' 'Permanent Admin Roles' $standingCount 'Privileged role always active, not through PIM' }
if ($script:caBaseline -and $script:signInDataAvailable) { & $addCard 'k-amber' 'activity' 'inactive,never' "No sign-in for $InactiveDays days or more, or never. Click to filter." 'Inactive' $inactiveCount "No sign-in for $InactiveDays+ days or never" }
if ($script:caBaseline -and $script:authDataAvailable) { & $addCard 'k-amber' 'auth' 'pwl,mfa,sf' 'Administrators without a passkey, Windows Hello or certificate registered. Click to filter.' 'No Phishing-Resistant Method' $noPhishingResistantCount 'Strongest method is below phishing-resistant' }
if ($script:caBaseline -and $script:caDataAvailable) { & $addCard 'k-amber' 'protection' 'none,weak,mfaonly' 'Administrators whose access protection is None, Weak or MFA only. Click to filter.' 'Access Protection Gaps' $accessGapCount 'Verdict is None, Weak or MFA only' }
$summaryColumns = switch ($summaryCards.Count) { { $_ -ge 10 } { 5 } 9 { 3 } 8 { 4 } 7 { 4 } default { 3 } }
$summaryHtml = $summaryCards -join "`n        "
$syncFilter = if ($connectorCount -gt 0 -or $unexpectedSyncCount -gt 0) { @"
        <div class="filter-group">
            <span class="filter-group-label">Sync role</span>
            <span class="filter-tag c-gray" data-group="sync" data-value="connector"  onclick="toggleTag(this)">Entra Connect sync account <span class="cnt"></span></span>
            <span class="filter-tag c-red"  data-group="sync" data-value="unexpected" onclick="toggleTag(this)">Sync role on other account <span class="cnt"></span></span>
        </div>
"@ } else { '' }
$guestIdpMap = [ordered]@{ microsoftentra = 'Microsoft Entra'; google = 'Google'; emailotp = 'Email OTP'; microsoftaccount = 'Microsoft account'; facebook = 'Facebook'; samlwsfed = 'SAML/WS-Fed'; localaccount = 'Local account' }
$guestIdpTags = @(foreach ($k in $guestIdpMap.Keys) { if (@($report | Where-Object { $_.GuestProvider -eq $guestIdpMap[$k] }).Count -gt 0) { "<span class=`"filter-tag c-gray`" data-group=`"guestidp`" data-value=`"$k`" onclick=`"toggleTag(this)`">Guest &middot; $([System.Net.WebUtility]::HtmlEncode($guestIdpMap[$k])) <span class=`"cnt`"></span></span>" } }) -join "`n            "
$authTrustedTag = if (@($report | Where-Object { $_.AuthKey -eq 'trusted' }).Count -gt 0) { "<span class=`"filter-tag c-blue`" data-group=`"auth`" data-value=`"trusted`" onclick=`"toggleTag(this)`">MFA trusted <span class=`"cnt`"></span></span>" } else { '' }
$authNaTag = if (@($report | Where-Object { $_.AuthKey -eq 'na' -or $_.SyncAccount -eq 'connector' }).Count -gt 0) { "<span class=`"filter-tag c-gray`" data-group=`"auth`" data-value=`"na`" onclick=`"toggleTag(this)`">N/A <span class=`"cnt`"></span></span>" } else { '' }
$fallbackFilter = if (@($report | Where-Object { $_.AuthKey -in @('pr', 'pwl', 'mfa') -and $_.WeakFallback.Count -gt 0 }).Count -gt 0) { @"
        <div class="filter-group">
            <span class="filter-group-label">Fallback</span>
            <span class="filter-tag c-amber" data-group="fallback" data-value="weak" onclick="toggleTag(this)">Weak fallback (SMS / Voice) <span class="cnt"></span></span>
        </div>
"@ } else { '' }
$authFilter = if ($script:authDataAvailable) { @"
        <div class="filter-group">
            <span class="filter-group-label">Auth methods</span>
            <span class="filter-tag c-green"  data-group="auth" data-value="pr"      onclick="toggleTag(this)">Phishing-resistant <span class="cnt"></span></span>
            <span class="filter-tag c-amber"  data-group="auth" data-value="pwl"     onclick="toggleTag(this)">Passwordless <span class="cnt"></span></span>
            <span class="filter-tag c-amber"  data-group="auth" data-value="mfa"     onclick="toggleTag(this)">MFA <span class="cnt"></span></span>
            <span class="filter-tag c-red"    data-group="auth" data-value="sf"      onclick="toggleTag(this)">Single factor <span class="cnt"></span></span>
            $authTrustedTag
            $authNaTag
            <span class="filter-tag c-gray"   data-group="auth" data-value="unknown" onclick="toggleTag(this)">Unknown <span class="cnt"></span></span>
        </div>
"@ } else { '' }
$accessPimTags = if ($script:pimBaseline) { "<span class=`"filter-tag c-amber`"  data-group=`"access`" data-value=`"standing`"   onclick=`"toggleTag(this)`">Standing privileged <span class=`"cnt`"></span></span>`n            <span class=`"filter-tag c-blue`"   data-group=`"access`" data-value=`"eligible`"   onclick=`"toggleTag(this)`">Eligible (PIM) <span class=`"cnt`"></span></span>" } else { '' }
$policyFilterTag = if (@($report | Where-Object { $_.AccessKey -eq 'policy' }).Count -gt 0) { "<span class=`"filter-tag c-red`" data-group=`"protection`" data-value=`"policy`" onclick=`"toggleTag(this)`">Policy applies <span class=`"cnt`"></span></span>" } else { '' }
$sdFilterTag = if (@($report | Where-Object { $_.AccessKey -eq 'sd' }).Count -gt 0) { "<span class=`"filter-tag c-blue`" data-group=`"protection`" data-value=`"sd`" onclick=`"toggleTag(this)`">Security defaults <span class=`"cnt`"></span></span>" } else { '' }
$devLocFilterHtml = if ($script:caBaseline) { @"
        <div class="filter-group">
            <span class="filter-group-label">Trusted device</span>
            <span class="filter-tag c-green"  data-group="device" data-value="device"   onclick="toggleTag(this)">Compliant / Hybrid <span class="cnt"></span></span>
            <span class="filter-tag c-amber"  data-group="device" data-value="optional" onclick="toggleTag(this)">Optional <span class="cnt"></span></span>
            <span class="filter-tag c-gray"   data-group="device" data-value="none"     onclick="toggleTag(this)">None <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Trusted location</span>
            <span class="filter-tag c-green"  data-group="loc" data-value="gsa"     onclick="toggleTag(this)">GSA network <span class="cnt"></span></span>
            <span class="filter-tag c-green"  data-group="loc" data-value="ip"      onclick="toggleTag(this)">Trusted IP <span class="cnt"></span></span>
            <span class="filter-tag c-amber"  data-group="loc" data-value="country" onclick="toggleTag(this)">Country <span class="cnt"></span></span>
            <span class="filter-tag c-amber"  data-group="loc" data-value="other"   onclick="toggleTag(this)">Other <span class="cnt"></span></span>
            <span class="filter-tag c-gray"   data-group="loc" data-value="none"    onclick="toggleTag(this)">None <span class="cnt"></span></span>
        </div>
"@ } else { '' }
$caFilter = if ($script:caDataAvailable) { @"
        <div class="filter-group">
            <span class="filter-group-label">Access protection</span>
            <span class="filter-tag c-green"  data-group="protection" data-value="strong"  onclick="toggleTag(this)">Strong <span class="cnt"></span></span>
            <span class="filter-tag c-green"  data-group="protection" data-value="good"    onclick="toggleTag(this)">Good <span class="cnt"></span></span>
            <span class="filter-tag c-amber"  data-group="protection" data-value="mfaonly" onclick="toggleTag(this)">MFA only <span class="cnt"></span></span>
            <span class="filter-tag c-amber"  data-group="protection" data-value="weak"    onclick="toggleTag(this)">Weak <span class="cnt"></span></span>
            <span class="filter-tag c-red"    data-group="protection" data-value="none"    onclick="toggleTag(this)">None <span class="cnt"></span></span>
            $sdFilterTag
            $policyFilterTag
            <span class="filter-tag c-gray"   data-group="protection" data-value="na"      onclick="toggleTag(this)">N/A <span class="cnt"></span></span>
        </div>
$devLocFilterHtml
"@ } else { '' }
# Alerts is N/A for Entra Connect sync accounts; the tag only appears when the report has such accounts
$notifyNaTag = if ($connectorCount -gt 0) { "<span class=`"filter-tag c-gray`" data-group=`"notify`" data-value=`"na`" onclick=`"toggleTag(this)`">N/A <span class=`"cnt`"></span></span>" } else { '' }
$unknownActivityTag = if (-not $script:signInDataAvailable) {
    "<span class='filter-tag c-gray' data-group='activity' data-value='unknown' onclick='toggleTag(this)'>Unknown <span class='cnt'></span></span>"
} else { '' }

$lastSignInFilter = if ($script:caBaseline) { @"
        <div class="filter-group">
            <span class="filter-group-label">Last sign-in</span>
            <span class="filter-tag c-green"  data-group="activity" data-value="active"   onclick="toggleTag(this)">Active (&lt; $InactiveDays days) <span class="cnt"></span></span>
            <span class="filter-tag c-amber" data-group="activity" data-value="inactive" onclick="toggleTag(this)">Inactive ($InactiveDays+ days) <span class="cnt"></span></span>
            <span class="filter-tag c-amber" data-group="activity" data-value="never"    onclick="toggleTag(this)">Never <span class="cnt"></span></span>
            $unknownActivityTag
        </div>
"@ } else { '' }
[void]$sb.Append(@"
<body>
    <header>
        <div class="header-text">
            <h1>Entra ID Administrator Report</h1>
            <div class="meta">
                <strong>Tenant:</strong> $(ConvertTo-HtmlSafe $tenantName) &nbsp;&middot;&nbsp;
                <strong>Tenant ID:</strong> $(ConvertTo-HtmlSafe $tenantId) &nbsp;&middot;&nbsp;
                <strong>Generated:</strong> $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC &nbsp;&middot;&nbsp;
                <strong>Inactive threshold:</strong> $InactiveDays days
            </div>
            <div class="meta">
                <strong>Assessment baseline:</strong> Microsoft Entra ID $LicenseBaseline
            </div>
        </div>
        <a class="github-link" href="https://github.com/matejklemencic/EntraID-AdminReport" target="_blank" rel="noopener" title="View source on GitHub"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 16 16" fill="#ffffff"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg></a>
        <button id="themeToggle" onclick="toggleTheme()" title="Toggle dark / light mode">&#127769;</button>
    </header>

    <div class="container">

    $notCollectedBanner
    $unavailableBanner
    $tenantAccessBanner

    <div class="summary" style="grid-template-columns: repeat($summaryColumns, 1fr)">
        $summaryHtml
    </div>
    <div class="tenant-findings">
        <h2>Tenant-level checks$(if ($tenantCounts) { " <span class='tenant-count'>$tenantCounts</span>" })</h2>
        <ul class="reason-list">$tenantFindingsHtml</ul>
        $tenantPassedHtml
    </div>

    <div class="filter-bar">
        <button id="filterToggle" class="filter-toggle-btn" onclick="toggleFilterPanel()" aria-expanded="false">
            <span class="caret">&#9656;</span> Search &amp; Filter
        </button>
        <span id="filterSummary" class="filter-summary"></span>
        <button class="export-csv-btn" onclick="exportCsv()" title="Download visible rows as CSV">&#8595; Export CSV</button>
    </div>

    <div class="controls" id="controlsPanel" hidden>
        <input type="text" id="searchInput" class="filter-search" placeholder="Search by name, UPN, mail, role, group, license or method..." oninput="queueApplyFilters()">

        $lastSignInFilter
        <div class="filter-group">
            <span class="filter-group-label">Source</span>
            <span class="filter-tag c-green" data-group="source" data-value="cloud"  onclick="toggleTag(this)">Cloud-only <span class="cnt"></span></span>
            <span class="filter-tag c-red"   data-group="source" data-value="onprem" onclick="toggleTag(this)">On-prem synced <span class="cnt"></span></span>
            <span class="filter-tag c-blue"   data-group="usertype" data-value="member" onclick="toggleTag(this)">Member <span class="cnt"></span></span>
            <span class="filter-tag c-purple" data-group="usertype" data-value="guest"  onclick="toggleTag(this)">Guest <span class="cnt"></span></span>
            $guestIdpTags
        </div>

$syncFilter
        <div class="filter-group">
            <span class="filter-group-label">Break-glass</span>
            <span class="filter-tag c-gray"  data-group="bg" data-value="yes"    onclick="toggleTag(this)">Break-glass <span class="cnt"></span></span>
            <span class="filter-tag c-amber" data-group="bg" data-value="likely" onclick="toggleTag(this)">Likely break-glass <span class="cnt"></span></span>
            <span class="filter-tag c-blue"  data-group="bg" data-value="no"     onclick="toggleTag(this)">Regular admin <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Enabled</span>
            <span class="filter-tag c-green"  data-group="enabled"  data-value="yes"    onclick="toggleTag(this)">Enabled <span class="cnt"></span></span>
            <span class="filter-tag c-gray"   data-group="enabled"  data-value="no"     onclick="toggleTag(this)">Disabled <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Entra ID roles</span>
            <span class="filter-tag c-red" data-group="access" data-value="ga"         onclick="toggleTag(this)">Global Administrator <span class="cnt"></span></span>
            <span class="filter-tag c-red"    data-group="access" data-value="privileged" onclick="toggleTag(this)">Privileged role <span class="cnt"></span></span>
            $accessPimTags
            <span class="filter-tag c-blue"   data-group="access" data-value="group"      onclick="toggleTag(this)">Via group <span class="cnt"></span></span>
            <span class="filter-tag c-blue"   data-group="access" data-value="scoped"     onclick="toggleTag(this)">Scoped role <span class="cnt"></span></span>
        </div>
        $authFilter
        $fallbackFilter
        $caFilter
        <div class="filter-group">
            <span class="filter-group-label">Licenses</span>
            <span class="filter-tag c-amber" data-group="license" data-value="mailbox"      onclick="toggleTag(this)">Mailbox <span class="cnt"></span></span>
            <span class="filter-tag c-blue"  data-group="license" data-value="productivity" onclick="toggleTag(this)">Productivity <span class="cnt"></span></span>
            <span class="filter-tag c-gray"  data-group="license" data-value="other"        onclick="toggleTag(this)">Other <span class="cnt"></span></span>
            <span class="filter-tag c-green" data-group="license" data-value="none"         onclick="toggleTag(this)">None <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Alerts</span>
            <span class="filter-tag c-amber" data-group="notify" data-value="missing" onclick="toggleTag(this)">Missing <span class="cnt"></span></span>
            <span class="filter-tag c-green" data-group="notify" data-value="set"     onclick="toggleTag(this)">Set <span class="cnt"></span></span>$notifyNaTag
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Severity</span>
            <span class="filter-tag c-red"   data-group="sev" data-value="high"   onclick="toggleTag(this)">High <span class="cnt"></span></span>
            <span class="filter-tag c-amber" data-group="sev" data-value="medium" onclick="toggleTag(this)">Medium <span class="cnt"></span></span>
            <span class="filter-tag c-blue"  data-group="sev" data-value="low"    onclick="toggleTag(this)">Low <span class="cnt"></span></span>
            <span class="filter-tag c-green" data-group="sev" data-value="ok"     onclick="toggleTag(this)">OK <span class="cnt"></span></span>
        </div>
        <div class="filter-results">
            <span id="resultCount" class="result-count"></span>
            <span id="activeChips" class="active-chips"></span>
            <button id="clearAll" class="clear-all" onclick="clearAllFilters()" style="display:none;">Clear all</button>
        </div>
    </div>

    <div class="table-wrap">
    <table id="reportTable">
        <thead>
            <tr>
                <th onclick="sortTable('reportTable', 0, 'string')">Administrator</th>
                <th onclick="sortTable('reportTable', 1, 'number')">Last sign-in</th>
                <th onclick="sortTable('reportTable', 2, 'string')">Source</th>
                <th onclick="sortTable('reportTable', 3, 'string')">Enabled</th>
                <th onclick="sortTable('reportTable', 4, 'number')">Entra ID roles</th>
                <th title="The strongest sign-in method the account has registered. Whether MFA is required is shown in Access protection." onclick="sortTable('reportTable', 5, 'string')">Auth methods</th>
                <th title="Admin accounts should require phishing-resistant MFA plus a trusted device or trusted location." onclick="sortTable('reportTable', 6, 'string')">Access protection</th>
                <th title="Admin accounts should not have mailbox or productivity licenses, and should have an email address so Entra alerts reach someone." onclick="sortTable('reportTable', 7, 'string')">Licenses &amp; alerts</th>
                <th onclick="sortTable('reportTable', 8, 'string')">Findings</th>
                <th class="csv-only">Object ID</th>
                <th class="csv-only">User principal name</th>
                <th class="csv-only">Mail</th>
                <th class="csv-only">Alternate email</th>
                <th class="csv-only">User type</th>
                <th class="csv-only">Break-glass</th>
                <th class="csv-only">Entra role details</th>
                <th class="csv-only">Registered methods</th>
                <th class="csv-only">Conditional Access policies</th>
                <th class="csv-only">Device / location / sign-in frequency</th>
                <th class="csv-only">AccessProtection</th>
                <th class="csv-only">MfaRequirement</th>
                <th class="csv-only">DeviceRequirement</th>
                <th class="csv-only">LocationRequirement</th>
                <th class="csv-only">SignInFrequency</th>
                <th class="csv-only">License SKUs</th>
                <th class="csv-only">Days since last sign-in</th>
                <th class="csv-only">Finding details</th>
                <th class="csv-only">Account type</th>
                <th class="csv-only">ConditionalAccessAvailable</th>
                <th class="csv-only">SecurityDefaultsEnabled</th>
                <th class="csv-only">AuthMethodsTier</th>
                <th class="csv-only">StrongestMethod</th>
                <th class="csv-only">WeakFallback</th>
                <th class="csv-only">GuestIdentityProvider</th>
                <th class="csv-only">GuestMfaTrust</th>
            </tr>
        </thead>
        <tbody>
"@)

# Sort: most severe first, then by name
$severityOrder = @{ high = 1; medium = 2; low = 3; ok = 4 }
$sortedReport = @($report | Sort-Object @{ Expression = { $severityOrder[$_.Severity] } }, @{ Expression = { $_.DisplayName } })
$modalDataEntries = [System.Collections.Generic.List[string]]::new()
$notCollectedBadge = "<span class='badge gray' title='Could not be read. See the note at the top of the report.'>Unknown</span>"
$authBadge = @{
    pr      = @{ Color = 'green'; Text = 'Phishing-resistant' }
    pwl     = @{ Color = 'amber'; Text = 'Passwordless' }
    mfa     = @{ Color = 'amber'; Text = 'MFA' }
    sf      = @{ Color = 'red';   Text = 'Single factor' }
    trusted = @{ Color = 'blue';  Text = 'MFA trusted' }
    na      = @{ Color = 'gray';  Text = 'N/A' }
    unknown = @{ Color = 'gray';  Text = 'Unknown' }
}
$authRank = @{ pr = 1; pwl = 2; mfa = 3; trusted = 4; sf = 5; unknown = 6; na = 7; nc = 8 }
$licenseBadge = @{
    mailbox      = @{ Color = 'amber'; Text = 'License: Mailbox';      Title = 'Has an Exchange Online mailbox license. Admin accounts should not be used for email. Click for details.' }
    productivity = @{ Color = 'blue';  Text = 'License: Productivity'; Title = 'Has Teams, SharePoint or Microsoft 365 Apps plans. Admin accounts do not need them. Click for details.' }
    other        = @{ Color = 'gray';  Text = 'License: Other';        Title = 'Has licenses without a mailbox or productivity plans. Click for details.' }
    none         = @{ Color = 'green'; Text = 'License: None';         Title = 'No license assigned. Click for details.' }
}

foreach ($a in $sortedReport) {
    $key = ConvertTo-HtmlSafe $a.Id
    $nameText = if ($a.DisplayName) { $a.DisplayName } else { $a.UserPrincipalName }
    $safeName = ConvertTo-HtmlSafe $nameText
    $portalUrl = "https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/$key"
    $entraRoles = @($a.Roles | Where-Object { $_.Kind -eq 'Entra' })
    $modal = [System.Collections.Generic.List[string]]::new()

    # Name badges
    $nameBadges = ''
    if ($a.SyncAccount -eq 'connector')  { $nameBadges += (New-BadgeHtml 'blue' 'Entra Connect sync account' "Service account of Microsoft Entra Connect: it holds the $SyncRoleName role. Checked as a service account, not as a human administrator." 'sync' 'connector') }
    if ($a.SyncAccount -eq 'unexpected') { $nameBadges += (New-BadgeHtml 'red' 'Sync role on user account' "Holds the $SyncRoleName role but does not look like an Entra Connect connector account. Microsoft says only the Connect wizard assigns this role." 'sync' 'unexpected') }
    $accountTypeText = switch ($a.SyncAccount) { 'connector' { 'Entra Connect sync account' } 'unexpected' { 'Sync role on user account' } default { 'Administrator' } }
    if ($a.IsBreakGlass)    { $nameBadges += (New-BadgeHtml 'gray' 'Break-glass' 'Emergency access account named with -BreakGlassAccounts.' 'bg' 'yes') }
    if ($a.LikelyBreakGlass) { $nameBadges += (New-BadgeHtml 'amber' 'Likely break-glass' 'Looks like an emergency access account. Pass it with -BreakGlassAccounts to check it as one.' 'bg' 'likely') }
    if ($a.UserType -eq 'guest') {
        $guestText = if ($a.GuestProvider) { 'Guest ' + [char]0x00B7 + ' ' + $a.GuestProvider } else { 'Guest' }
        $nameBadges += (New-BadgeHtml 'purple' $guestText 'Guest or external account.' 'usertype' 'guest').Replace("class='badge purple", "class='badge purple guest-idp")
    }
    # These badges sit under the source badge; the CSV has its own columns for them, so they are left out of the Source column
    $nameBadges = $nameBadges -replace "class='badge ", "class='badge csv-exclude "

    $sourceText = if ($a.OnPremisesSynced) { New-BadgeHtml 'red' 'On-prem synced' 'Synchronized from on-premises Active Directory. Microsoft recommends cloud-only accounts for role assignments.' 'source' 'onprem' }
                  else { New-BadgeHtml 'green' 'Cloud-only' 'Created in Microsoft Entra ID.' 'source' 'cloud' }
    $guestIdp = if ($a.GuestKind) { $a.GuestProvider.ToLower() -replace '[^a-z0-9]', '' } else { '' }
    $enabledText = if ($a.AccountEnabled) { New-BadgeHtml 'green' 'Yes' 'Sign-in allowed.' 'enabled' 'yes' } else { New-BadgeHtml 'gray' 'No' 'Sign-in blocked.' 'enabled' 'no' }

    # Entra roles
    $eligibleCount = @($entraRoles | Where-Object { $_.Type -eq 'Eligible' }).Count
    $hasGa = @($entraRoles | Where-Object { $_.RoleId -eq $GlobalAdminRoleId -and $_.Type -in @('Active', 'Eligible') }).Count -gt 0
    $hasPrivileged = @($entraRoles | Where-Object { $_.Privileged }).Count -gt 0
    $hasStanding = @($entraRoles | Where-Object { $_.Privileged -and $_.ScopeKind -eq 'tenant' -and $_.Type -eq 'Active' -and $_.Assignment -ne 'Activated (PIM)' }).Count -gt 0
    $hasScoped = @($entraRoles | Where-Object { $_.ScopeKind -ne 'tenant' }).Count -gt 0
    $entraText = "<span class='muted'>None</span>"
    if ($entraRoles.Count -gt 0) {
        # Grouped layout: privileged roles first, then the others. Both groups are always shown, even when empty.
        $privilegedRows = [System.Collections.Generic.List[string]]::new()
        $otherRows = [System.Collections.Generic.List[string]]::new()
        foreach ($role in $entraRoles) {
            $roleCell = if ($role.BuiltIn) { "<a href='$(Get-EntraRoleLearnUrl $role.Role)' target='_blank' rel='noopener'>$(ConvertTo-HtmlSafe $role.Role)</a>" } else { ConvertTo-HtmlSafe $role.Role }
            $typeText = if ($role.Type -eq 'Owner') { 'Group owner' } elseif ($role.Assignment -and $role.Assignment -ne 'Active') { "$($role.Type) - $($role.Assignment)" } else { $role.Type }
            $typeCell = ConvertTo-HtmlSafe $typeText
            # The risk signal sits in the Type column: a privileged role that is permanently active
            if ($role.Privileged -and $role.ScopeKind -eq 'tenant' -and $role.Type -eq 'Active' -and $role.Assignment -in @('Permanent', 'Active')) { $typeCell = "<span class='role-risk'>$typeCell</span>" }
            $row = New-ModalRowHtml @($roleCell, $typeCell, (ConvertTo-HtmlSafe $role.Via), (Get-RoleScopeHtml $role), (Format-ReportDate $role.Ends))
            if ($role.Privileged) { $privilegedRows.Add($row) } else { $otherRows.Add($row) }
        }
        # Only tenant-wide privileged roles count as risk; a scoped role has a limited impact
        $permanentPrivileged = @($entraRoles | Where-Object { $_.Privileged -and $_.ScopeKind -eq 'tenant' -and $_.Type -eq 'Active' -and $_.Assignment -in @('Permanent', 'Active') }).Count
        $tenantPrivilegedCount = @($entraRoles | Where-Object { $_.Privileged -and $_.ScopeKind -eq 'tenant' }).Count
        $rows = (New-RoleGroupHtml 'Privileged roles' $privilegedRows ($privilegedRows.Count -eq 0) 'No privileged roles') + (New-RoleGroupHtml 'Non-privileged roles' $otherRows $true 'No non-privileged roles')
        $banner = if ($script:pimBaseline -and -not $script:eligibilityAvailable) { "<div class='info-banner'>Eligible (PIM) roles could not be read. Only active roles are listed.</div>" } else { '' }
        $html = (Get-RoleSummaryHtml $entraRoles.Count $privilegedRows.Count $permanentPrivileged $tenantPrivilegedCount ($privilegedRows.Count - $tenantPrivilegedCount)) + $banner + (New-ModalTableHtml 'mtEntra' @('Role', 'Type', 'Assigned via', 'Scope', 'Ends') $rows)
        $modal.Add("entraTitle: $(ConvertTo-JsString "Microsoft Entra ID roles"), entraHtml: $(ConvertTo-JsString $html)")
        $label = "Roles: $($entraRoles.Count)" + $(if ($eligibleCount -gt 0) { " ($eligibleCount eligible)" } else { '' })
        $entraText = New-BadgeHtml 'blue' $label 'Click for role details.' '' '' (Get-ModalOnClick $key 'entra')
        if ($hasGa) { $entraText += New-BadgeHtml 'red' 'Global Admin' 'Holds or is eligible for Global Administrator.' 'access' 'ga' }
    }

    # Authentication methods: what is registered (whether MFA is required is shown in Access protection)
    $authText = if ($script:caBaseline) { $notCollectedBadge } else { "<span class='muted'>Not assessed</span>" }
    $authCsvTier = $(if ($script:caBaseline) { 'Unknown' } else { 'Not assessed' }); $weakCsv = ''; $trustCsv = ''; $fallbackAttr = ''
    if ($a.AuthCollected) {
        $authOnClick = Get-ModalOnClick $key 'auth'
        $modal.Add("authTitle: $(ConvertTo-JsString "Auth methods"), authHtml: $(ConvertTo-JsString (New-AuthModalHtml $a))")
        $authInfo = $authBadge[$a.AuthKey]
        $authCsvTier = $authInfo.Text
        $authTitle = if ($a.AuthKey -in @('unknown', 'trusted', 'na')) { "$($authInfo.Text). Click for details." } else { "Strongest registered method: $($a.AuthLabel). Click for details." }

        $authParts = @(New-BadgeHtml $authInfo.Color $authInfo.Text $authTitle '' '' $authOnClick)

        if ($a.WeakFallback.Count -gt 0) {
            $weakCsv = $a.WeakFallback -join ', '
            $fallbackAttr = ' data-fallback="weak"'
            $authParts += "<span class='auth-chip amber' title='A weaker method is registered next to the strongest one.'>+ $(ConvertTo-HtmlSafe $weakCsv)</span>"
        }

        $trustCsv = switch ($a.GuestTrust) { 'accepted' { 'Accepted' } 'rejected' { 'Not accepted' } 'unknown' { 'Unknown' } default { '' } }
        $authText = "<span class='perm-badges'>$($authParts -join '')</span>"
    }
    # Access protection: one verdict (phishing-resistant MFA plus a trusted device or location) and the three requirements behind it
    $accessKey = $a.AccessKey
    $caText = $notCollectedBadge
    $controlsDetail = ''
    $mfaReq = ''; $devReq = ''; $locReq = ''; $sifCsv = ''; $accessCsv = 'Unknown'
    if ($a.CaCollected) {
        $modal.Add("caTitle: $(ConvertTo-JsString "Access protection"), caHtml: $(ConvertTo-JsString (New-AccessModalHtml $a $accessKey))")
        $caOnClick = Get-ModalOnClick $key 'ca'
        $accessCsv = switch ($accessKey) { 'strong' { 'Strong' } 'good' { 'Good' } 'mfaonly' { 'MFA only' } 'weak' { 'Weak' } 'none' { 'None' } 'sd' { 'Security defaults' } 'policy' { 'Policy applies' } 'na' { 'N/A' } default { 'Unknown' } }
        $verdictBadge = switch ($accessKey) {
            'strong'  { @('green', 'Strong', 'Phishing-resistant MFA plus a compliant device and a trusted location. Click for details.') }
            'good'    { @('green', 'Good', 'Phishing-resistant MFA plus a compliant device or a trusted location. Click for details.') }
            'mfaonly' { @('amber', 'MFA only', 'Phishing-resistant MFA, but no device or location requirement. Click for details.') }
            'weak'    { @('amber', 'Weak', 'MFA is not phishing-resistant or covers only some resources. Click for details.') }
            'none'    { @('red', 'None', 'No Conditional Access policy requires MFA for this account. Click for details.') }
            'sd'      { @('blue', 'Security defaults', 'Security defaults require MFA on every sign-in for this account. Click for details.') }
            'policy'  { @('red', 'Policy applies', 'An enabled Conditional Access policy applies to this break-glass account. Click for details.') }
            default   { @('gray', 'N/A', 'Does not apply (break-glass or sync account). Click for details.') }
        }
        $strip = ''
        if ($accessKey -notin @('na', 'policy', 'sd')) {
            $pillState = {
                param($state, $name, $tip)
                $symbol = switch ($state) { 'ok' { '&#10003;' } 'warn' { '~' } default { '&ndash;' } }
                "<span class='ap-pill $state' title='$(ConvertTo-HtmlSafe $tip)' onclick=`"$caOnClick`">$symbol $name</span>"
            }
            $mfaState = switch ($a.CaKey) { 'pr' { 'ok' } { $_ -in @('mfa', 'partial', 'activation') } { 'warn' } default { 'none' } }
            $devState = switch ($a.DeviceKey) { 'device' { 'ok' } 'optional' { 'warn' } default { 'none' } }
            $locState = switch ($a.LocKey) { { $_ -in @('gsa', 'ip') } { 'ok' } { $_ -in @('country', 'other') } { 'warn' } default { 'none' } }
            if ($accessKey -eq 'sd') { $mfaState = 'ok'; $devState = 'none'; $locState = 'none' }
            $strip = "<span class='ap-strip csv-exclude'>$(& $pillState $mfaState 'MFA' 'Phishing-resistant MFA required for all resources: check marks it as met, a tilde as weaker, a dash as missing.')$(& $pillState $devState 'Device' 'Compliant or hybrid joined device required for all resources.')$(& $pillState $locState 'Location' 'Access limited to a trusted IP range or the Global Secure Access network.')</span>"
            $reqText = @{ ok = 'Met'; warn = 'Weaker'; none = 'Missing' }
            $mfaReq = $reqText[$mfaState]; $devReq = $reqText[$devState]; $locReq = $reqText[$locState]
            if ($accessKey -eq 'sd') { $devReq = $locReq = $(if (-not $script:caBaseline) { 'Not available' } else { 'Not configured' }) }
            $sifCsv = if ($accessKey -eq 'sd') { '' } elseif ($a.SifKey -eq 'none') { 'Not set' } else { Format-Hours $a.SifHours }
            $controlsDetail = "Device: $(if ($a.DeviceKey -eq 'device') { $a.DeviceLabel } else { $a.DeviceKey }) | Location: $(if ($a.LocKey -in @('none', 'nc')) { 'none' } else { "$($a.LocKey) ($($a.LocLabel))" }) | Sign-in frequency: $(if ($a.SifKey -eq 'none') { 'not set' } else { Format-Hours $a.SifHours })"
        }
        $caText = "<span class='perm-badges'>$(New-BadgeHtml $verdictBadge[0] $verdictBadge[1] $verdictBadge[2] '' '' $caOnClick)$strip</span>"
    }
    $rank = @{ policy = 0; none = 1; weak = 2; mfaonly = 3; good = 4; strong = 5; sd = 6; nc = 7; na = 8 }
    $accessSort = "$($rank[$accessKey])-$accessKey"
    # A connector account is a service account: MFA, passkeys and Conditional Access coverage are not assessed for it
    $authAttr = $a.AuthKey; $accessAttr = $accessKey; $deviceAttr = $a.DeviceKey; $locAttr = $a.LocKey
    if ($accessKey -eq 'sd') { $deviceAttr = 'na'; $locAttr = 'na' }
    if ($a.SyncAccount -eq 'connector') {
        $naBadge = "<span class='badge gray' title='Not applicable: a service account does not use MFA.$(if ($script:caBaseline) { ' Microsoft recommends excluding the Entra Connect sync account from Conditional Access.' })'>N/A</span>"
        $authText = $naBadge; $caText = $naBadge; $authAttr = 'na'; $accessAttr = 'na'; $deviceAttr = 'na'; $locAttr = 'na'
    }

    $notifyAttr = if ($a.SyncAccount -eq 'connector') { 'na' } elseif ($a.Mail -or $a.OtherMails.Count -gt 0) { 'set' } else { 'missing' }
    # Licenses and notification email modal
    $hasMailAddr = [bool]$a.Mail -or $a.OtherMails.Count -gt 0
    $licBanner = if ($a.SyncAccount -eq 'connector') { @('gray', 'Service account - not assessed') }
                 elseif (-not $hasMailAddr) { @('red', 'No notification email - alerts reach nobody') }
                 elseif ($a.LicenseKey -eq 'mailbox') { @('amber', 'Mailbox license on an admin account') }
                 elseif ($a.LicenseKey -eq 'productivity') { @('amber', 'Productivity license on an admin account') }
                 else { @('green', 'Dedicated admin account - notification email set') }
    $html = "<div class='modal-banner $($licBanner[0])'><span class='modal-dot'></span><span>$($licBanner[1])</span></div>"

    $html += if ($a.Licenses.Count -gt 0) {
        '<div style="margin-top:14px"></div>' + (New-ModalTableHtml 'mtSkus' @('License', 'Flagged service plans') (($a.Licenses | ForEach-Object {
            $planClass = if ($_.Category -eq 'mailbox') { 'lic-plan-mailbox' } else { 'lic-plan-productivity' }
            New-ModalRowHtml @((ConvertTo-HtmlSafe (Get-LicenseFriendlyName $_.Sku)), $(if ($_.Flagged.Count -gt 0) { "<span class='$planClass'>$(ConvertTo-HtmlSafe ($_.Flagged -join ', '))</span>" } else { "<span class='muted'>-</span>" }))
        }) -join ''))
    } else { "<p class='muted' style='font-style:italic;margin-top:14px'>No licenses assigned.</p>" }

    if ($a.SyncAccount -ne 'connector') {
        $emailParts = @($(if ($a.Mail) { "Email $(ConvertTo-HtmlSafe $a.Mail)" }), $(if ($a.OtherMails.Count -gt 0) { "Alternate email $(ConvertTo-HtmlSafe ($a.OtherMails -join ', '))" })) | Where-Object { $_ }
        if ($emailParts.Count -gt 0) { $html += "<div class='lic-emails'>$($emailParts -join ' - ')</div>" }

        $upnAt = $a.UserPrincipalName.LastIndexOf('@')
        $upnDomain = if ($upnAt -ge 0) { $a.UserPrincipalName.Substring($upnAt + 1) } else { '' }
        if (-not $upnDomain -or $upnDomain -like '*.onmicrosoft.com') { $upnDomain = 'yourdomain.com' }
        $plusExample = "<code>name+admin@$(ConvertTo-HtmlSafe $upnDomain)</code>"
        $recommendation = $null; $mentionsPlus = $false
        if (-not $hasMailAddr) {
            if ($a.IsBreakGlass) { $recommendation = 'Set the Email attribute to a mailbox the security team monitors, so alerts for this account are seen.' }
            else { $recommendation = "Set the Email attribute. Idea: a plus address of the owner's mailbox, for example $plusExample"; $mentionsPlus = $true }
        }
        elseif ($a.LicenseKey -eq 'mailbox') { $recommendation = "Remove the mailbox license. To keep notifications, set the Email to a plus address of the owner's mailbox, for example $plusExample"; $mentionsPlus = $true }
        elseif ($a.LicenseKey -eq 'productivity') { $recommendation = 'Remove the productivity plans. Admin accounts do not need Teams, SharePoint or Microsoft 365 Apps.' }
        if ($recommendation) { $html += "<div class='modal-rec'><strong>Recommended:</strong> $recommendation</div>" }
        if ($mentionsPlus) { $html += "<div class='modal-note'>Plus addressing is on by default in Exchange Online. Test delivery once. <a href='https://learn.microsoft.com/exchange/recipients-in-exchange-online/plus-addressing-in-exchange-online' target='_blank' rel='noopener noreferrer'>Learn more</a></div>" }
    }
    $modal.Add("licenseTitle: $(ConvertTo-JsString "Licenses and notification email"), licenseHtml: $(ConvertTo-JsString $html)")
    $licOnClick = Get-ModalOnClick $key 'license'
    $licBadgeInfo = $licenseBadge[$a.LicenseKey]
    $alertBadge = switch ($notifyAttr) {
        'na'      { New-BadgeHtml 'gray' 'Alerts: N/A' 'Not applicable: a service account does not receive alerts. Click for details.' '' '' $licOnClick }
        'set'     { New-BadgeHtml 'green' 'Alerts: Set' "An Email or Alternate email is set, so Entra alerts$(if ($script:pimBaseline) { ' (ID Protection, PIM)' }) have an address. Click for details." '' '' $licOnClick }
        default   { New-BadgeHtml $(if ((Get-DirectNotificationRoles $a).Count -gt 0) { 'amber' } else { 'blue' }) 'Alerts: Missing' "No Email or Alternate email is set. Entra alerts$(if ($script:pimBaseline) { ' (ID Protection, PIM)' }) reach nobody. Click for details." '' '' $licOnClick }
    }
    $licenseText = "<span class='perm-badges'>$(New-BadgeHtml $licBadgeInfo.Color $licBadgeInfo.Text $licBadgeInfo.Title '' '' $licOnClick)$alertBadge</span>"

    # Last sign-in
    $rows = @(
        New-ModalRowHtml @('Last successful sign-in', (Format-ReportDateTime $a.LastSuccessfulSignIn))
        $(if ((Format-ReportDateTime $a.LastInteractiveSignIn) -ne (Format-ReportDateTime $a.LastSuccessfulSignIn)) { New-ModalRowHtml @('Last interactive sign-in attempt', (Format-ReportDateTime $a.LastInteractiveSignIn)) })
        New-ModalRowHtml @('Last non-interactive sign-in attempt', (Format-ReportDateTime $a.LastNonInteractiveSignIn))
        New-ModalRowHtml @('Created', (Format-ReportDateTime $a.Created))
        New-ModalRowHtml @('User principal name', (ConvertTo-HtmlSafe $a.UserPrincipalName))
        New-ModalRowHtml @('Object ID', $key)
    ) -join ''
    $modal.Add("activityTitle: $(ConvertTo-JsString "Sign-in activity"), activityHtml: $(ConvertTo-JsString (New-ModalTableHtml 'mtActivity' @('Property', 'Value') $rows))")
    # Days since the last sign-in; "Never" sorts as the largest value, unknown just below it
    $activitySort = switch ($a.ActivityBucket) { 'unknown' { 999998 } 'notassessed' { 999998 } 'never' { 999999 } default { [int]$a.DaysSinceActivity } }
    $activityTip = if ($a.LastActivity) { "$(Format-ReportDateTime $a.LastActivity)$(if ($a.LastActivityIsApproximate) { ' (last sign-in attempt, may have failed)' })" } else { 'Click for sign-in details.' }
    # Stale colour: enabled accounts only; 90 days for a break-glass account, the inactive threshold for the others
    $staleDays = if ($a.IsBreakGlass) { 90 } else { $InactiveDays }
    $stale = $a.AccountEnabled -and ($a.ActivityBucket -eq 'never' -or ($a.ActivityBucket -eq 'inactive' -and $null -ne $a.DaysSinceActivity -and $a.DaysSinceActivity -ge $staleDays))
    $activityInner = switch ($a.ActivityBucket) {
        'notassessed' { "<span class='muted'>Not assessed</span>" }
        'unknown' { "<span class='muted'>Unknown</span>" }
        'never'   { "<span class='$(if ($stale) { 'activity-inactive' })'>Never</span>" }
        default {
            $cls = if ($stale) { 'activity-inactive' } else { '' }
            $daysText = if ($a.DaysSinceActivity -eq 0) { 'Today' } elseif ($a.DaysSinceActivity -eq 1) { '1 day' } else { "$($a.DaysSinceActivity) days" }
            "<span class='$cls'>$daysText</span>"
        }
    }    $activityText = "<span class='activity-link' onclick=`"$(Get-ModalOnClick $key 'activity')`" title='$(ConvertTo-HtmlSafe $activityTip)'>$activityInner</span>"

    # Findings
    $findingItems = ($a.Findings | ForEach-Object { "<li><span class='badge $($reasonBadge[$_.Level])'>$($reasonLabel[$_.Level])</span><span>$(ConvertTo-HtmlSafe $_.Text)$(if ($_.Detail) { "<div class='muted'>$(ConvertTo-HtmlSafe $_.Detail)</div>" })</span></li>" }) -join ''
    $html = if ($a.Findings.Count -gt 0) { "<ul class='reason-list'>$findingItems</ul>" } else { "<p class='muted'>No findings in the areas that were checked.</p>" }
    $notChecked = @($(if ($script:caBaseline -and -not $script:authDataAvailable) { 'authentication methods' }), $(if (-not $script:caDataAvailable) { 'access protection' }) | Where-Object { $_ })
    if ($notChecked.Count -gt 0) { $html += "<div class='modal-note'>Not checked in this run: $($notChecked -join ', ').</div>" }
    $modal.Add("findingsTitle: $(ConvertTo-JsString "Findings"), findingsHtml: $(ConvertTo-JsString $html)")
    $realFindings = @($a.Findings | Where-Object { $_.Level -ne 'info' }).Count
    $findingsLabel = if ($a.Severity -eq 'ok') { 'OK' } else { "$($reasonLabel[$a.Severity]) ($realFindings)" }
    $findingsText = New-BadgeHtml $reasonBadge[$a.Severity] $findingsLabel 'Click for the findings and recommendations.' '' '' (Get-ModalOnClick $key 'findings')

    # The person is stored once per user; the modals only carry their label as title
    $whoJs = "who: { name: $(ConvertTo-JsString $nameText), upn: $(ConvertTo-JsString $a.UserPrincipalName) }"
    $modalDataEntries.Add("`"$key`": { $whoJs, $($modal -join ', ') }")

    # CSV-only and search text
    $entraDetail  = @($entraRoles | ForEach-Object { "$($_.Role) ($($_.Type), $($_.Via), $($_.Scope))" }) -join ', '
    $caDetail     = @($a.CaPolicies | Where-Object { $_.Result -ne 'excluded' } | ForEach-Object { "$($_.Name) ($($_.RequirementLabel))" }) -join ', '
    $findingText  = @($a.Findings | ForEach-Object { "[$($reasonLabel[$_.Level])] $($_.Text)$(if ($_.Detail) { " ($($_.Detail))" })" }) -join ' | '
    $licenseNames = @($a.Skus | ForEach-Object { Get-LicenseFriendlyName $_ }) -join ' '
    $methodNames = @($a.Methods | ForEach-Object { $info = Get-MethodInfo $_; if ($info) { $info.Label } }) -join ' '
    $searchText = ConvertTo-HtmlSafe ((@($a.DisplayName, $a.UserPrincipalName, $a.Mail, $entraDetail, ($a.Skus -join ' '), $licenseNames, ($a.Methods -join ' '), $methodNames) | Where-Object { $_ }) -join ' ').ToLower()
    $rowClass = if ($a.Severity -in @('high', 'medium')) { "sev-$($a.Severity)" } else { '' }
    $bgValue = if ($a.IsBreakGlass) { 'yes' } elseif ($a.LikelyBreakGlass) { 'likely' } else { 'no' }
    $bgCsv = switch ($bgValue) { 'yes' { 'Break-glass' } 'likely' { 'Likely break-glass' } default { 'Regular admin' } }
    $flag = { param($value) if ($value) { 'yes' } else { 'no' } }

    [void]$sb.Append(@"
            <tr class="$rowClass" data-search="$searchText" data-sev="$($a.Severity)" data-source="$(if ($a.OnPremisesSynced) { 'onprem' } else { 'cloud' })" data-guestidp="$guestIdp" data-enabled="$(& $flag $a.AccountEnabled)" data-usertype="$($a.UserType)" data-ga="$(& $flag $hasGa)" data-privileged="$(& $flag $hasPrivileged)" data-standing="$(& $flag ($hasStanding -and -not $a.IsBreakGlass -and $a.SyncAccount -ne 'connector'))" data-scoped="$(& $flag $hasScoped)" data-eligible="$(& $flag ($eligibleCount -gt 0))" data-group="$(& $flag (@($a.Roles | Where-Object { $_.ViaGroupId }).Count -gt 0))" data-id="$key" data-auth="$authAttr"$fallbackAttr data-access="$accessAttr" data-device="$deviceAttr" data-loc="$locAttr" data-sync="$($a.SyncAccount)" data-license="$($a.LicenseKey)" data-notify="$notifyAttr" data-activity="$(if ($a.SyncAccount -eq 'connector') { 'na' } else { $a.ActivityBucket })" data-bg="$bgValue">
                <td data-sort="$($safeName.ToLower())"><a class="guest-name" href="$portalUrl" target="_blank" title="Open in Entra portal">$safeName</a><div class="muted csv-exclude" style="margin-top:4px">$(ConvertTo-HtmlSafe $a.UserPrincipalName)</div></td>
                <td class="cell-sm" data-sort="$activitySort">$activityText</td>
                <td class="cell-sm"><span class="perm-badges">$sourceText$nameBadges</span></td>
                <td class="cell-sm">$enabledText</td>
                <td class="cell-sm" data-sort="$($entraRoles.Count)"><span class="perm-badges">$entraText</span></td>
                <td class="cell-sm" data-sort="$($authRank[$authAttr])">$authText</td>
                <td class="cell-sm" data-sort="$accessSort">$caText</td>
                <td class="cell-sm" data-sort="$($a.LicenseKey) $notifyAttr">$licenseText</td>
                <td class="cell-sm" data-sort="$($severityOrder[$a.Severity])">$findingsText</td>
                <td class="csv-only">$key</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe $a.UserPrincipalName)</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe $a.Mail)</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe ($a.OtherMails -join ', '))</td>
                <td class="csv-only">$(if ($a.UserType -eq 'guest') { 'Guest' } else { 'Member' })</td>
                <td class="csv-only">$bgCsv</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe $entraDetail)</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe ($a.Methods -join ', '))</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe $caDetail)</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe $controlsDetail)</td>
                <td class="csv-only">$accessCsv</td>
                <td class="csv-only">$mfaReq</td>
                <td class="csv-only">$devReq</td>
                <td class="csv-only">$locReq</td>
                <td class="csv-only">$sifCsv</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe ($a.Skus -join ', '))</td>
                <td class="csv-only">$(if ($null -ne $a.DaysSinceActivity) { $a.DaysSinceActivity })</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe $findingText)</td>
                <td class="csv-only">$accountTypeText</td>
                <td class="csv-only">$caAvailCsv</td>
                <td class="csv-only">$sdCsv</td>
                <td class="csv-only">$authCsvTier</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe $a.AuthLabel)</td>
                <td class="csv-only">$weakCsv</td>
                <td class="csv-only">$(ConvertTo-HtmlSafe $a.GuestProvider)</td>
                <td class="csv-only">$trustCsv</td>
            </tr>
"@)
}

$reportDetailsBlock = "const reportDetails = {`n" + ($modalDataEntries -join ",`n") + "`n};"

[void]$sb.Append(@"
        </tbody>
    </table>
    </div>

    <script>
        $reportDetailsBlock
"@)

[void]$sb.Append(@'

        // Active filters: group -> Set of selected values (OR within a group, AND across groups)
        const activeFilters = {};
        const groupLabels = {
            sev: 'Severity', source: 'Source', enabled: 'Enabled', usertype: 'Source', access: 'Entra ID roles',
            auth: 'Auth methods', fallback: 'Fallback', guestidp: 'Source', protection: 'Access protection', device: 'Trusted device', loc: 'Trusted location', license: 'Licenses', notify: 'Alerts', activity: 'Last sign-in', bg: 'Break-glass', sync: 'Sync role'
        };
        const valueLabels = {
            scoped: 'Scoped role', sd: 'Security defaults', policy: 'Policy applies', strong: 'Strong', good: 'Good', mfaonly: 'MFA only', weak: 'Weak', na: 'N/A', 'fallback:weak': 'Weak fallback (SMS / Voice)',
            high: 'High', medium: 'Medium', low: 'Low', ok: 'OK',
            cloud: 'Cloud-only', onprem: 'On-prem synced',
            member: 'Member', guest: 'Guest',
            ga: 'Global Administrator', privileged: 'Privileged role', standing: 'Standing privileged', eligible: 'Eligible (PIM)', group: 'Via group',
            pr: 'Phishing-resistant', pwl: 'Passwordless', mfa: 'MFA', sf: 'Single factor', trusted: 'MFA trusted', microsoftentra: 'Guest: Microsoft Entra', google: 'Guest: Google', emailotp: 'Guest: Email OTP', microsoftaccount: 'Guest: Microsoft account', facebook: 'Guest: Facebook', samlwsfed: 'Guest: SAML/WS-Fed', localaccount: 'Guest: Local account', unknown: 'Unknown',
            partial: 'Partial', activation: 'After activation', none: 'None',
            mailbox: 'Mailbox', productivity: 'Productivity', other: 'Other', missing: 'Missing', set: 'Set',
            active: 'Active', inactive: 'Inactive', never: 'Never',
            yes: 'Yes', no: 'No', likely: 'Likely', connector: 'Entra Connect sync account', device: 'Compliant / Hybrid', optional: 'Optional', gsa: 'GSA network', ip: 'Trusted IP', country: 'Country', long: 'Above limit', unexpected: 'Sync role on other account'
        };

        function rowMatchesTag(row, group, value) {
            const d = row.dataset;
            switch (group) {
                case 'sev':      return d.sev === value;
                case 'source':   return d.source === value;
                case 'enabled':  return d.enabled === value;
                case 'usertype': return d.usertype === value;
                case 'auth':     return d.auth === value;
                case 'fallback': return d.fallback === value;
                case 'guestidp': return d.guestidp === value;
                case 'protection': return d.access === value;
                case 'device':   return d.device === value;
                case 'loc':      return d.loc === value;
                case 'license':  return d.license === value;
                case 'notify':   return d.notify === value;
                case 'activity': return d.activity === value;
                case 'bg':       return d.bg === value;
                case 'sync':     return d.sync === value;
                case 'access':   return d[value] === 'yes';
            }
            return false;
        }

        let _searchDebounceHandle = null;

        function queueApplyFilters() {
            if (_searchDebounceHandle) {
                clearTimeout(_searchDebounceHandle);
            }
            _searchDebounceHandle = setTimeout(applyFilters, 150);
        }

        function rowVisible(row) {
            const search = document.getElementById('searchInput').value.toLowerCase().trim();
            if (search && !(row.dataset.search || '').includes(search)) return false;
            for (const group in activeFilters) {
                const vals = activeFilters[group];
                if (!vals || vals.size === 0) continue;
                let any = false;
                vals.forEach(v => { if (rowMatchesTag(row, group, v)) any = true; });
                if (!any) return false;
            }
            return true;
        }

        function applyFilters() {
            const rows = document.querySelectorAll('#reportTable tbody tr');
            let shown = 0;
            rows.forEach(row => {
                const ok = rowVisible(row);
                row.style.display = ok ? '' : 'none';
                if (ok) shown++;
            });
            document.getElementById('resultCount').textContent =
                'Showing ' + shown + ' of ' + rows.length + ' admins';
            renderActiveChips();

            const search = document.getElementById('searchInput').value.trim();
            let activeCount = (search ? 1 : 0);
            for (const g in activeFilters) activeCount += activeFilters[g].size;
            const summary = document.getElementById('filterSummary');
            if (activeCount > 0) {
                summary.textContent = activeCount + ' filter' + (activeCount > 1 ? 's' : '') +
                    ' \u00b7 showing ' + shown + ' of ' + rows.length;
                summary.style.display = '';
            } else {
                summary.style.display = 'none';
            }
        }

        function toggleFilterPanel(forceShow) {
            const panel = document.getElementById('controlsPanel');
            const btn = document.getElementById('filterToggle');
            const show = forceShow === true ? true : panel.hasAttribute('hidden');
            if (show) { panel.removeAttribute('hidden'); } else { panel.setAttribute('hidden', ''); }
            btn.setAttribute('aria-expanded', show ? 'true' : 'false');
            btn.querySelector('.caret').innerHTML = show ? '&#9662;' : '&#9656;';
        }

        function addFilter(group, value) {
            if (!activeFilters[group]) activeFilters[group] = new Set();
            if (!activeFilters[group].has(value)) {
                activeFilters[group].add(value);
                const tag = document.querySelector('.filter-tag[data-group="' + group + '"][data-value="' + value + '"]');
                if (tag) tag.classList.add('active');
            }
            applyFilters();
        }

        // Clickable spans and divs get a button role, a tab stop and Enter / Space
        function makeButtons(root) {
            root.querySelectorAll('.filter-tag, .summary-card, .clickable-badge, .tenant-line.clickable, .ap-pill, .activity-link, th[onclick]').forEach(el => {
                if (el.getAttribute('role')) return;
                el.setAttribute('role', 'button');
                el.setAttribute('tabindex', '0');
            });
        }
        document.addEventListener('keydown', function (e) {
            if ((e.key === 'Enter' || e.key === ' ') && e.target.matches && e.target.matches('[role="button"]')) { e.preventDefault(); e.target.click(); }
        });

        function toggleTag(el) {
            const group = el.dataset.group, value = el.dataset.value;
            if (!activeFilters[group]) activeFilters[group] = new Set();
            if (activeFilters[group].has(value)) {
                activeFilters[group].delete(value);
                el.classList.remove('active');
            } else {
                activeFilters[group].add(value);
                el.classList.add('active');
            }
            applyFilters();
        }

        function renderActiveChips() {
            const wrap = document.getElementById('activeChips');
            const chips = [];
            for (const group in activeFilters) {
                activeFilters[group].forEach(v => {
                    const tagEl = document.querySelector('.filter-tag[data-group="' + group + '"][data-value="' + v + '"]');
                    const colorClass = tagEl ? (Array.from(tagEl.classList).find(c => c.startsWith('c-')) || '') : '';
                    chips.push('<span class="chip ' + colorClass + '" onclick="removeFilter(\'' + group + '\',\'' + v + '\')">' + groupLabels[group] + ': ' + (valueLabels[group + ':' + v] || valueLabels[v] || v) + ' &times;</span>');
                });
            }
            wrap.innerHTML = chips.join('');
            document.getElementById('clearAll').style.display = chips.length ? '' : 'none';
        }

        function removeFilter(group, value) {
            if (activeFilters[group]) activeFilters[group].delete(value);
            const el = document.querySelector('.filter-tag[data-group="' + group + '"][data-value="' + value + '"]');
            if (el) el.classList.remove('active');
            applyFilters();
        }

        function clearAllFilters() {
            for (const group in activeFilters) activeFilters[group].clear();
            document.querySelectorAll('.filter-tag.active').forEach(el => el.classList.remove('active'));
            document.getElementById('searchInput').value = '';
            applyFilters();
        }

        function computeTagCounts() {
            const rows = Array.from(document.querySelectorAll('#reportTable tbody tr'));
            document.querySelectorAll('.filter-tag').forEach(el => {
                const group = el.dataset.group, value = el.dataset.value;
                const n = rows.filter(r => rowMatchesTag(r, group, value)).length;
                el.querySelector('.cnt').textContent = '(' + n + ')';
                el.style.display = n === 0 ? 'none' : '';
            });
            document.querySelectorAll('.filter-group').forEach(g => {
                const tags = Array.from(g.querySelectorAll('.filter-tag'));
                g.style.display = tags.length && tags.every(t => t.style.display === 'none') ? 'none' : '';
            });
        }

        // Cells can carry a data-sort value (ISO date, recommendation priority, ...) that
        // sorts better than their displayed text
        let _sortCol = -1, _sortAsc = true;
        const _modalSortState = {};
        function sortTable(tableId, columnIndex, type) {
            const table = document.getElementById(tableId);
            if (!table) return;
            let state;
            if (tableId === 'reportTable') {
                if (_sortCol === columnIndex) { _sortAsc = !_sortAsc; } else { _sortCol = columnIndex; _sortAsc = type !== 'number'; }
                state = { col: _sortCol, asc: _sortAsc };
            } else {
                state = _modalSortState[tableId] || { col: -1, asc: true };
                if (state.col === columnIndex) { state.asc = !state.asc; } else { state.col = columnIndex; state.asc = type !== 'number'; }
                _modalSortState[tableId] = state;
            }
            const dir = state.asc ? 1 : -1;
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const cellValue = cell => (cell.dataset.sort !== undefined ? cell.dataset.sort : cell.textContent).trim();

            const compare = (a, b) => {
                let aVal = cellValue(a.cells[columnIndex]);
                let bVal = cellValue(b.cells[columnIndex]);
                if (type === 'number') {
                    aVal = parseInt(aVal.replace(/[^0-9]/g, '')) || 0;
                    bVal = parseInt(bVal.replace(/[^0-9]/g, '')) || 0;
                    return (aVal - bVal) * dir;
                }
                return aVal.localeCompare(bVal) * dir;
            };

            // A grouped table (the roles modal) is sorted only between two group header rows; the headers and the
            // placeholder rows never move
            const isGroupRow = row => row.classList.contains('role-group') || row.classList.contains('role-empty');
            if (rows.some(isGroupRow)) {
                let run = [];
                const flush = () => { run.sort(compare).forEach(row => tbody.appendChild(row)); run = []; };
                rows.forEach(row => { if (isGroupRow(row)) { flush(); tbody.appendChild(row); } else { run.push(row); } });
                flush();
            } else {
                rows.sort(compare);
                rows.forEach(row => tbody.appendChild(row));
            }

            table.querySelectorAll('thead th').forEach(th => {
                th.classList.remove('sort-asc', 'sort-desc');
                th.removeAttribute('aria-sort');
            });
            const sortedHeader = table.querySelectorAll('thead th')[columnIndex];
            sortedHeader?.classList.add(state.asc ? 'sort-asc' : 'sort-desc');
            sortedHeader?.setAttribute('aria-sort', state.asc ? 'ascending' : 'descending');
        }

        function exportCsv() {
            // The CSV keeps the original column order; Last sign-in (second on screen) stays after Licenses & alerts
            const csvOrder = n => { const o = Array.from({ length: n }, (_, i) => i); o.splice(1, 1); o.splice(7, 0, 1); return o; };
            const headers = Array.from(document.querySelectorAll('#reportTable thead th'))
                .map(th => th.textContent.replace(/[\u25B2\u25BC]/g, '').trim());
            const order = csvOrder(headers.length);

            const visibleRows = Array.from(document.querySelectorAll('#reportTable tbody tr'))
                .filter(tr => tr.style.display !== 'none');

            // Neutralize leading formula characters so a hostile value (e.g. a guest display
            // name starting with '=') cannot execute as a formula when opened in Excel.
            const esc = v => {
                let s = String(v);
                if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
                return '"' + s.replace(/"/g, '""') + '"';
            };

            const lines = [order.map(i => headers[i]).map(esc).join(';')];
            visibleRows.forEach(tr => {
                const cells = Array.from(tr.cells).map(td => {
                    const clone = td.cloneNode(true);
                    clone.querySelectorAll('.csv-exclude').forEach(n => n.remove());
                    return esc(clone.textContent.trim().replace(/\s+/g, ' '));
                });
                lines.push(order.map(i => cells[i]).join(';'));
            });

            // UTF-8 BOM ensures Excel opens the file with correct encoding
            downloadFile('\uFEFF' + lines.join('\r\n'), 'EntraIDAdminReport_' + new Date().toISOString().slice(0, 10) + '.csv');
        }

        function downloadFile(content, fileName) {
            const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
            const url  = URL.createObjectURL(blob);
            const a    = document.createElement('a');
            a.href     = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        let _modalTrigger = null;

        function openDetailModal(eyebrow, html, who) {
            _modalTrigger = document.activeElement;
            const name = who && who.name ? who.name : '';
            const upn  = who && who.upn  ? who.upn  : '';
            document.getElementById('detailModalEyebrow').textContent = eyebrow;
            document.getElementById('detailModalTitle').textContent = name || eyebrow;
            const sub = document.getElementById('detailModalSub');
            const showUpn = upn && upn !== name;          // no duplicate line when the name already is the UPN
            sub.textContent = showUpn ? upn : '';
            sub.hidden = !showUpn;
            document.getElementById('detailModalBody').innerHTML = html;
            makeButtons(document.getElementById('detailModalBody'));
            document.getElementById('detailModalOverlay').classList.add('active');
            document.querySelector('#detailModalOverlay .modal-box').scrollTop = 0;
            document.querySelector('.modal-close').focus();
            for (const id in _modalSortState) delete _modalSortState[id];
        }

        function closeDetailModal() {
            document.getElementById('detailModalOverlay').classList.remove('active');
            if (_modalTrigger) { _modalTrigger.focus(); _modalTrigger = null; }
        }

        function toggleTheme() {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const next = isDark ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            document.getElementById('themeToggle').innerHTML = next === 'dark' ? '&#9728;&#65039;' : '&#127769;';
            localStorage.setItem('entra-report-theme', next);
        }

        (function () {
            const saved = localStorage.getItem('entra-report-theme') || 'light';
            document.documentElement.setAttribute('data-theme', saved);
            document.getElementById('themeToggle').innerHTML = saved === 'dark' ? '&#9728;&#65039;' : '&#127769;';

            document.getElementById('reportTable').addEventListener('click', function (e) {
                const badge = e.target.closest('.clickable-badge');
                if (!badge) return;
                const group = badge.dataset.fg, value = badge.dataset.fv;
                if (!group || !value) return;
                addFilter(group, value);
                toggleFilterPanel(true);
            });

            // A card can map to several values of one group (e.g. Inactive = inactive + stale)
            document.querySelectorAll('.summary, .tenant-findings').forEach(box => box.addEventListener('click', function (e) {
                const card = e.target.closest('.summary-card, .tenant-line');
                if (!card) return;
                if (card.dataset.clear) { clearAllFilters(); return; }
                const group = card.dataset.fg, value = card.dataset.fv;
                if (!group || !value) return;
                value.split(',').forEach(v => addFilter(group, v));
                toggleFilterPanel(true);
                document.getElementById('reportTable').scrollIntoView({ behavior: 'smooth', block: 'start' });
            }));

            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') closeDetailModal();
            });

            makeButtons(document);
            computeTagCounts();
            applyFilters();
        })();
    </script>

    <div id="detailModalOverlay" class="modal-overlay" onclick="if(event.target===this) closeDetailModal()">
        <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="detailModalEyebrow detailModalTitle" aria-describedby="detailModalBody">
            <button class="modal-close" onclick="closeDetailModal()" aria-label="Close">&times;</button>
            <div class="modal-heading">
                <div id="detailModalEyebrow" class="modal-eyebrow"></div>
                <h3 id="detailModalTitle"></h3>
                <div id="detailModalSub" class="modal-sub" hidden></div>
            </div>
            <div id="detailModalBody"></div>
        </div>
    </div>
    </div>
'@)

[void]$sb.Append(@"

    <footer class="report-footer">
        Copyright &copy; 2026 <a href="https://www.matej.guru/about" target="_blank" rel="noopener">Matej Klemencic</a> &middot; $ScriptVersion
    </footer>
</body>
</html>
"@)

$html = $sb.ToString()

# Save the HTML report - UTF-8 without BOM for consistent output across PS 5.1 and PS 7
if ($DryRun) {
    Write-Host "DryRun: skipping report write to '$OutputPath'" -ForegroundColor Yellow
} else {
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Report generated successfully: $OutputPath" -ForegroundColor Green

    # Open the report in default browser (interactive mode only)
    if (-not $NonInteractive) {
        Write-Host "Opening report in default browser..." -ForegroundColor Green
        Start-Process ([System.IO.Path]::GetFullPath($OutputPath))
    }
}

# Display summary statistics in console
Write-Host "`n=== REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Administrator accounts: $totalAdmins" -ForegroundColor White
Write-Host "`nSeverity:" -ForegroundColor White
Write-Host "  - High: $highCount" -ForegroundColor Red
Write-Host "  - Medium: $mediumCount" -ForegroundColor Yellow
Write-Host "  - Low: $lowCount" -ForegroundColor Gray
Write-Host "  - OK: $okCount" -ForegroundColor Green
Write-Host "`nSignals:" -ForegroundColor White
Write-Host "  - Global Administrators (active or eligible): $globalAdminCount (recommended: fewer than $GlobalAdminLimit)" -ForegroundColor White
Write-Host "  - Active privileged role assignments: $privilegedAssignmentCount (recommended: fewer than $PrivilegedAssignmentLimit)" -ForegroundColor White
Write-Host "  - On-premises synced: $onPremCount" -ForegroundColor Red
if ($script:pimBaseline) { Write-Host "  - Permanent admin roles: $standingCount" -ForegroundColor DarkYellow }
Write-Host "  - Mailbox licensed: $mailboxCount" -ForegroundColor DarkYellow
if ($script:caBaseline -and $script:signInDataAvailable) { Write-Host "  - Inactive ($InactiveDays+ days or never): $inactiveCount" -ForegroundColor DarkYellow }
if ($script:caBaseline -and $script:authDataAvailable)   { Write-Host "  - No phishing-resistant method: $noPhishingResistantCount" -ForegroundColor DarkYellow }
if ($script:caBaseline -and $script:caDataAvailable) { Write-Host "  - Access protection gaps: $accessGapCount" -ForegroundColor DarkYellow }
Write-Host "  - Break-glass accounts: $breakGlassCount named, $likelyBreakGlassCount more look like one" -ForegroundColor Gray
Write-Host "  - Entra Connect sync accounts (service accounts, checked separately): $connectorCount$(if ($unexpectedSyncCount -gt 0) { ", PLUS $unexpectedSyncCount other account(s) holding the sync role" })" -ForegroundColor $(if ($unexpectedSyncCount -gt 0) { 'Red' } else { 'Gray' })
$skipped = @($(if ($BreakGlassAccounts.Count -eq 0) { '-BreakGlassAccounts' }) | Where-Object { $_ })
if ($skipped.Count -gt 0) { Write-Host "`nNot collected in this run (add the parameter to include it): $($skipped -join ', ')" -ForegroundColor Gray }

# Azure DevOps integration - emit pipeline-native signals when running on an ADO agent
# (TF_BUILD is set by the agent). No effect on local or interactive runs.
if ($env:TF_BUILD -eq 'True') {
    if ($highCount -gt 0) {
        Write-Host "##vso[task.logissue type=warning]$highCount administrator account(s) have high-severity findings - review the EntraIDAdminReport artifact."
        Write-Host "##vso[task.complete result=SucceededWithIssues;]Administrator accounts with high-severity findings found"
    }

    # Markdown summary shown as a tab on the pipeline run (same numbers as the console summary)
    $adoSummaryMd = @"
# Entra ID Administrator Report - $tenantName

Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; **$totalAdmins** administrator accounts analyzed

| Severity | Accounts |
|----------|----------|
| High | $highCount |
| Medium | $mediumCount |
| Low | $lowCount |
| OK | $okCount |

| Signal | Count |
|--------|-------|
| Global Administrators (active or eligible) | $globalAdminCount |
| Active privileged role assignments | $privilegedAssignmentCount |
| On-premises synced | $onPremCount |
| Permanent admin roles | $(if ($script:pimBaseline) { $standingCount } else { 'not assessed' }) |
| Mailbox licensed | $mailboxCount |
| Inactive ($InactiveDays+ days or never) | $(if ($script:caBaseline -and $script:signInDataAvailable) { $inactiveCount } else { 'not assessed' }) |
| No phishing-resistant method | $(if ($script:caBaseline -and $script:authDataAvailable) { $noPhishingResistantCount } else { 'not assessed' }) |
| Access protection gaps | $(if ($script:caBaseline -and $script:caDataAvailable) { $accessGapCount } else { 'not assessed' }) |
| Break-glass accounts named | $breakGlassCount |
| Entra Connect sync accounts (service accounts) | $connectorCount |
| Other accounts holding the sync role | $unexpectedSyncCount |

$(if ($skipped.Count -gt 0) { "Not collected in this run: $($skipped -join ', ')." })

Download the full interactive HTML report from the **EntraIDAdminReport** pipeline artifact.
"@
    $adoSummaryPath = Join-Path ([System.IO.Path]::GetTempPath()) 'EntraIDAdminReport-summary.md'
    [System.IO.File]::WriteAllText($adoSummaryPath, $adoSummaryMd, [System.Text.UTF8Encoding]::new($false))
    Write-Host "##vso[task.uploadsummary]$adoSummaryPath"
}

    Write-Host "`nScript completed successfully!" -ForegroundColor Green

} finally {
    # Guaranteed to run even if the script throws - keeps Graph sessions clean
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
