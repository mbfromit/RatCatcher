#Requires -Version 5.1
<#
.SYNOPSIS
    RatCatcher — scans for evidence of the March 31, 2026 Axios NPM supply chain attack.
.DESCRIPTION
    Runs ten checks covering the full compromise kill chain:
    lockfile evidence, deployed package artifacts, npm cache, dropped RAT payloads,
    persistence mechanisms, XOR-obfuscated indicators, and network evidence.
    Generates a forensic report and submits results to the RatCatcher dashboard.
.PARAMETER Path
    Root directories to scan for Node.js projects. Defaults to common dev locations.
.PARAMETER OutputPath
    Directory for report and log files.
.EXAMPLE
    .\Invoke-RatCatcher.ps1
.EXAMPLE
    .\Invoke-RatCatcher.ps1 -Path C:\Dev
#>
[CmdletBinding()]
param(
    [string[]]$Path         = $(if ($env:OS -eq 'Windows_NT') { @('C:\') } else { @('/') }),
    [string]$OutputPath     = $(if ($env:OS -eq 'Windows_NT') { 'C:\Logs' } else { '/tmp' }),
    [switch]$NoSubmit,
    [switch]$NonInteractive,
    [switch]$NoVerify,
    [string]$SubmitPassword,
    [int]$Threads           = 4,
    [string]$OllamaUrl      = 'http://192.168.1.203:11434',
    [string]$OllamaModel    = 'gemma4:26b',
    # Test-artifact overrides — point at synthetic data without touching real npm cache or firewall log
    [string]$TestCacheDir,
    [string]$TestFirewallLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$RatCatcherVersion = '1.1.0'

$pvt = Join-Path $PSScriptRoot 'Private'
. (Join-Path $pvt 'Get-NodeProjects.ps1')
. (Join-Path $pvt 'Invoke-LockfileAnalysis.ps1')
. (Join-Path $pvt 'Find-ForensicArtifacts.ps1')
. (Join-Path $pvt 'Invoke-NpmCacheScan.ps1')
. (Join-Path $pvt 'Search-DroppedPayloads.ps1')
. (Join-Path $pvt 'Find-PersistenceArtifacts.ps1')
. (Join-Path $pvt 'Search-XorEncodedC2.ps1')
. (Join-Path $pvt 'Get-NetworkEvidence.ps1')
. (Join-Path $pvt 'New-ScanReport.ps1')
. (Join-Path $pvt 'New-ExecBriefing.ps1')
. (Join-Path $pvt 'New-ScanLogHtml.ps1')
. (Join-Path $pvt 'Send-ScanReport.ps1')
. (Join-Path $pvt 'Submit-ScanToApi.ps1')
. (Join-Path $pvt 'Invoke-FindingVerification.ps1')

# Load logo for HTML reports (resize to ~600px to keep embedded size reasonable)
$logoBase64 = ''
$logoFile   = Join-Path $PSScriptRoot 'RatCatcher.png'
if (Test-Path $logoFile) {
    try { $logoBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($logoFile)) } catch { }
}


# ── Resolve scan paths (expand drive roots, skip OS/system folders) ───────────
$excludedTopLevel = @(
    'Windows', 'Program Files', 'Program Files (x86)',
    'ProgramData', 'Recovery', 'System Volume Information',
    'MSOCache', 'OneDriveTemp', '$Recycle.Bin', 'Config.Msi'
)

$resolvedPaths = [System.Collections.Generic.List[string]]::new()
foreach ($root in $Path) {
    $rootItem = Get-Item -LiteralPath $root -ErrorAction SilentlyContinue
    if (-not $rootItem) { Write-Warning "Path not found, skipping: $root"; continue }

    # If the user passed a drive root (e.g. C:\), expand to its immediate subdirectories
    # so we can exclude OS folders and show the user exactly what will be scanned
    if ($rootItem.FullName -match '^[A-Za-z]:\\?$') {
        Get-ChildItem -LiteralPath $rootItem.FullName -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin $excludedTopLevel -and $_.Name -notmatch '^\$' } |
        ForEach-Object { $resolvedPaths.Add($_.FullName) }
    } else {
        $resolvedPaths.Add($rootItem.FullName)
    }
}

# ── Confirmation prompt ────────────────────────────────────────────────────────
Write-Host ''
Write-Host '================================================================'
Write-Host "  RATCATCHER v$RatCatcherVersion"
Write-Host '================================================================'
Write-Host ''
Write-Host '  The following folders will be scanned on this machine:'
Write-Host ''
foreach ($p in $resolvedPaths) { Write-Host "    $p" }
Write-Host ''
Write-Host '  Skipped (OS/system):' ($excludedTopLevel -join ', ')
Write-Host ''
if ($NonInteractive) {
    Write-Host '  [NonInteractive] Skipping confirmation — starting scan automatically.'
} else {
    $confirm = Read-Host '  Press ENTER to start the scan, or type Q to quit'
    if ($confirm -match '^[Qq]') { Write-Host 'Scan cancelled.'; exit 0 }
}
Write-Host ''

# ── Submission password ───────────────────────────────────────────────────────
if (-not $NoSubmit) {
    if ($SubmitPassword) {
        $submitPassword = $SubmitPassword
    } else {
        Write-Host '  A submission password is required to run the scan.'
        Write-Host '  Contact your manager or the DevOps team if you do not have one.'
        Write-Host ''
        $submitPassword = Read-Host '  Enter RatCatcher submission password'
        if ([string]::IsNullOrWhiteSpace($submitPassword)) {
            Write-Host ''
            Write-Host '  No password entered — scan cancelled.'
            exit 0
        }
    }
    Write-Host ''
}

$null = New-Item -ItemType Directory -Path $OutputPath -Force
$hn   = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } elseif ($env:HOSTNAME) { $env:HOSTNAME } else { 'unknown' }
$ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
$log  = Join-Path $OutputPath "RatCatcher-${hn}-${ts}.log"

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$Level] $Msg"
    Write-Host $line
    Add-Content -Path $log -Value $line -ErrorAction SilentlyContinue
}

$attackWindow = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
$startTime    = Get-Date

Write-Log "RatCatcher - 10-check suite"
Write-Log "Attack window start: $attackWindow"
Write-Log "Scanning paths: $($resolvedPaths -join ', ')"

# ── Check 1: Discover Node.js projects ────────────────────────────────────────
Write-Log "[1/10] Discovering Node.js projects..."
$projects = @(Get-NodeProjects -Path $resolvedPaths)
Write-Log "Found $($projects.Count) project(s)"

# ── Checks 2 & 3: Lockfile analysis + artifact detection (parallel on PS7) ───
if ($PSVersionTable.PSVersion.Major -ge 7 -and $projects.Count -gt 0) {
    Write-Log "[2/10] Analysing lockfiles (parallel, $Threads threads)..."
    $lockfileResults = @($projects | ForEach-Object -Parallel {
        . (Join-Path $using:pvt 'Invoke-LockfileAnalysis.ps1')
        Invoke-LockfileAnalysis -ProjectPath $_.ProjectPath
    } -ThrottleLimit $Threads)

    Write-Log "[3/10] Detecting project-level forensic artifacts (parallel)..."
    $rawArtifacts = @($projects | ForEach-Object -Parallel {
        . (Join-Path $using:pvt 'Find-ForensicArtifacts.ps1')
        Find-ForensicArtifacts -ProjectPath $_.ProjectPath
    } -ThrottleLimit $Threads)
} else {
    Write-Log "[2/10] Analysing lockfiles (sequential)..."
    $lockfileResults = @($projects | ForEach-Object { Invoke-LockfileAnalysis -ProjectPath $_.ProjectPath })
    Write-Log "[3/10] Detecting project-level forensic artifacts..."
    $rawArtifacts    = @($projects | ForEach-Object { Find-ForensicArtifacts -ProjectPath $_.ProjectPath })
}
# Ensure these are always arrays even if checks 2/3 were skipped (no projects found)
if (-not $lockfileResults) { $lockfileResults = @() }
if (-not $rawArtifacts)    { $rawArtifacts    = @() }
$artifacts = @($rawArtifacts | Where-Object { $_ })

# ── Check 4: npm cache ────────────────────────────────────────────────────────
Write-Log "[4/10] Scanning npm cache and global npm..."
$cacheFindings = @(Invoke-NpmCacheScan -CacheDirOverride $TestCacheDir)

# ── Check 5: Dropped payloads ─────────────────────────────────────────────────
Write-Log "[5/10] Searching for dropped RAT payloads in temp/appdata..."
$droppedPayloads = @(Search-DroppedPayloads -AttackWindowStart $attackWindow)

# ── Check 6: Persistence ──────────────────────────────────────────────────────
Write-Log "[6/10] Checking persistence mechanisms (tasks, registry, startup)..."
$persistenceArtifacts = @(Find-PersistenceArtifacts -AttackWindowStart $attackWindow)

# ── Check 7: XOR-encoded indicators ──────────────────────────────────────────
Write-Log "[7/10] Scanning for XOR-encoded C2 indicators..."
$xorFindings = @(Search-XorEncodedC2)

# ── Check 8: Network evidence ─────────────────────────────────────────────────
Write-Log "[8/10] Checking network evidence (DNS cache, active connections, firewall log)..."
$neParams = @{}
if ($TestFirewallLogPath) { $neParams['FirewallLogPath'] = $TestFirewallLogPath }
$networkEvidence = @(Get-NetworkEvidence @neParams)

# ── AI Verification: annotate findings via local LLM ─────────────────────────
if (-not $NoVerify) {
    Write-Log "[AI] Verifying findings against local LLM ($OllamaModel)..."
    $verifyParams = @{ OllamaUrl = $OllamaUrl; Model = $OllamaModel }

    $categoriesToVerify = @(
        @{ Name = 'Forensic Artifacts';    Ref = 'artifacts' }
        @{ Name = 'npm Cache';             Ref = 'cacheFindings' }
        @{ Name = 'Dropped Payloads';      Ref = 'droppedPayloads' }
        @{ Name = 'Persistence Artifacts'; Ref = 'persistenceArtifacts' }
        @{ Name = 'XOR-Encoded C2';        Ref = 'xorFindings' }
        @{ Name = 'Network Evidence';      Ref = 'networkEvidence' }
    )

    $totalVerified = 0

    foreach ($cat in $categoriesToVerify) {
        $findings = Get-Variable -Name $cat.Ref -ValueOnly
        if (-not $findings -or $findings.Count -eq 0) { continue }
        Write-Log "[AI] Verifying $($findings.Count) finding(s) in '$($cat.Name)'..."

        $verifiedFindings = Invoke-FindingVerification `
            -Findings $findings `
            -FindingCategory $cat.Name `
            @verifyParams

        $totalVerified += $verifiedFindings.Count

        foreach ($f in $verifiedFindings) {
            Write-Log "[AI] $($f.AiVerdict): $($f.Type) — $($f.AiReason)" 'INFO'
        }

        # Write annotated findings back (all kept, just annotated)
        Set-Variable -Name $cat.Ref -Value $verifiedFindings
    }

    Write-Log "[AI] Verification complete: $totalVerified finding(s) annotated with AI verdicts"
} else {
    Write-Log "[AI] LLM verification skipped (-NoVerify)"
}

# ── Compute aggregate AI verdict ──────────────────────────────────────────────
$aiVerdict = $null
if (-not $NoVerify) {
    $allFindingsList = @($artifacts) + @($cacheFindings) + @($droppedPayloads) +
                       @($persistenceArtifacts) + @($xorFindings) + @($networkEvidence)
    if ($allFindingsList.Count -eq 0) {
        $aiVerdict = 'AI_CLEAN'
    } else {
        $successfulVerdicts = @($allFindingsList | Where-Object { $_.AiVerdict -and $_.AiVerdict -ne 'Error' })
        if ($successfulVerdicts.Count -gt 0) {
            if ($successfulVerdicts | Where-Object { $_.AiVerdict -in 'Confirmed', 'Likely' }) {
                $aiVerdict = 'AI_COMPROMISE'
            } else {
                $aiVerdict = 'AI_FALSE_POSITIVE'
            }
        }
    }
    Write-Log "[AI] Aggregate verdict: $(if ($aiVerdict) { $aiVerdict } else { 'null (all findings errored)' })"
}

# ── Check 9: Generate report ──────────────────────────────────────────────────
$duration = (Get-Date) - $startTime
$metadata = @{
    Timestamp = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
    Hostname  = $hn
    Username  = if ($env:USERNAME) { $env:USERNAME } elseif ($env:USER) { $env:USER } else { 'unknown' }
    Duration  = "$([Math]::Round($duration.TotalSeconds,1))s"
    Paths     = $Path
}

Write-Log "[9/10] Generating forensic report..."
$reportPath = New-ScanReport `
    -Projects             $projects `
    -LockfileResults      @($lockfileResults) `
    -Artifacts            $artifacts `
    -CacheFindings        $cacheFindings `
    -DroppedPayloads      $droppedPayloads `
    -PersistenceArtifacts $persistenceArtifacts `
    -XorFindings          $xorFindings `
    -NetworkEvidence      $networkEvidence `
    -OutputPath           $OutputPath `
    -ScanMetadata         $metadata `
    -LogoBase64           $logoBase64 `
    -AiVerdict            $aiVerdict

Write-Log "Technical report: $reportPath"

# Convert scan log to HTML now so its filename is available for the briefing link
Write-Log "[9a/10] Converting scan log to HTML..."
# (this Write-Log call is the last entry — flush then convert)
$logHtmlPath = New-ScanLogHtml -LogPath $log -LogoBase64 $logoBase64 -ScanMetadata $metadata
$log = $logHtmlPath   # update $log so summary still refers to correct file

# ── Check 9b: Executive Briefing ──────────────────────────────────────────────
Write-Log "[9b/10] Generating executive briefing..."
$briefingPath = New-ExecBriefing `
    -ProjectCount         $projects.Count `
    -LockfileResults      @($lockfileResults) `
    -Artifacts            $artifacts `
    -CacheFindings        $cacheFindings `
    -DroppedPayloads      $droppedPayloads `
    -PersistenceArtifacts $persistenceArtifacts `
    -XorFindings          $xorFindings `
    -NetworkEvidence      $networkEvidence `
    -TechnicalReportPath  $reportPath `
    -LogHtmlPath          $logHtmlPath `
    -OutputPath           $OutputPath `
    -ScanMetadata         $metadata `
    -LogoBase64           $logoBase64 `
    -AiVerdict            $aiVerdict

Write-Log "Executive briefing: $briefingPath"

# ── Check 10: Submit to dashboard ─────────────────────────────────────────────
$vulnCount      = @($lockfileResults | Where-Object { $_.HasVulnerableAxios -or $_.HasMaliciousPlainCrypto }).Count
$criticalCount  = @($artifacts + $cacheFindings + $droppedPayloads + $persistenceArtifacts + $xorFindings + $networkEvidence | Where-Object { $_.Severity -eq 'Critical' }).Count

if (-not $NoSubmit) {
    Write-Log "[10/10] Submitting results to dashboard..."
    $submitVerdict  = if ($vulnCount -gt 0 -or $criticalCount -gt 0) { 'COMPROMISED' } else { 'CLEAN' }

    $submitResult = Submit-ScanToApi `
        -ApiUrl          'https://mbfromit.com/ratcatcher-dev/submit' `
        -Password        $submitPassword `
        -Hostname        $hn `
        -Username        $metadata.Username `
        -ScanTimestamp   $metadata.Timestamp `
        -Duration        $metadata.Duration `
        -Verdict         $submitVerdict `
        -ProjectsScanned $projects.Count `
        -VulnerableCount $vulnCount `
        -CriticalCount   $criticalCount `
        -PathsScanned    ($resolvedPaths | ConvertTo-Json -Compress) `
        -BriefPath       $briefingPath `
        -ReportPath      $reportPath `
        -AiVerdict       $aiVerdict

    switch ($submitResult.Status) {
        'success'        { Write-Log "[INFO] Scan submitted successfully (ID: $($submitResult.Id))" }
        'wrong-password' { Write-Log 'Submission password incorrect — report not submitted' 'WARN' }
        'error'          { Write-Log "Submission failed: $($submitResult.Message)" 'WARN' }
    }
} else {
    Write-Log "[10/10] Dashboard submission skipped (-NoSubmit)"
}

Write-Log ''
Write-Log "═══════════════════════════════════════"
Write-Log " SCAN COMPLETE - $(Get-Date -Format 'HH:mm:ss')"
Write-Log " Projects scanned    : $($projects.Count)"
Write-Log " Vulnerable (lockfile): $vulnCount"
Write-Log " Critical findings   : $criticalCount"
Write-Log " Technical report    : $reportPath"
Write-Log " Executive briefing  : $briefingPath"

# ── Launch briefing in browser ────────────────────────────────────────────────
Write-Log "Opening executive briefing in browser..."
try { Start-Process $briefingPath } catch { Write-Log "Could not auto-launch briefing: $_" 'WARN' }

if ($vulnCount -gt 0 -or $criticalCount -gt 0) {
    Write-Log ' STATUS: COMPROMISED - isolate machine and review reports' 'WARN'
} else {
    Write-Log ' STATUS: CLEAN - no compromise evidence found across all 10 checks'
}

Write-Log ''
Write-Log '═══════════════════════════════════════'
Write-Log ' SECURITY REMINDER'
Write-Log ' If you changed your ExecutionPolicy to run this scan,'
Write-Log ' restore it now by closing this window or running:'
Write-Log '   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted'
Write-Log '═══════════════════════════════════════'

if ($vulnCount -gt 0 -or $criticalCount -gt 0) { exit 1 } else { exit 0 }
