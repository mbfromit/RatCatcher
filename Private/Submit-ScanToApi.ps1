function Submit-ScanToApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ApiUrl,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$Hostname,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$ScanTimestamp,
        [Parameter(Mandatory)][string]$Duration,
        [Parameter(Mandatory)][string]$Verdict,
        [Parameter(Mandatory)][int]$ProjectsScanned,
        [Parameter(Mandatory)][int]$VulnerableCount,
        [Parameter(Mandatory)][int]$CriticalCount,
        [Parameter(Mandatory)][string]$PathsScanned,
        [Parameter(Mandatory)][string]$BriefPath,
        [Parameter(Mandatory)][string]$ReportPath
    )

    if ([string]::IsNullOrEmpty($Password)) {
        return @{ Status = 'skipped' }
    }

    if (-not (Test-Path -LiteralPath $BriefPath -PathType Leaf)) {
        return @{ Status = 'error'; Message = "Brief file not found: $BriefPath" }
    }
    if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
        return @{ Status = 'error'; Message = "Report file not found: $ReportPath" }
    }

    try {
        $response = Invoke-RestMethod -Uri $ApiUrl -Method POST -Form @{
            password         = $Password
            hostname         = $Hostname
            username         = $Username
            scan_timestamp   = $ScanTimestamp
            duration         = $Duration
            verdict          = $Verdict
            projects_scanned = [string]$ProjectsScanned
            vulnerable_count = [string]$VulnerableCount
            critical_count   = [string]$CriticalCount
            paths_scanned    = $PathsScanned
            brief            = Get-Item -LiteralPath $BriefPath
            report           = Get-Item -LiteralPath $ReportPath
        }
        if (-not $response.id) {
            return @{ Status = 'error'; Message = 'API response missing id field' }
        }
        return @{ Status = 'success'; Id = $response.id }
    }
    catch {
        $statusCode = $null
        if ($_.Exception -is [System.Net.WebException]) {
            $httpResponse = $_.Exception.Response
            if ($httpResponse -and $httpResponse.StatusCode) {
                $statusCode = [int]$httpResponse.StatusCode
            }
        }
        if ($statusCode -eq 401) {
            return @{ Status = 'wrong-password' }
        }
        return @{ Status = 'error'; Message = $_.ToString() }
    }
}
