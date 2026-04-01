function Invoke-LockfileAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectPath)

    $vulnAxios   = @('1.14.1', '0.30.4')
    $vulnCrypto  = '4.2.1'
    $result = [PSCustomObject]@{
        ProjectPath             = $ProjectPath
        HasVulnerableAxios      = $false
        VulnerableAxiosVersion  = $null
        HasMaliciousPlainCrypto = $false
        LockfileType            = $null
        LockfilePath            = $null
        Error                   = $null
    }

    $pkgLock  = Join-Path $ProjectPath 'package-lock.json'
    $yarnLock = Join-Path $ProjectPath 'yarn.lock'
    $pnpmLock = Join-Path $ProjectPath 'pnpm-lock.yaml'

    if (Test-Path $pkgLock) {
        $result.LockfileType = 'npm'; $result.LockfilePath = $pkgLock
        try {
            $lock = Get-Content $pkgLock -Raw | ConvertFrom-Json -ErrorAction Stop
            $props = if ($lock.packages) { $lock.packages.PSObject.Properties }
                     elseif ($lock.dependencies) { $lock.dependencies.PSObject.Properties }
                     else { @() }
            foreach ($p in $props) {
                $name = $p.Name -replace '^node_modules/', ''
                $ver  = $p.Value.version
                if ($name -eq 'axios' -and $ver -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $ver }
                if ($name -eq 'plain-crypto-js' -and $ver -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
        } catch { $result.Error = "Failed to parse package-lock.json: $_" }

    } elseif (Test-Path $yarnLock) {
        $result.LockfileType = 'yarn'; $result.LockfilePath = $yarnLock
        try {
            $content = Get-Content $yarnLock -Raw -ErrorAction Stop
            foreach ($m in [regex]::Matches($content, '(?m)^axios@[^\n]+\n\s+version\s+"([^"]+)"')) {
                if ($m.Groups[1].Value -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $m.Groups[1].Value }
            }
            foreach ($m in [regex]::Matches($content, '(?m)^plain-crypto-js@[^\n]+\n\s+version\s+"([^"]+)"')) {
                if ($m.Groups[1].Value -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
        } catch { $result.Error = "Failed to parse yarn.lock: $_" }

    } elseif (Test-Path $pnpmLock) {
        $result.LockfileType = 'pnpm'; $result.LockfilePath = $pnpmLock
        try {
            $content = Get-Content $pnpmLock -Raw -ErrorAction Stop
            # pnpm-lock.yaml format: "  /axios/1.14.1:" or "  axios@1.14.1:"
            foreach ($m in [regex]::Matches($content, '(?m)^\s+(?:/|)axios[/@]([^\s:]+):')) {
                if ($m.Groups[1].Value -in $vulnAxios) { $result.HasVulnerableAxios = $true; $result.VulnerableAxiosVersion = $m.Groups[1].Value }
            }
            foreach ($m in [regex]::Matches($content, '(?m)^\s+(?:/|)plain-crypto-js[/@]([^\s:]+):')) {
                if ($m.Groups[1].Value -eq $vulnCrypto) { $result.HasMaliciousPlainCrypto = $true }
            }
        } catch { $result.Error = "Failed to parse pnpm-lock.yaml: $_" }
    }

    return $result
}
