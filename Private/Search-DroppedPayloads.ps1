function Search-DroppedPayloads {
    [CmdletBinding()]
    param(
        [string[]]$ScanPaths,
        [datetime]$AttackWindowStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
    )

    # Default to the filesystem locations a dropper would target
    if (-not $ScanPaths) {
        if ($IsWindows) {
            $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:HOME }
            $appData      = if ($env:APPDATA)      { $env:APPDATA }      else { Join-Path $env:HOME '.config' }
            $ScanPaths = @(
                $env:TEMP, $env:TMP,
                (Join-Path $localAppData 'Temp'),
                $localAppData, $appData
            )
        } elseif ($IsMacOS) {
            $ScanPaths = @(
                '/tmp',
                (Join-Path $env:HOME 'Library/Caches'),
                (Join-Path $env:HOME 'Library/Application Support'),
                (Join-Path $env:HOME '.config')
            )
        } else {
            # Linux
            $ScanPaths = @(
                '/tmp', '/var/tmp',
                (Join-Path $env:HOME '.cache'),
                (Join-Path $env:HOME '.local/share'),
                (Join-Path $env:HOME '.config')
            )
        }
        $ScanPaths = @($ScanPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Known RAT artifacts by platform
    if ($IsMacOS) {
        $ratPath = '/Library/Caches/com.apple.act.mond'
        if (Test-Path $ratPath) {
            $findings.Add([PSCustomObject]@{
                Type = 'DroppedExecutable'; Path = $ratPath; Hash = $null
                CreationTime = (Get-Item $ratPath).CreationTime; Severity = 'Critical'
                Description = "Known macOS RAT binary (com.apple.act.mond) found at $ratPath"
            })
        }
    } elseif ($IsLinux) {
        $ratPath = '/tmp/ld.py'
        if (Test-Path $ratPath) {
            $findings.Add([PSCustomObject]@{
                Type = 'DroppedExecutable'; Path = $ratPath; Hash = $null
                CreationTime = (Get-Item $ratPath).CreationTime; Severity = 'Critical'
                Description = "Known Linux RAT script (ld.py) found at $ratPath"
            })
        }
    }

    foreach ($scanPath in $ScanPaths) {
        try {
            Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -ge $AttackWindowStart -and $_.Length -le 10MB -and $_.Length -gt 0 } |
            Where-Object { try { [IO.File]::OpenRead($_.FullName).Dispose(); $true } catch { $false } } |
            Select-Object -First 2000 |
            ForEach-Object {
                $file = $_
                $type = $null
                $sev  = 'Medium'

                if ($IsWindows) {
                    # Check for PE magic bytes (MZ header = 0x4D 0x5A)
                    if ($file.Extension -in @('.exe', '.dll') -or $file.Length -gt 0) {
                        try {
                            $bytes = [IO.File]::ReadAllBytes($file.FullName) | Select-Object -First 2
                            if ($bytes.Count -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                                try {
                                    $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                                    if ($sig -and $sig.Status -eq 'Valid') { return }
                                } catch { }
                                $type = 'DroppedExecutable'
                                $sev  = 'Critical'
                            }
                        } catch { }
                    }
                    # Suspicious Windows script extensions
                    if (-not $type -and $file.Extension -in @('.ps1', '.vbs', '.bat', '.cmd')) {
                        $type = 'SuspiciousScript'; $sev = 'High'
                    }
                } elseif ($IsMacOS) {
                    # Check for Mach-O magic bytes (0xCF 0xFA = 64-bit, 0xCE 0xFA = 32-bit)
                    if ($file.Extension -in @('.dylib', '.app', '') -or $file.Length -gt 0) {
                        try {
                            $bytes = [IO.File]::ReadAllBytes($file.FullName) | Select-Object -First 4
                            if ($bytes.Count -ge 4 -and
                                (($bytes[0] -eq 0xCF -and $bytes[1] -eq 0xFA -and $bytes[2] -eq 0xED -and $bytes[3] -eq 0xFE) -or
                                 ($bytes[0] -eq 0xCE -and $bytes[1] -eq 0xFA -and $bytes[2] -eq 0xED -and $bytes[3] -eq 0xFE))) {
                                $type = 'DroppedExecutable'; $sev = 'Critical'
                            }
                        } catch { }
                    }
                    # Suspicious macOS script extensions
                    if (-not $type -and $file.Extension -in @('.sh', '.py', '.command', '.scpt')) {
                        $type = 'SuspiciousScript'; $sev = 'High'
                    }
                } else {
                    # Linux: Check for ELF magic bytes (0x7F 0x45 0x4C 0x46)
                    if ($file.Extension -in @('.so', '.elf', '') -or $file.Length -gt 0) {
                        try {
                            $bytes = [IO.File]::ReadAllBytes($file.FullName) | Select-Object -First 4
                            if ($bytes.Count -ge 4 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46) {
                                $type = 'DroppedExecutable'; $sev = 'Critical'
                            }
                        } catch { }
                    }
                    # Suspicious Linux script extensions
                    if (-not $type -and $file.Extension -in @('.sh', '.py', '.pl', '.rb')) {
                        $type = 'SuspiciousScript'; $sev = 'High'
                    }
                }

                if ($type) {
                    $hash = $null
                    try { $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower() } catch { }
                    $findings.Add([PSCustomObject]@{
                        Type         = $type
                        Path         = $file.FullName
                        Hash         = $hash
                        CreationTime = $file.CreationTime
                        Severity     = $sev
                        Description  = "${type} created after attack window in temp/appdata location: $($file.FullName)"
                    })
                }
            }
        } catch { Write-Warning "Error scanning ${scanPath}: $_" }
    }

    return @($findings)
}
