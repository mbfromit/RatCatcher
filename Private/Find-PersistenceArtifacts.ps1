function Find-PersistenceArtifacts {
    [CmdletBinding()]
    param(
        [datetime]$AttackWindowStart = [datetime]::Parse('2026-03-31T00:21:00Z').ToLocalTime()
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($IsWindows) {
        # ── Windows: Scheduled Tasks ──────────────────────────────────────────
        $suspiciousPaths = @('temp', 'tmp', 'appdata', 'localappdata', 'programdata', 'public')
        try {
            Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } |
            ForEach-Object {
                $task = $_
                $taskDate = $null
                try { $taskDate = [datetime]::Parse($task.Date) } catch { }
                $isNew = $taskDate -and $taskDate -ge $AttackWindowStart

                foreach ($action in $task.Actions) {
                    if ($action.PSObject.Properties['Execute'] -eq $null) { continue }
                    $exe  = if ($action.Execute)   { $action.Execute }   else { '' }
                    $args = if ($action.Arguments) { $action.Arguments } else { '' }
                    $full = "$exe $args".ToLower()

                    $isSuspiciousPath   = $suspiciousPaths | Where-Object { $full -match $_ }
                    $isSuspiciousExe    = $exe -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|cmd\.exe'
                    $hasHiddenWindow    = $args -match '-windowstyle\s+hidden|-w\s+hidden|-nop|-noni'

                    if ($isNew -or ($isSuspiciousPath -and $isSuspiciousExe) -or $hasHiddenWindow) {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'SuspiciousScheduledTask'
                            Location    = "Task Scheduler: $($task.TaskPath)$($task.TaskName)"
                            Name        = $task.TaskName
                            Value       = "$exe $args"
                            Severity    = 'Critical'
                            Description = "Scheduled task '$($task.TaskName)' runs suspicious command: $exe $args"
                        })
                    }
                }
            }
        } catch { Write-Warning "Scheduled task scan failed: $_" }

        # ── Windows: Registry Run Keys ────────────────────────────────────────
        $safeRunKeyPaths = @(
            '[/\\]Microsoft[/\\]WindowsApps[/\\]',
            '[/\\]Microsoft[/\\]Teams[/\\]',
            '[/\\]Microsoft[/\\]OneDrive[/\\]'
        )
        $runKeys = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        foreach ($keyPath in $runKeys) {
            try {
                $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }
                $props.PSObject.Properties |
                Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') } |
                ForEach-Object {
                    $val  = $_.Value.ToLower()
                    $isKnownSafe      = $safeRunKeyPaths | Where-Object { $val -match $_ }
                    $isSuspiciousPath = $suspiciousPaths | Where-Object { $val -match $_ }
                    $hasNodeOrScript  = $val -match 'node|npm|\.ps1|\.vbs|\.bat|\.cmd|\.js'
                    if (-not $isKnownSafe -and ($isSuspiciousPath -or $hasNodeOrScript)) {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'SuspiciousRunKey'
                            Location    = $keyPath
                            Name        = $_.Name
                            Value       = $_.Value
                            Severity    = 'Critical'
                            Description = "Registry Run key '$($_.Name)' points to suspicious path: $($_.Value)"
                        })
                    }
                }
            } catch { Write-Warning "Registry key scan failed for ${keyPath}: $_" }
        }

        # ── Windows: Startup Folder ───────────────────────────────────────────
        $startupFolders = @(
            [Environment]::GetFolderPath('Startup'),
            [Environment]::GetFolderPath('CommonStartup')
        ) | Where-Object { $_ -and (Test-Path $_) }
        foreach ($folder in $startupFolders) {
            try {
                Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -ge $AttackWindowStart } |
                ForEach-Object {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'SuspiciousStartupEntry'
                        Location    = $folder
                        Name        = $_.Name
                        Value       = $_.FullName
                        Severity    = 'Critical'
                        Description = "File added to startup folder after attack window: $($_.FullName)"
                    })
                }
            } catch { Write-Warning "Startup folder scan failed for ${folder}: $_" }
        }

    } elseif ($IsMacOS) {
        # ── macOS: LaunchAgents / LaunchDaemons ───────────────────────────────
        $launchPaths = @(
            (Join-Path $env:HOME 'Library/LaunchAgents'),
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons'
        ) | Where-Object { Test-Path $_ }

        foreach ($launchDir in $launchPaths) {
            try {
                Get-ChildItem -Path $launchDir -Filter '*.plist' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -ge $AttackWindowStart -or $_.LastWriteTime -ge $AttackWindowStart } |
                ForEach-Object {
                    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                    $isSuspicious = $content -match 'sfrclak|callnrwise|142\.11\.206|plain-crypto|node|npm|/tmp/|curl|wget|python|nohup'
                    if ($isSuspicious -or $_.CreationTime -ge $AttackWindowStart) {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'SuspiciousLaunchAgent'
                            Location    = $launchDir
                            Name        = $_.Name
                            Value       = $_.FullName
                            Severity    = if ($isSuspicious) { 'Critical' } else { 'Medium' }
                            Description = "Launch agent/daemon '$($_.Name)' created or modified after attack window"
                        })
                    }
                }
            } catch { Write-Warning "LaunchAgent scan failed for ${launchDir}: $_" }
        }

        # ── macOS: Cron jobs ──────────────────────────────────────────────────
        try {
            $crontab = & crontab -l 2>/dev/null
            if ($crontab) {
                foreach ($line in $crontab -split "`n") {
                    if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
                    if ($line -match 'sfrclak|callnrwise|142\.11\.206|plain-crypto|/tmp/ld\.py|com\.apple\.act\.mond|curl.*sfrclak|nohup') {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'SuspiciousCronJob'
                            Location    = 'crontab'
                            Name        = 'User crontab'
                            Value       = $line.Trim()
                            Severity    = 'Critical'
                            Description = "Cron job contains suspicious C2/malware reference: $($line.Trim())"
                        })
                    }
                }
            }
        } catch { Write-Warning "Crontab scan failed: $_" }

    } else {
        # ── Linux: Systemd user services ──────────────────────────────────────
        $systemdPaths = @(
            (Join-Path $env:HOME '.config/systemd/user'),
            '/etc/systemd/system'
        ) | Where-Object { Test-Path $_ }

        foreach ($svcDir in $systemdPaths) {
            try {
                Get-ChildItem -Path $svcDir -Filter '*.service' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -ge $AttackWindowStart -or $_.LastWriteTime -ge $AttackWindowStart } |
                ForEach-Object {
                    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                    $isSuspicious = $content -match 'sfrclak|callnrwise|142\.11\.206|plain-crypto|node|npm|/tmp/ld\.py|curl|wget|python|nohup'
                    if ($isSuspicious -or $_.CreationTime -ge $AttackWindowStart) {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'SuspiciousSystemdService'
                            Location    = $svcDir
                            Name        = $_.Name
                            Value       = $_.FullName
                            Severity    = if ($isSuspicious) { 'Critical' } else { 'Medium' }
                            Description = "Systemd service '$($_.Name)' created or modified after attack window"
                        })
                    }
                }
            } catch { Write-Warning "Systemd scan failed for ${svcDir}: $_" }
        }

        # ── Linux: Cron jobs ──────────────────────────────────────────────────
        try {
            $crontab = & crontab -l 2>/dev/null
            if ($crontab) {
                foreach ($line in $crontab -split "`n") {
                    if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
                    if ($line -match 'sfrclak|callnrwise|142\.11\.206|plain-crypto|/tmp/ld\.py|curl.*sfrclak|nohup') {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'SuspiciousCronJob'
                            Location    = 'crontab'
                            Name        = 'User crontab'
                            Value       = $line.Trim()
                            Severity    = 'Critical'
                            Description = "Cron job contains suspicious C2/malware reference: $($line.Trim())"
                        })
                    }
                }
            }
        } catch { Write-Warning "Crontab scan failed: $_" }

        # ── Linux: /etc/cron.d ────────────────────────────────────────────────
        $cronDirs = @('/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly') | Where-Object { Test-Path $_ }
        foreach ($cronDir in $cronDirs) {
            try {
                Get-ChildItem -Path $cronDir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -ge $AttackWindowStart } |
                ForEach-Object {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'SuspiciousCronFile'
                        Location    = $cronDir
                        Name        = $_.Name
                        Value       = $_.FullName
                        Severity    = 'Medium'
                        Description = "Cron file '$($_.Name)' created after attack window in $cronDir"
                    })
                }
            } catch { Write-Warning "Cron.d scan failed for ${cronDir}: $_" }
        }

        # ── Linux: Autostart ──────────────────────────────────────────────────
        $autostartDir = Join-Path $env:HOME '.config/autostart'
        if (Test-Path $autostartDir) {
            try {
                Get-ChildItem -Path $autostartDir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.CreationTime -ge $AttackWindowStart } |
                ForEach-Object {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'SuspiciousAutostart'
                        Location    = $autostartDir
                        Name        = $_.Name
                        Value       = $_.FullName
                        Severity    = 'Medium'
                        Description = "Autostart entry '$($_.Name)' created after attack window"
                    })
                }
            } catch { Write-Warning "Autostart scan failed: $_" }
        }
    }

    return @($findings)
}
