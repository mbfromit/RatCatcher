function New-ScanLogHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [string]$LogoBase64 = '',
        [hashtable]$ScanMetadata = @{}
    )

    $lines = @(Get-Content -Path $LogPath -ErrorAction SilentlyContinue)

    function Esc([string]$s) { if (-not $s) { return '' }; $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;') }

    # Parse log lines into HTML
    $linesHtml = ($lines | ForEach-Object {
        $line = $_
        if ($line -match '^\[(\d{2}:\d{2}:\d{2})\] \[(\w+)\] (.*)$') {
            $ts    = $Matches[1]
            $level = $Matches[2]
            $msg   = Esc $Matches[3]
            $cls   = switch ($level) { 'WARN' {'ll-warn'} 'ERROR' {'ll-error'} default {'ll-info'} }
            "<div class=`"ll $cls`"><span class=`"ll-ts`">[$ts]</span><span class=`"ll-lv`">[$level]</span><span class=`"ll-msg`">$msg</span></div>"
        } elseif ($line -match '^=+$' -or $line -match '^-+$') {
            "<div class=`"ll-sep`">$(Esc $line)</div>"
        } elseif ($line.Trim()) {
            "<div class=`"ll ll-info`"><span class=`"ll-msg`" style=`"padding-left:0`">$(Esc $line)</span></div>"
        } else {
            '<div class="ll-blank">&nbsp;</div>'
        }
    }) -join "`n"

    $hostname  = if ($ScanMetadata.Hostname) { $ScanMetadata.Hostname } else { 'unknown' }
    $timestamp = if ($ScanMetadata.Timestamp) { $ScanMetadata.Timestamp } else { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }
    $logoImg   = if ($LogoBase64) { "<img src=`"data:image/png;base64,$LogoBase64`" class=`"rc-logo`" alt=`"RatCatcher`">" } else { '' }

    $css = @'
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#06090f;--panel:#0d1117;--card:#161b22;--border:#21303f;--accent:#00d4ff;--accent2:#58a6ff;--text:#c9d1d9;--text-muted:#6e7681;--text-bright:#e6edf3;--pass:#3fb950;--fail:#f85149;--warn:#e3b341}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}
.rc-header{background:var(--panel);border-bottom:2px solid var(--accent);padding:0 32px;display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:100;box-shadow:0 2px 20px rgba(0,0,0,.5),0 0 40px rgba(0,212,255,.05)}
.rc-logo{height:68px;width:auto;padding:8px 0}
.rc-header-text{flex:1}
.rc-title{font-size:22px;font-weight:700;color:var(--accent);letter-spacing:4px;font-family:'Consolas',monospace}
.rc-subtitle{font-size:11px;color:var(--text-muted);letter-spacing:1px;margin-top:2px}
.rc-main{max-width:1100px;margin:0 auto;padding:32px}
.rc-panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden}
.rc-panel-hdr{background:var(--card);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:10px}
.rc-panel-title{font-size:11px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:var(--accent2);font-family:'Consolas',monospace}
.rc-panel-count{margin-left:auto;font-size:11px;color:var(--text-muted);font-family:'Consolas',monospace}
.log-wrap{background:#06090f;padding:16px 20px;font-family:'Consolas','Courier New',monospace;font-size:12.5px;line-height:1.65}
.ll{display:flex;gap:10px;padding:0}
.ll-ts{color:#2a3140;flex-shrink:0;user-select:none;min-width:72px}
.ll-lv{flex-shrink:0;min-width:50px}
.ll-info .ll-lv{color:var(--text-muted)}
.ll-warn .ll-lv{color:var(--warn)}
.ll-error .ll-lv{color:var(--fail)}
.ll-msg{color:#8b949e;word-break:break-word}
.ll-warn .ll-msg{color:var(--warn)}
.ll-error .ll-msg{color:var(--fail)}
.ll-info .ll-msg{color:#8b949e}
.ll-sep{color:#1e3a5f;font-family:'Consolas',monospace;font-size:12px;padding:2px 0}
.ll-blank{height:4px}
.rc-footer{text-align:center;padding:24px 32px;color:var(--text-muted);font-size:11px;border-top:1px solid var(--border);margin-top:32px;font-family:'Consolas',monospace;letter-spacing:.5px}
'@

    $lineCount = $lines.Count

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>RatCatcher — Scan Log — $(Esc $hostname)</title>
<style>$css</style>
</head>
<body>
<div class="rc-header">
  $logoImg
  <div class="rc-header-text">
    <div class="rc-title">RATCATCHER</div>
    <div class="rc-subtitle">SCAN LOG &nbsp;&#47;&#47;&nbsp; $(Esc $hostname) &nbsp;&#47;&#47;&nbsp; $(Esc $timestamp)</div>
  </div>
</div>

<div class="rc-main">
  <div class="rc-panel">
    <div class="rc-panel-hdr">
      <span class="rc-panel-title">SCAN LOG OUTPUT</span>
      <span class="rc-panel-count">$lineCount lines</span>
    </div>
    <div class="log-wrap">
$linesHtml
    </div>
  </div>
</div>

<div class="rc-footer">
  RATCATCHER v1.0 &nbsp;&#47;&#47;&nbsp; $(Esc $hostname) &nbsp;&#47;&#47;&nbsp; $(Esc $timestamp)
</div>
</body>
</html>
"@

    # Write HTML, delete the raw .log
    $htmlPath = [IO.Path]::ChangeExtension($LogPath, '.html')
    $html | Set-Content -Path $htmlPath -Encoding UTF8
    Remove-Item -Path $LogPath -Force -ErrorAction SilentlyContinue

    return $htmlPath
}
