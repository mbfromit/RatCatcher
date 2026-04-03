function Invoke-FindingVerification {
    <#
    .SYNOPSIS
        Verifies scan findings against a local LLM to reduce false positives.
    .DESCRIPTION
        Sends each finding along with the reference article about the Axios supply chain
        attack to a local Ollama instance running qwen3:14b. The model evaluates whether
        each finding is genuinely related to the attack or a likely false positive.
    .PARAMETER Findings
        Array of finding objects from any check (artifacts, cache, payloads, persistence, xor, network).
    .PARAMETER FindingCategory
        Label for the category of findings being verified (for logging).
    .PARAMETER OllamaUrl
        Base URL for the Ollama API server.
    .PARAMETER Model
        Ollama model to use for verification.
    .PARAMETER TimeoutSec
        Per-finding HTTP timeout in seconds.
    #>
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,

        [string]$FindingCategory = 'General',

        [string]$OllamaUrl = 'http://192.168.1.203:11434',

        [string]$Model = 'qwen3:14b',

        [int]$TimeoutSec = 120
    )

    if (-not $Findings -or $Findings.Count -eq 0) { return @() }

    $articleContext = @'
REFERENCE: Axios NPM Supply Chain Attack — March 31, 2026

The popular HTTP client Axios suffered a supply chain compromise after two malicious npm package versions (1.14.1 and 0.30.4) introduced a fake dependency called "plain-crypto-js" version 4.2.1. This dependency delivered a cross-platform remote access trojan (RAT) targeting Windows, macOS, and Linux systems.

ATTACK MECHANISM:
Its sole purpose is to execute a postinstall script that acts as a cross-platform RAT dropper, targeting macOS, Windows, and Linux. The malware contacts a command and control server and delivers platform-specific second-stage payloads before self-destructing and replacing its package.json with a clean version to evade forensic detection.

COMPROMISE DETAILS:
The attackers compromised the npm account credentials of primary Axios maintainer "jasonsaayman," bypassing GitHub Actions CI/CD pipelines. They changed the account's registered email to "ifstap@proton.me" and obtained a long-lived classic npm access token for direct registry access. The "plain-crypto-js" package was published by npm user "nrwise" with email "nrwise@proton.me."

TIMELINE:
- March 30, 2026, 05:57 UTC: Clean "plain-crypto-js@4.2.0" published
- March 30, 2026, 23:59 UTC: Malicious "plain-crypto-js@4.2.1" published
- March 31, 2026, 00:21 UTC: Axios "1.14.1" published with injected dependency
- March 31, 2026, 01:00 UTC: Axios "0.30.4" published with injected dependency

This was not opportunistic. The malicious dependency was staged 18 hours in advance. Three separate payloads were pre-built for three operating systems.

MALWARE CAPABILITIES BY PLATFORM:
macOS: Executes AppleScript payload fetching trojan from "sfrclak.com:8000," saves as "/Library/Caches/com.apple.act.mond," makes executable, launches via /bin/zsh, then deletes AppleScript.
Windows: Locates PowerShell binary, copies to "%PROGRAMDATA%\wt.exe," writes VBScript to temp directory, fetches PowerShell RAT from C2 server, executes it, then deletes downloaded file.
Linux: Runs shell command via Node.js execSync to fetch Python RAT from server, saves to "/tmp/ld.py," executes in background using nohup.

C2 COMMUNICATION:
Each platform sends a distinct POST body to the same C2 URL — packages.npm.org/product0 (macOS), packages.npm.org/product1 (Windows), packages.npm.org/product2 (Linux). This allows the C2 to serve platform-appropriate payloads from a single endpoint.

RAT CAPABILITIES (all platforms):
- System fingerprinting
- 60-second beacon intervals
- Arbitrary payload execution
- Shell command execution
- File system enumeration
- Process enumeration
- Graceful self-termination

The Windows variant additionally creates "%PROGRAMDATA%\system.bat" with download cradles and Registry Run keys for persistence across reboots.

FORENSIC EVASION:
The Node.js dropper removes the postinstall script, deletes the malicious package.json, and renames "package.md" (a clean manifest) to "package.json" to avoid detection during post-infection inspection.

ATTRIBUTION:
Elastic Security Labs noted potential overlap with WAVESHAPER, a C++ backdoor attributed to North Korean threat actor UNC1069, though attribution remains unconfirmed.

ADDITIONAL COMPROMISED PACKAGES:
Socket identified two packages distributing the same malware:
- @shadanai/openclaw (versions 2026.3.28-2, 2026.3.28-3, 2026.3.31-1, 2026.3.31-2)
- @qqbrowser/openclaw-qbot (version 0.0.130)

KNOWN INDICATORS OF COMPROMISE (IOCs):
- Packages: axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1
- C2 Domain: sfrclak.com
- C2 IP: 142.11.206.73
- C2 Port: 8000
- XOR Key: OrDeR_7077 (constant 333)
- File artifacts: /Library/Caches/com.apple.act.mond (macOS), %PROGRAMDATA%\wt.exe (Windows), /tmp/ld.py (Linux)
- Persistence: Registry Run keys pointing to %PROGRAMDATA%, scheduled tasks with suspicious executors
- Known malicious hash (setup.js): e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09

REMEDIATION:
- Downgrade to Axios 1.14.0 or 0.30.3
- Rotate secrets and credentials immediately
- Remove "plain-crypto-js" from node_modules
- Assume full compromise if artifacts found
- Block egress to sfrclak.com
- Audit CI/CD pipeline runs using affected versions
'@

    $systemPrompt = @'
You are a cybersecurity analyst verifying forensic scanner findings against a known attack profile. You will receive:
1. A reference article describing the Axios NPM supply chain attack of March 31, 2026
2. A specific finding from a forensic scanner

Your job is to determine whether the finding is genuinely related to this specific attack or is likely a false positive (normal system activity unrelated to the attack).

RESPOND WITH EXACTLY ONE LINE in this format:
VERDICT: <Confirmed|Likely|Unlikely|FalsePositive> | REASON: <one sentence explanation>

Definitions:
- Confirmed: Finding directly matches a known IOC from the attack (exact package version, exact C2 domain/IP, exact file path, exact hash)
- Likely: Finding is consistent with the attack pattern but not an exact IOC match (e.g., suspicious file in temp created during attack window, persistence mechanism matching described techniques)
- Unlikely: Finding has weak or coincidental connection to the attack (e.g., port 8000 used by a known legitimate service, scheduled task from a trusted vendor)
- FalsePositive: Finding is clearly unrelated normal system activity (e.g., legitimate software update, well-known application persistence entry)

Be strict: only mark Confirmed for exact IOC matches. Lean toward FalsePositive for anything that looks like normal system operation.
Do not think out loud. Do not include any text before or after the verdict line.
'@

    $verified = [System.Collections.Generic.List[object]]::new()

    foreach ($finding in $Findings) {
        $findingText = ($finding | Format-List | Out-String).Trim()

        $userPrompt = @"
REFERENCE ARTICLE:
$articleContext

SCANNER FINDING (Category: $FindingCategory):
$findingText

Evaluate this finding. Is it related to the Axios supply chain attack described above, or is it a false positive?
"@

        $requestBody = @{
            model    = $Model
            messages = @(
                @{ role = 'system'; content = $systemPrompt }
                @{ role = 'user';   content = $userPrompt }
            )
            stream  = $false
            think   = $false
            options = @{
                temperature   = 0.1
                num_predict   = 1000
            }
        } | ConvertTo-Json -Depth 4

        try {
            $response = Invoke-RestMethod `
                -Uri "$OllamaUrl/api/chat" `
                -Method POST `
                -Body $requestBody `
                -ContentType 'application/json' `
                -TimeoutSec $TimeoutSec

            $responseText = $response.message.content.Trim()

            # Strip any <think>...</think> blocks (qwen3 thinking mode)
            $responseText = $responseText -replace '(?s)<think>.*?</think>', '' | ForEach-Object { $_.Trim() }

            # Parse verdict from response
            $verdict = 'Unknown'
            $reason  = ''
            if ($responseText -match 'VERDICT:\s*(Confirmed|Likely|Unlikely|FalsePositive)\s*\|\s*REASON:\s*(.+)') {
                $verdict = $Matches[1]
                $reason  = $Matches[2].Trim()
            } elseif ($responseText -match '(Confirmed|Likely|Unlikely|FalsePositive)') {
                $verdict = $Matches[1]
                $reason  = $responseText
            }

            $finding | Add-Member -NotePropertyName 'AiVerdict' -NotePropertyValue $verdict -Force
            $finding | Add-Member -NotePropertyName 'AiReason'  -NotePropertyValue $reason  -Force
        }
        catch {
            # On LLM failure, keep the finding (fail-open so we don't hide real threats)
            $finding | Add-Member -NotePropertyName 'AiVerdict' -NotePropertyValue 'Error' -Force
            $finding | Add-Member -NotePropertyName 'AiReason'  -NotePropertyValue "LLM verification failed: $_" -Force
        }

        $verified.Add($finding)
    }

    return @($verified)
}
