# RatCatcher - Software Bill of Materials (SBOM)

**Document Version:** 1.0  
**Generated:** 2026-04-13  
**Product Version:** 2.1.0 (Scanner) / 1.0.0 (Dashboard Worker)  
**Format:** Human-readable (CycloneDX-aligned)

---

## 1. Product Overview

| Field | Value |
|---|---|
| Name | RatCatcher |
| Purpose | Forensic scanner and dashboard for the March 31 2026 Axios NPM supply chain attack |
| License | Proprietary (no license file declared) |
| Repository | github.com/mbfromit/RatCatcher |
| Maintainer | Mark Berry |

### Components

| Component | Type | Version | Runtime |
|---|---|---|---|
| PowerShell Scanner | Application | 2.1.0 | PowerShell 7.0+ |
| Cloudflare Worker Dashboard | Service | 1.0.0 | Cloudflare Workers (compatibility_date 2025-01-01) |

---

## 2. PowerShell Scanner

### 2.1 Source Files

| File | Description |
|---|---|
| `Invoke-RatCatcher.ps1` | Main entry point - orchestrates 10-check forensic suite, manages parallelism, drives scan lifecycle |
| `Private/Get-NodeProjects.ps1` | Check 1 - Discovers Node.js projects by finding package.json files recursively |
| `Private/Invoke-LockfileAnalysis.ps1` | Check 2 - Parses npm/yarn/pnpm lockfiles for compromised package versions |
| `Private/Find-ForensicArtifacts.ps1` | Check 3 - Scans node_modules for malicious packages, verifies hashes, searches for C2 indicators |
| `Private/Invoke-NpmCacheScan.ps1` | Check 4 - Inspects npm content-addressable cache and global installs for malicious tarballs |
| `Private/Search-DroppedPayloads.ps1` | Check 5 - Scans temp/appdata directories for RAT payloads by magic bytes and timestamps |
| `Private/Find-PersistenceArtifacts.ps1` | Check 6 - Platform-specific persistence mechanism scanning (tasks, registry, launchd, systemd) |
| `Private/Search-XorEncodedC2.ps1` | Check 7 - Decodes XOR-obfuscated files searching for C2 domains and IPs |
| `Private/Get-NetworkEvidence.ps1` | Check 8 - Active connections, DNS cache, firewall log analysis for C2 traffic |
| `Private/New-ScanReport.ps1` | Check 9 - Generates HTML technical forensic report |
| `Private/New-ExecBriefing.ps1` | Check 9b - Generates HTML executive briefing |
| `Private/New-ScanLogHtml.ps1` | Check 9a - Converts plaintext scan log to styled HTML |
| `Private/Send-ScanReport.ps1` | Optional - SMTP email delivery of reports |
| `Private/Submit-ScanToApi.ps1` | Check 10 - Submits results to Cloudflare Worker API via multipart/form-data |

### 2.2 Platform Support

| Platform | Supported | OS-Specific Features |
|---|---|---|
| Windows | Yes | Scheduled Tasks (Get-ScheduledTask), Registry Run keys (HKCU/HKLM), Startup folders, ipconfig /displaydns, PE/MZ detection |
| macOS | Yes | LaunchAgents/LaunchDaemons (plist), crontab, `log show` unified log, lsof, Mach-O detection |
| Linux | Yes | systemd services, cron.d, crontab, journalctl/syslog, lsof/ss, ELF detection |

### 2.3 Dependencies

The scanner has **zero external module dependencies**. It uses only PowerShell built-in cmdlets and .NET base class libraries.

#### .NET / PowerShell APIs Used

| API | Usage |
|---|---|
| `[System.Text.Encoding]::UTF8` | Multipart form-data byte construction |
| `[System.IO.File]::ReadAllBytes()` | Binary file reading (logo, reports) |
| `[System.IO.MemoryStream]` | In-memory binary assembly |
| `[Convert]::ToBase64String()` | Logo embedding in HTML |
| `[regex]::Matches()` / `[regex]::Escape()` | Lockfile and log parsing |
| `[System.Collections.Generic.List]` | Efficient list operations |
| `[System.Security.Cryptography.*]` | Via Get-FileHash (SHA-256) |
| `[uri]::EscapeDataString()` | URL encoding for dashboard link |

#### System Commands Invoked

| Command | Platform | Purpose |
|---|---|---|
| `hostname` | All | Machine identification |
| `ipconfig /displaydns` | Windows | DNS cache inspection |
| `Get-NetTCPConnection` | Windows | Active TCP connections |
| `Get-ScheduledTask` | Windows | Scheduled task enumeration |
| `Get-ItemProperty HKCU:/HKLM:` | Windows | Registry Run key inspection |
| `lsof -nP -i` | macOS/Linux | Active network connections |
| `ss -tnp` | Linux | Active TCP connections |
| `log show` | macOS | Unified log DNS queries |
| `journalctl` | Linux | System log inspection |
| `crontab -l` | macOS/Linux | Crontab enumeration |
| `open` / `xdg-open` / `Start-Process` | macOS/Linux/Windows | Launch browser/files |

### 2.4 External Endpoints

| URL | Method | Purpose |
|---|---|---|
| `https://mbfromit.com/ratcatcher/submit` | POST | Submit scan results and reports |
| `https://mbfromit.com/ratcatcher/dashboard` | GET | Opened in browser after submission |

### 2.5 Data Formats

| Format | Direction | Description |
|---|---|---|
| package.json (JSON) | Input | Node.js project metadata |
| package-lock.json (JSON) | Input | npm lockfile |
| yarn.lock (text) | Input | Yarn lockfile |
| pnpm-lock.yaml (YAML) | Input | pnpm lockfile |
| HTML | Output | Technical report, executive briefing, scan log |
| multipart/form-data (RFC 2388) | Output | API submission payload |
| Plaintext log | Output | Scan log file |

---

## 3. Cloudflare Worker Dashboard

### 3.1 Source Files

| File | Description |
|---|---|
| `src/index.js` | Worker entry point - request routing and cron trigger handler |
| `src/util.js` | Shared utilities - JSON responses, password auth, HTML escaping |
| `src/handlers/submit.js` | Receives scanner submissions, stores reports in R2, inserts D1 rows |
| `src/handlers/api.js` | Admin API - stats, submissions, report serving, export, filtering |
| `src/handlers/dashboard.js` | Server-rendered single-page dashboard HTML/CSS/JS |
| `src/handlers/ack.js` | Finding acknowledgement CRUD, manager certification, verdict override |
| `src/handlers/ai-verify.js` | AI verification engine - calls Gemma 4 31B via Cloudflare Tunnel |
| `src/handlers/userReport.js` | User-facing report endpoint with ownership verification |

### 3.2 npm Dependencies

#### Direct (devDependencies only - no production dependencies)

| Package | Version Constraint | Locked Version | Purpose |
|---|---|---|---|
| `wrangler` | ^3.0.0 | 3.114.17 | Cloudflare Worker CLI, local dev, deployment |
| `vitest` | ^2.0.0 | 2.1.9 | Unit test framework |

#### Notable Transitive Dependencies

| Package | Version | Brought By | Purpose |
|---|---|---|---|
| `@cloudflare/workerd` | 1.20250718.0 | wrangler | Local Worker runtime (platform-specific binaries) |
| `@cloudflare/kv-asset-handler` | 0.3.4 | wrangler | KV static asset serving |
| `@cloudflare/unenv-preset` | 2.0.2 | wrangler | Node.js compatibility shim |
| `esbuild` | 0.17.19+ | wrangler | JavaScript bundling |
| `miniflare` | (bundled) | wrangler | Local Worker simulation |
| `mime` | 3.0.0+ | wrangler | MIME type detection |
| `fsevents` | ~2.3.2 | vitest | macOS file watching (optional) |

> **Note:** The Worker itself imports zero npm packages at runtime. All production code uses only Cloudflare platform APIs. npm dependencies are exclusively build/test tooling.

### 3.3 Cloudflare Platform Bindings

| Binding | Type | Production Name | Production ID |
|---|---|---|---|
| `DB` | D1 (SQLite) | ratcatcher | `b535d898-8007-4fc8-8f41-63da8dd31f1a3` |
| `BUCKET` | R2 (Object Storage) | ratcatcher-reports | - |
| Cron Trigger | Scheduled | `*/5 * * * *` | Retries AI_PENDING submissions |
| Route | HTTP | `mbfromit.com/ratcatcher/*` | zone: mbfromit.com |

#### Dev Environment Bindings

| Binding | Type | Dev Name | Dev ID |
|---|---|---|---|
| `DB` | D1 | ratcatcher-dev | `90e9640b-afe2-4e81-9734-b1a0731b5e91` |
| `BUCKET` | R2 | ratcatcher-dev-reports | - |
| Route | HTTP | `mbfromit.com/ratcatcher-dev/*` | zone: mbfromit.com |

### 3.4 Environment Variables / Secrets

| Variable | Type | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` | Secret | Dashboard admin and submission authentication |
| `AI_TUNNEL_URL` | Secret | Cloudflare Tunnel URL to Ollama/Gemma instance |
| `AI_API_KEY` | Secret | API key for AI tunnel authentication |

### 3.5 External Endpoints Called

| URL | Method | Purpose |
|---|---|---|
| `${AI_TUNNEL_URL}/api/ps` | GET | Poll Ollama for loaded model status |
| `${AI_TUNNEL_URL}/api/chat` | POST | Send finding to Gemma 4 31B for verdict |
| `${AI_TUNNEL_URL}/api/generate` | POST | Warm up / load model into GPU memory |

> **Current status:** AI endpoints are offline (AWS instance shut down April 2026). Worker degrades gracefully when `AI_TUNNEL_URL` is unset.

### 3.6 Web / Crypto APIs Used

| API | Usage |
|---|---|
| `fetch()` | HTTP requests to Ollama tunnel |
| `AbortSignal.timeout()` | Request timeout enforcement (10s-180s) |
| `crypto.randomUUID()` | Generate submission and finding IDs |
| `URL` / `URLSearchParams` | Query string parsing |
| `FormData` | Multipart submission parsing |
| `Response` / `Request` | Standard Fetch API |
| `ctx.waitUntil()` | Background task execution (AI verify-all) |

### 3.7 Data Formats

| Format | Direction | Description |
|---|---|---|
| multipart/form-data | Input | Scanner submissions with file attachments |
| JSON | Input/Output | All API request/response bodies |
| HTML | Input/Output | Reports stored in R2, dashboard UI served to browser |
| SQL | Internal | D1 queries (parameterized, no raw interpolation) |

---

## 4. Database Schema

### submissions

| Column | Type | Description |
|---|---|---|
| id | TEXT PK | UUID v4 |
| hostname | TEXT NOT NULL | Scanned machine name |
| username | TEXT NOT NULL | User who ran the scan |
| submitted_at | TEXT NOT NULL | ISO 8601 submission timestamp |
| scan_timestamp | TEXT NOT NULL | ISO 8601 scan start time |
| duration | TEXT | Human-readable duration |
| verdict | TEXT NOT NULL | CLEAN or COMPROMISED |
| projects_scanned | INTEGER | Node.js projects found |
| vulnerable_count | INTEGER | Projects with vulnerable lockfiles |
| critical_count | INTEGER | Critical-severity findings |
| paths_scanned | TEXT | JSON array of scanned paths |
| brief_key | TEXT NOT NULL | R2 key for executive briefing |
| report_key | TEXT NOT NULL | R2 key for technical report |
| findings_count | INTEGER | Unique findings for acknowledgement |
| ai_verdict | TEXT | AI_CLEAN, AI_COMPROMISE, AI_FALSE_POSITIVE, AI_PENDING, AI_PARTIAL |
| certified_by | TEXT | Manager name |
| certified_at | TEXT | ISO 8601 certification timestamp |

### finding_ai_verdicts

| Column | Type | Description |
|---|---|---|
| id | TEXT PK | UUID v4 |
| submission_id | TEXT FK | References submissions.id |
| finding_index | INTEGER NOT NULL | Position in findings array |
| category | TEXT NOT NULL | Finding type (e.g. C2Indicator, MaliciousPackage) |
| description | TEXT | Finding detail (truncated to 500 chars) |
| verdict | TEXT NOT NULL | Confirmed, Likely, Unlikely, FalsePositive, TimedOut, Error |
| reason | TEXT | One-sentence AI reasoning |
| verified_at | TEXT NOT NULL | ISO 8601 verification timestamp |

### finding_acknowledgements

| Column | Type | Description |
|---|---|---|
| id | TEXT PK | UUID v4 |
| submission_id | TEXT FK | References submissions.id |
| finding_hash | TEXT | SHA-256 of finding type+path (client-generated) |
| reason | TEXT | Reviewer's explanation |
| acknowledged_at | TEXT | ISO 8601 acknowledgement timestamp |
| is_threat | INTEGER | 0 = false positive, 1 = confirmed threat |

---

## 5. Test Suite

| File | Framework | Covers |
|---|---|---|
| `cloudflare/test/api.test.js` | Vitest | handleStats, handleSubmissions |
| `cloudflare/test/ack.test.js` | Vitest | handlePostAck, handleGetAcks, handleDeleteAck |
| `cloudflare/test/router.test.js` | Vitest | Request routing in index.js |
| `cloudflare/test/submit.test.js` | Vitest | handleSubmit multipart parsing |
| `Tests/*.Tests.ps1` | Pester | PowerShell scanner modules (13 test files) |

---

## 6. Supply Chain Notes

- **Scanner:** Zero external dependencies. All functionality is built on PowerShell built-ins and .NET BCL. No modules to audit.
- **Worker:** Zero runtime npm imports. The only npm packages are `wrangler` (build/deploy) and `vitest` (testing), both devDependencies. Attack surface from npm supply chain is limited to the development/build pipeline only.
- **AI Model:** Gemma 4 31B (Google) served via Ollama, accessed through Cloudflare Tunnel. Model is self-hosted, not a third-party API. Currently offline.
- **Infrastructure:** All production data (D1 database, R2 reports) is hosted on Cloudflare under account `mbfromit@gmail.com`. No AWS/GCP/Azure dependencies for the dashboard itself.
