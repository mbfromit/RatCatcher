# AI Verdict Display Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the Ollama AI verdict as the primary verdict label in the dashboard, replacing the binary CLEAN/COMPROMISED with AI_CLEAN, AI_FALSE_POSITIVE, or AI_COMPROMISE where AI ran.

**Architecture:** Add a nullable `ai_verdict` column to D1 `submissions`. The scanner computes the aggregate after `Invoke-FindingVerification` and submits it as a form field. The Cloudflare Worker stores it, uses it to drive `positive`/`reviewed`/`not_reviewed` stats, and the dashboard renders label + row colour based on it.

**Tech Stack:** Cloudflare Workers (JS), Cloudflare D1 (SQLite), Wrangler CLI, PowerShell 5.1+, Vitest

---

## File Map

| File | Change |
|---|---|
| D1 (wrangler CLI) | Add `ai_verdict TEXT` column |
| `cloudflare/src/handlers/submit.js` | Accept + validate + store `ai_verdict` |
| `cloudflare/test/submit.test.js` | Add tests for `ai_verdict` field |
| `cloudflare/src/handlers/api.js` | Update `positive`/`reviewed`/`not_reviewed` logic; expose `ai_verdict` on rows |
| `cloudflare/test/api.test.js` | Add tests for updated stats + row fields |
| `cloudflare/src/handlers/dashboard.js` | New verdict label function, row class, orange CSS, filter logic |
| `Private/Submit-ScanToApi.ps1` | Add optional `$AiVerdict` param + form field |
| `Invoke-RatCatcher.ps1` | Compute aggregate `$aiVerdict` after AI verification loop |

---

## Task 1: D1 Schema Migration

**Files:** Run via Wrangler CLI — no source file created.

- [ ] **Step 1: Add the column**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher/cloudflare"
npx wrangler d1 execute ratcatcher-db --remote --command \
  "ALTER TABLE submissions ADD COLUMN ai_verdict TEXT;"
```

Expected: `✅ Successfully executed` (no output rows).

- [ ] **Step 2: Verify**

```bash
npx wrangler d1 execute ratcatcher-db --remote --command \
  "SELECT sql FROM sqlite_master WHERE name = 'submissions';"
```

Expected: the `CREATE TABLE` statement includes `ai_verdict TEXT`.

- [ ] **Step 3: Commit migration note**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher"
git commit --allow-empty -m "chore: D1 migration — add ai_verdict column to submissions"
```

---

## Task 2: Worker — accept and store ai_verdict in submit.js

**Files:**
- Modify: `cloudflare/src/handlers/submit.js`
- Modify: `cloudflare/test/submit.test.js`

- [ ] **Step 1: Write the failing tests**

Open `cloudflare/test/submit.test.js`. Add these two tests inside the existing `describe('handleSubmit', ...)` block, after the last existing test:

```js
  it('stores ai_verdict when provided with a valid value', async () => {
    const env = makeEnv()
    const capturedBindArgs = []
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn((...args) => {
        capturedBindArgs.push(...args)
        return { run: vi.fn().mockResolvedValue({ success: true }) }
      })
    }))
    const req = makeRequest(makeForm({ ai_verdict: 'AI_COMPROMISE', verdict: 'COMPROMISED' }))
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(201)
    expect(capturedBindArgs).toContain('AI_COMPROMISE')
  })

  it('stores null ai_verdict when field is omitted', async () => {
    const env = makeEnv()
    const capturedBindArgs = []
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn((...args) => {
        capturedBindArgs.push(...args)
        return { run: vi.fn().mockResolvedValue({ success: true }) }
      })
    }))
    const req = makeRequest(makeForm()) // no ai_verdict field
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(201)
    expect(capturedBindArgs).toContain(null) // ai_verdict is null
  })
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher/cloudflare"
npx vitest run test/submit.test.js 2>&1 | tail -20
```

Expected: the two new tests FAIL (ai_verdict not captured yet).

- [ ] **Step 3: Update submit.js**

In `cloudflare/src/handlers/submit.js`, make three changes:

**Change 1** — validate `ai_verdict`. Add this block after the required-fields check (after line 32, before `const briefFile`):

```js
  const validAiVerdicts = ['AI_COMPROMISE', 'AI_FALSE_POSITIVE', 'AI_CLEAN']
  const rawAiVerdict = formData.get('ai_verdict')
  const aiVerdict = validAiVerdicts.includes(rawAiVerdict) ? rawAiVerdict : null
```

**Change 2** — update the INSERT column list (replace the existing INSERT):

```js
    await env.DB.prepare(`
      INSERT INTO submissions
        (id, hostname, username, submitted_at, scan_timestamp, duration, verdict,
         projects_scanned, vulnerable_count, critical_count, paths_scanned, brief_key, report_key,
         ai_verdict)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      formData.get('hostname'),
      formData.get('username'),
      new Date().toISOString(),
      formData.get('scan_timestamp'),
      formData.get('duration')    || null,
      formData.get('verdict'),
      toInt(formData.get('projects_scanned')),
      toInt(formData.get('vulnerable_count')),
      toInt(formData.get('critical_count')),
      formData.get('paths_scanned') || null,
      briefKey,
      reportKey,
      aiVerdict
    ).run()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run test/submit.test.js
```

Expected: ALL tests PASS (including the two new ones).

- [ ] **Step 5: Commit**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher"
git add cloudflare/src/handlers/submit.js cloudflare/test/submit.test.js
git commit -m "feat: accept and store ai_verdict on scan submission"
```

---

## Task 3: Worker — update handleSubmissions and handleStats in api.js

**Files:**
- Modify: `cloudflare/src/handlers/api.js`
- Modify: `cloudflare/test/api.test.js`

### 3a — handleSubmissions

- [ ] **Step 1: Write the failing tests**

Open `cloudflare/test/api.test.js`. Add this describe block after the existing `handleSubmissions` tests:

```js
describe('handleSubmissions — ai_verdict derived fields', () => {
  function makeEnvWithRow(row) {
    const env = makeEnv()
    env.DB.prepare = vi.fn()
      .mockReturnValueOnce({ first: vi.fn().mockResolvedValue({ total: 1 }) })
      .mockReturnValueOnce({
        bind: vi.fn(() => ({
          all: vi.fn().mockResolvedValue({ results: [row] })
        }))
      })
    return env
  }

  it('returns positive=1 for AI_COMPROMISE row', async () => {
    const env = makeEnvWithRow({
      id: 'x', hostname: 'H', username: 'u', submitted_at: '2026-04-01T12:00:00Z',
      verdict: 'COMPROMISED', ai_verdict: 'AI_COMPROMISE',
      positive: 1, reviewed: 0, is_latest: 1
    })
    const res = await handleSubmissions(get('/ratcatcher/api/submissions'), env)
    const body = await res.json()
    expect(body.submissions[0].positive).toBe(1)
    expect(body.submissions[0].reviewed).toBe(0)
  })

  it('returns reviewed=1 for AI_FALSE_POSITIVE row', async () => {
    const env = makeEnvWithRow({
      id: 'y', hostname: 'H', username: 'u', submitted_at: '2026-04-01T12:00:00Z',
      verdict: 'COMPROMISED', ai_verdict: 'AI_FALSE_POSITIVE',
      positive: 0, reviewed: 1, is_latest: 1
    })
    const res = await handleSubmissions(get('/ratcatcher/api/submissions'), env)
    const body = await res.json()
    expect(body.submissions[0].reviewed).toBe(1)
    expect(body.submissions[0].positive).toBe(0)
  })
})
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher/cloudflare"
npx vitest run test/api.test.js 2>&1 | tail -20
```

Expected: the new tests FAIL (query doesn't use ai_verdict yet).

- [ ] **Step 3: Update handleSubmissions in api.js**

In `cloudflare/src/handlers/api.js`, make these changes to `handleSubmissions`:

**Change 1** — replace the `positive === '1'` condition block (the WHERE filter for the positive card click). The whole `if (positive === '1') { ... } else if (filterReviewed === '1') { ... } else if (filterReviewed === '0') { ... }` block becomes:

```js
    if (positive === '1') {
      conditions.push("ai_verdict = 'AI_COMPROMISE'")
    } else if (filterReviewed === '1') {
      conditions.push("(ai_verdict = 'AI_FALSE_POSITIVE' OR (findings_count > 0 AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) >= findings_count AND (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id AND is_threat = 1) = 0))")
    } else if (filterReviewed === '0') {
      conditions.push("(ai_verdict IS NULL AND (findings_count IS NULL OR findings_count = 0 OR (SELECT COUNT(*) FROM finding_acknowledgements WHERE submission_id = submissions.id) < findings_count))")
    }
```

**Change 2** — in the inner SELECT of `rowsStmt`, add `ai_verdict` to the column list:

```js
    const rowsStmt = env.DB.prepare(`
      SELECT s.*,
        CASE WHEN s.submitted_at = latest.max_at THEN 1 ELSE 0 END AS is_latest,
        COALESCE(ac.ack_count, 0) AS ack_count,
        COALESCE(tc.threat_count, 0) AS threat_count,
        CASE WHEN s.ai_verdict = 'AI_COMPROMISE' THEN 1 ELSE 0 END AS positive,
        CASE WHEN s.ai_verdict = 'AI_FALSE_POSITIVE'
               OR (COALESCE(tc.threat_count, 0) = 0 AND s.findings_count > 0 AND COALESCE(ac.ack_count, 0) >= s.findings_count)
             THEN 1 ELSE 0 END AS reviewed
      FROM (
        SELECT id, hostname, username, submitted_at, verdict, ai_verdict, duration,
               projects_scanned, vulnerable_count, critical_count, findings_count
        FROM submissions${where}
        ORDER BY submitted_at DESC
        LIMIT ? OFFSET ?
      ) s
      LEFT JOIN (
        SELECT hostname, MAX(submitted_at) AS max_at FROM submissions GROUP BY hostname
      ) latest ON s.hostname = latest.hostname
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s.id = tc.submission_id
    `)
```

### 3b — handleStats

- [ ] **Step 4: Write the failing stats tests**

Add to `cloudflare/test/api.test.js`, after the `handleStats` tests:

```js
describe('handleStats — ai_verdict logic', () => {
  it('returns correct positive/reviewed/compromised counts based on ai_verdict', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn(() => ({
      first: vi.fn().mockResolvedValue({
        total: 3,
        clean: 0,
        positive: 1,
        reviewed: 1,
        compromised: 1
      })
    }))
    const res = await handleStats(get('/ratcatcher/api/stats'), env)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.positive).toBe(1)
    expect(body.reviewed).toBe(1)
    expect(body.compromised).toBe(1)
  })
})
```

- [ ] **Step 5: Update handleStats in api.js**

Replace the entire SQL string inside `handleStats` with:

```js
    const row = await env.DB.prepare(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN verdict = 'CLEAN' THEN 1 ELSE 0 END) AS clean,
        SUM(CASE WHEN ai_verdict = 'AI_COMPROMISE' THEN 1 ELSE 0 END) AS positive,
        SUM(CASE WHEN ai_verdict = 'AI_FALSE_POSITIVE'
                   OR (verdict = 'COMPROMISED'
                       AND COALESCE(tc.threat_count, 0) = 0
                       AND s.findings_count > 0
                       AND COALESCE(ac.ack_count, 0) >= s.findings_count)
                 THEN 1 ELSE 0 END) AS reviewed,
        SUM(CASE WHEN verdict = 'COMPROMISED'
                   AND ai_verdict IS NULL
                   AND COALESCE(tc.threat_count, 0) = 0
                   AND (s.findings_count IS NULL OR s.findings_count = 0
                        OR COALESCE(ac.ack_count, 0) < s.findings_count)
                 THEN 1 ELSE 0 END) AS compromised
      FROM submissions s
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS ack_count FROM finding_acknowledgements GROUP BY submission_id
      ) ac ON s.id = ac.submission_id
      LEFT JOIN (
        SELECT submission_id, COUNT(*) AS threat_count FROM finding_acknowledgements WHERE is_threat = 1 GROUP BY submission_id
      ) tc ON s.id = tc.submission_id
    `).first()
```

- [ ] **Step 6: Run all tests**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher/cloudflare"
npx vitest run
```

Expected: ALL tests PASS.

- [ ] **Step 7: Commit**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher"
git add cloudflare/src/handlers/api.js cloudflare/test/api.test.js
git commit -m "feat: drive positive/reviewed/not_reviewed stats from ai_verdict"
```

---

## Task 4: Worker — update dashboard.js verdict display

**Files:**
- Modify: `cloudflare/src/handlers/dashboard.js`

No unit tests for the dashboard HTML (it's rendered client-side JS). Verify visually in Task 6.

- [ ] **Step 1: Add the `.ai-fp` row CSS**

In `cloudflare/src/handlers/dashboard.js`, find the CSS block containing `.reviewed` and `.positive` (around line 61). Add one new rule after `.positive`:

```css
tr.ai-fp .vrd{color:#e8a838;font-weight:bold}
```

- [ ] **Step 2: Update the row class assignment**

Find this line (around line 148):

```js
      tr.className=s.verdict==='COMPROMISED'?'comp':'clean';
```

Replace with:

```js
      tr.className=s.ai_verdict==='AI_FALSE_POSITIVE'?'ai-fp':s.verdict==='COMPROMISED'?'comp':'clean';
```

- [ ] **Step 3: Replace the verdict cell**

Find this line (around line 153):

```js
        +'<td class="vrd">'+(s.verdict==='COMPROMISED'?'[!] COMPROMISED':'[+] CLEAN')+(s.positive?'<span class="positive"> &#9888; POSITIVE FINDING</span>':s.reviewed?'<span class="reviewed"> &#10003; REVIEWED</span>':'')+'</td>'
```

Replace with:

```js
        +'<td class="vrd">'+_vl(s)+(s.positive?'<span class="positive"> &#9888; POSITIVE FINDING</span>':s.reviewed?'<span class="reviewed"> &#10003; REVIEWED</span>':'')+'</td>'
```

- [ ] **Step 4: Add the `_vl` helper function**

In `cloudflare/src/handlers/dashboard.js`, find the `<script>` tag opening line (around line 118 — the line with `const B=location.pathname...`). Insert this helper function immediately before that line, inside the `<script>` block:

```js
function _vl(s){if(s.ai_verdict==='AI_COMPROMISE')return'[!] AI Verified Compromise';if(s.ai_verdict==='AI_FALSE_POSITIVE')return'[~] AI Verified False Positive';if(s.ai_verdict==='AI_CLEAN')return'[+] AI Verified Clean';return s.verdict==='COMPROMISED'?'[!] COMPROMISED':'[+] CLEAN'}
```

- [ ] **Step 5: Run all tests to confirm no regressions**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher/cloudflare"
npx vitest run
```

Expected: ALL tests PASS.

- [ ] **Step 6: Commit**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher"
git add cloudflare/src/handlers/dashboard.js
git commit -m "feat: display AI verdict labels and orange row for AI false positives"
```

---

## Task 5: Scanner — compute aggregate ai_verdict and submit it

**Files:**
- Modify: `Private/Submit-ScanToApi.ps1`
- Modify: `Invoke-RatCatcher.ps1`

No new Pester tests for these (the existing `Tests/Submit-ScanToApi.Tests.ps1` tests will run to confirm no regression). The aggregate logic is trivial conditional logic, verified by the deploy smoke test in Task 6.

- [ ] **Step 1: Update Submit-ScanToApi.ps1**

Open `Private/Submit-ScanToApi.ps1`. Make two changes:

**Change 1** — add `$AiVerdict` to the param block, after `$ReportPath`:

```powershell
        [string]$ReportPath,
        [string]$AiVerdict = $null
```

**Change 2** — in the `$fields` ordered hashtable, add `ai_verdict` conditionally. Replace the closing `}` of the `$fields` block with:

```powershell
        paths_scanned    = $PathsScanned
    }
    if ($AiVerdict) { $fields['ai_verdict'] = $AiVerdict }
```

The full updated `$fields` block looks like:

```powershell
        $fields = [ordered]@{
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
        }
        if ($AiVerdict) { $fields['ai_verdict'] = $AiVerdict }
```

- [ ] **Step 2: Run existing Submit-ScanToApi tests**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher"
pwsh -Command "Invoke-Pester Tests/Submit-ScanToApi.Tests.ps1 -Output Detailed" 2>&1 | tail -20
```

Expected: All existing tests PASS.

- [ ] **Step 3: Add aggregate ai_verdict computation to Invoke-RatCatcher.ps1**

Open `Invoke-RatCatcher.ps1`. Find the end of the AI verification block (around line 232 — the line `Write-Log "[AI] LLM verification skipped (-NoVerify)"`). The block ends with the closing `}` of `if (-not $NoVerify)`.

Insert this block **after** that closing `}` and **before** the `# ── Check 9: Generate report` comment:

```powershell
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
```

- [ ] **Step 4: Pass $aiVerdict to Submit-ScanToApi**

Find the `Submit-ScanToApi` call in `Invoke-RatCatcher.ps1` (near the bottom of the file). Add `-AiVerdict $aiVerdict` to the splat. The call looks similar to:

```powershell
    $submitResult = Submit-ScanToApi `
        -ApiUrl          $ApiUrl `
        -Password        $submitPassword `
        -Hostname        $hn `
        -Username        $metadata.Username `
        -ScanTimestamp   $metadata.Timestamp `
        -Duration        $metadata.Duration `
        -Verdict         $overallStatus `
        -ProjectsScanned $projects.Count `
        -VulnerableCount $vulnProjects.Count `
        -CriticalCount   $criticalCount `
        -PathsScanned    ($resolvedPaths | ConvertTo-Json -Compress) `
        -BriefPath       $briefingPath `
        -ReportPath      $reportPath `
        -AiVerdict       $aiVerdict
```

- [ ] **Step 5: Commit**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher"
git add Private/Submit-ScanToApi.ps1 Invoke-RatCatcher.ps1
git commit -m "feat: compute and submit aggregate ai_verdict from scanner"
```

---

## Task 6: Deploy and Verify

- [ ] **Step 1: Deploy the worker**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher/cloudflare"
npx wrangler deploy
```

Expected: `✅ Deployed ... ratcatcher`

- [ ] **Step 2: Refresh the dashboard**

Open the dashboard. Confirm:
- The existing scan row (which has `ai_verdict = NULL`) still shows `[!] COMPROMISED` in red — no regression.
- Stats cards load without error.

- [ ] **Step 3: Run a new scan with AI verification enabled**

```powershell
.\Invoke-RatCatcher.ps1 -SubmitPassword <password> -NonInteractive
```

Expected in the console output:
- `[AI] Aggregate verdict: AI_COMPROMISE` (if findings confirmed) or `AI_FALSE_POSITIVE` / `AI_CLEAN`

- [ ] **Step 4: Verify dashboard verdict label**

After the scan submits, reload the dashboard and confirm:
- **AI_COMPROMISE scan** → row is red, verdict reads `[!] AI Verified Compromise`
- **AI_FALSE_POSITIVE scan** → row is orange text (not red background), verdict reads `[~] AI Verified False Positive`, counts as Reviewed not Not Reviewed
- **AI_CLEAN scan** → row is green, verdict reads `[+] AI Verified Clean`

- [ ] **Step 5: Verify stats cards**

- **Positive Findings** card increments only for AI_COMPROMISE scans
- **Reviewed** card increments for AI_FALSE_POSITIVE scans
- **Not Reviewed** card does NOT count AI_FALSE_POSITIVE scans

- [ ] **Step 6: Push branch**

```bash
cd "/Users/mberry/Documents/Claude Projects/RatCatcher"
git push origin feature/ai-verification
```
