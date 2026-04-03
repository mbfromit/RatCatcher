# AI Verdict Display — Design Spec

**Date:** 2026-04-02
**Branch:** feature/ai-verification

## Goal

Replace the binary COMPROMISED/CLEAN verdict label in the dashboard with AI-aware labels that reflect the outcome of Ollama verification. Only scans where AI confirmed a real threat show red. AI-cleared false positives are shown in orange and auto-count as reviewed.

---

## Data Model

### D1 Migration

```sql
ALTER TABLE submissions ADD COLUMN ai_verdict TEXT;
```

**Allowed values:**

| Value | Meaning |
|---|---|
| `NULL` | AI verification did not run |
| `AI_COMPROMISE` | AI confirmed ≥1 finding as Confirmed or Likely |
| `AI_FALSE_POSITIVE` | AI ran; all findings were Unlikely or FalsePositive |
| `AI_CLEAN` | AI ran; scan was clean (no findings) |

Old rows remain `NULL` and display exactly as before.

---

## Aggregate AI Verdict Rule (computed in scanner)

After all findings have been passed through `Invoke-FindingVerification`:

```
if (no findings AND AI ran)            → AI_CLEAN
elif (any finding is Confirmed/Likely) → AI_COMPROMISE
elif (AI ran)                          → AI_FALSE_POSITIVE
else                                   → omit field (NULL in D1)
```

"AI ran" = `Invoke-FindingVerification` was called and returned without error for at least one finding category, OR the scan was CLEAN and Ollama was reachable.

---

## Scanner Changes (PowerShell)

### RatCatcher.ps1 (main scan script)

After AI verification completes, compute the aggregate and pass to `Submit-ScanToApi`:

```powershell
$aiVerdict = $null
if ($aiRan) {
    $allAiFindings = $allFindings  # findings that went through Invoke-FindingVerification
    if ($allAiFindings.Count -eq 0) {
        $aiVerdict = 'AI_CLEAN'
    } elseif ($allAiFindings | Where-Object { $_.AiVerdict -in 'Confirmed', 'Likely' }) {
        $aiVerdict = 'AI_COMPROMISE'
    } else {
        $aiVerdict = 'AI_FALSE_POSITIVE'
    }
}
```

### Submit-ScanToApi.ps1

Add optional `$AiVerdict` parameter. When non-null, include as `ai_verdict` form field. When null, omit the field entirely so the D1 column stays NULL.

---

## Worker Changes (Cloudflare)

### submit.js

- Read `ai_verdict` from form data
- Validate: accept only `AI_COMPROMISE`, `AI_FALSE_POSITIVE`, `AI_CLEAN`, or null/missing
- Store in `submissions.ai_verdict`

### api.js — handleSubmissions

Include `ai_verdict` in the SELECT. Update derived columns:

```sql
-- positive: only AI-confirmed threats
CASE WHEN s.ai_verdict = 'AI_COMPROMISE' THEN 1 ELSE 0 END AS positive,

-- reviewed: AI false positive OR manually reviewed
CASE WHEN s.ai_verdict = 'AI_FALSE_POSITIVE'
       OR (COALESCE(tc.threat_count,0) = 0
           AND s.findings_count > 0
           AND COALESCE(ac.ack_count,0) >= s.findings_count)
     THEN 1 ELSE 0 END AS reviewed
```

### api.js — handleStats

```sql
SUM(CASE WHEN ai_verdict = 'AI_COMPROMISE' THEN 1 ELSE 0 END) AS positive,

SUM(CASE WHEN ai_verdict = 'AI_FALSE_POSITIVE'
           OR (verdict = 'COMPROMISED'
               AND COALESCE(tc.threat_count,0) = 0
               AND s.findings_count > 0
               AND COALESCE(ac.ack_count,0) >= s.findings_count)
         THEN 1 ELSE 0 END) AS reviewed,

SUM(CASE WHEN verdict = 'COMPROMISED'
           AND ai_verdict IS NULL
           AND (s.findings_count IS NULL OR s.findings_count = 0
                OR COALESCE(ac.ack_count,0) < s.findings_count)
         THEN 1 ELSE 0 END) AS not_reviewed
```

### dashboard.js — verdict cell rendering

| `verdict` | `ai_verdict` | Label | Color |
|---|---|---|---|
| COMPROMISED | `AI_COMPROMISE` | `[!] AI Verified Compromise` | Red (existing `.comp`) |
| COMPROMISED | `AI_FALSE_POSITIVE` | `[~] AI Verified False Positive` | Orange (new `.ai-fp` class) |
| COMPROMISED | NULL | `[!] COMPROMISED` | Red (unchanged) |
| CLEAN | `AI_CLEAN` | `[+] AI Verified Clean` | Green (existing `.clean`) |
| CLEAN | NULL | `[+] CLEAN` | Green (unchanged) |

New CSS class:
```css
.ai-fp { color: #e8a838; }
```

The existing POSITIVE FINDING / REVIEWED badges remain for scans that have also been manually confirmed/acknowledged.

---

## Stats Card Impact

| Card | Logic |
|---|---|
| **Positive Findings** | `ai_verdict = 'AI_COMPROMISE'` |
| **Reviewed** | `ai_verdict = 'AI_FALSE_POSITIVE'` OR manually reviewed |
| **Not Reviewed** | `verdict = 'COMPROMISED'` AND `ai_verdict IS NULL` AND not manually reviewed |
| **Clean** | `verdict = 'CLEAN'` (unchanged) |
| **Compromised** | `verdict = 'COMPROMISED'` (unchanged — raw count) |

---

## Files Changed

| File | Change |
|---|---|
| D1 (wrangler CLI) | `ALTER TABLE submissions ADD COLUMN ai_verdict TEXT` |
| `Private/Submit-ScanToApi.ps1` | Add `$AiVerdict` param + form field |
| `RatCatcher.ps1` | Compute aggregate `$aiVerdict` after AI verification; pass to Submit |
| `cloudflare/src/handlers/submit.js` | Accept + validate + store `ai_verdict` |
| `cloudflare/src/handlers/api.js` | Update SELECT, positive/reviewed/not_reviewed logic in both queries |
| `cloudflare/src/handlers/dashboard.js` | Update verdict cell label + color; add `.ai-fp` CSS |

---

## Out of Scope

- Per-finding AI verdict display in the dashboard (already in HTML report)
- Retroactively re-running AI on old scans
- Changing the base `verdict` column (still CLEAN/COMPROMISED)
