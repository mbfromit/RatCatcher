# RatCatcher Submission API & Manager Dashboard — Design Spec

**Date:** 2026-04-01
**Status:** Approved

---

## Overview

A Cloudflare-hosted submission API and manager dashboard that collects RatCatcher scan results from up to 1,000 global employees and presents them in a centralized view. Managers can see all submissions, drill into individual reports, and monitor aggregate stats (total scans, clean vs. compromised).

---

## Architecture

All traffic is routed through a **Cloudflare Worker** deployed to the existing `mbfromit.com` domain. No subdomain is created — the feature lives entirely under `mbfromit.com/ratcatcher/*`.

```
mbfromit.com/ratcatcher/
├── submit                  POST  — accepts scan submissions (submission password)
├── dashboard               GET   — manager dashboard UI (admin password)
├── api/submissions         GET   — paginated submission list JSON (admin password)
├── api/stats               GET   — aggregate totals JSON (admin password)
├── api/report/:id/brief    GET   — serve exec briefing HTML from R2 (admin password)
└── api/report/:id/full     GET   — serve forensic report HTML from R2 (admin password)
```

### Cloudflare Services

| Service | Purpose | Free Tier |
|---|---|---|
| Workers | API logic + dashboard serving | 100k req/day |
| D1 (SQLite) | Submission metadata, stats queries | 5M rows/day |
| R2 | HTML file storage | 10GB / 1M ops/month |

---

## Authentication

**Two separate passwords, no usernames.**

| Password | Used by | Protects |
|---|---|---|
| Submission password | RatCatcher script (employees) | `POST /submit` |
| Admin password | Managers | All `/dashboard` and `/api/*` routes |

Both passwords are stored as **Cloudflare Worker secrets** (environment variables), never in source code.

**Submission password distribution:** Shared via SharePoint / Teams / Email by IT. Employees enter it when prompted by the script.

**Admin password:** Stored in `sessionStorage` in the browser after login. Sent as `X-Admin-Password` header on every API call. Stateless — no sessions or cookies.

---

## Data Model

### D1 Table: `submissions`

```sql
CREATE TABLE submissions (
    id               TEXT PRIMARY KEY,   -- UUID generated at submission time
    hostname         TEXT NOT NULL,      -- from COMPUTERNAME env var
    username         TEXT NOT NULL,      -- from USERNAME env var
    submitted_at     TEXT NOT NULL,      -- ISO 8601, when API received it
    scan_timestamp   TEXT NOT NULL,      -- from scan metadata
    duration         TEXT,               -- e.g. "47.3s"
    verdict          TEXT NOT NULL,      -- 'CLEAN' or 'COMPROMISED'
    projects_scanned INTEGER,
    vulnerable_count INTEGER,
    critical_count   INTEGER,
    paths_scanned    TEXT,               -- JSON array of scanned paths
    brief_key        TEXT NOT NULL,      -- R2 key: submissions/{id}/brief.html
    report_key       TEXT NOT NULL       -- R2 key: submissions/{id}/report.html
);
```

### R2 Object Keys

```
submissions/{id}/brief.html    — exec briefing HTML
submissions/{id}/report.html   — forensic report HTML
```

### Stats Query

```sql
SELECT
    COUNT(*)                        AS total,
    SUM(verdict = 'CLEAN')          AS clean,
    SUM(verdict = 'COMPROMISED')    AS compromised
FROM submissions;
```

---

## API Contract

### POST /ratcatcher/submit

Accepts `multipart/form-data`. No authentication header — password is a form field.

**Request fields:**

| Field | Type | Description |
|---|---|---|
| `password` | text | Shared submission password |
| `hostname` | text | Machine name |
| `username` | text | Windows username |
| `scan_timestamp` | text | ISO 8601 timestamp from scan |
| `duration` | text | Scan duration string |
| `verdict` | text | `CLEAN` or `COMPROMISED` |
| `projects_scanned` | text | Integer as string |
| `vulnerable_count` | text | Integer as string |
| `critical_count` | text | Integer as string |
| `paths_scanned` | text | JSON array string |
| `brief` | file | Exec briefing HTML file |
| `report` | file | Forensic report HTML file |

**Responses:**

| Code | Meaning |
|---|---|
| `201` | `{"id": "<uuid>"}` — submission stored |
| `400` | Missing required field(s) |
| `401` | Incorrect submission password |
| `413` | HTML file exceeds 25MB limit |
| `500` | Storage failure (D1 or R2) |

**Atomicity:** Both HTML files are written to R2 before the D1 row is inserted. If either R2 upload fails, no metadata row is written.

### GET /ratcatcher/api/submissions

Returns paginated submission list. Admin password required via `X-Admin-Password` header.

Query params: `?page=1&limit=50`

```json
{
  "total": 1247,
  "page": 1,
  "limit": 50,
  "submissions": [
    {
      "id": "uuid",
      "hostname": "DESKTOP-ABC123",
      "username": "jsmith",
      "submitted_at": "2026-04-01T14:32:00Z",
      "verdict": "CLEAN",
      "duration": "47.3s",
      "projects_scanned": 12,
      "vulnerable_count": 0,
      "critical_count": 0
    }
  ]
}
```

### GET /ratcatcher/api/stats

```json
{
  "total": 1247,
  "clean": 1189,
  "compromised": 58
}
```

### GET /ratcatcher/api/report/:id/brief
### GET /ratcatcher/api/report/:id/full

Streams the HTML file from R2. Returns `Content-Type: text/html`. If the R2 object is missing, returns a plain "Report no longer available" HTML page.

---

## Manager Dashboard

Single-page HTML app served at `mbfromit.com/ratcatcher/dashboard` by the Worker. Matches the existing dark security look and feel of the scan reports.

### Login View

Password form. On success, admin password is stored in `sessionStorage`.

### Dashboard View

**Stats bar:**
```
[ Total Scans: 1,247 ]  [ Clean: 1,189 ✓ ]  [ Compromised: 58 ⚠ ]
```

**Submissions table** (newest first, 50 per page):

| Submitted | Hostname | User | Duration | Verdict | Actions |
|---|---|---|---|---|---|
| 2026-04-01 14:32 | DESKTOP-ABC123 | jsmith | 47.3s | ✓ CLEAN | View |
| 2026-04-01 09:11 | LAPTOP-XYZ789 | mbrown | 2m 14s | ⚠ COMPROMISED | View |

- COMPROMISED rows highlighted in red
- **View** opens the exec briefing HTML in a new tab
- The Worker injects a "Full Technical Report →" banner at the top of the briefing HTML when serving it, linking to `/api/report/:id/full`. This avoids storing absolute URLs in R2.

---

## PowerShell Changes (Invoke-RatCatcher.ps1)

Add a `-Submit` switch parameter. When present, after the scan completes:

1. Prompt: `"Enter RatCatcher submission password (press Enter to skip):"`
2. If skipped (empty input): log `[WARN] Submission skipped` and exit normally
3. If entered: POST `multipart/form-data` to `https://mbfromit.com/ratcatcher/submit` via `Invoke-RestMethod`
4. On `201`: log `[INFO] Scan submitted successfully (ID: <uuid>)`
5. On `401`: log `[WARN] Submission password incorrect — report not submitted`
6. On network/other error: log `[WARN] Submission failed: <reason>`

**Submission never blocks the scan exit code.** A failed submission does not change exit 0/1.

---

## Error Handling

| Scenario | Behavior |
|---|---|
| User skips password prompt | Submission skipped silently with WARN log |
| Network failure during POST | WARN logged, scan exits normally |
| Wrong submission password | API returns 401, WARN logged |
| Wrong admin password on dashboard | "Incorrect password" shown, no data exposed |
| R2 file manually deleted | View link returns "Report no longer available" page |
| HTML file > 25MB | API returns 413 (RatCatcher reports are well under 1MB in practice) |
| R2 upload fails mid-submission | D1 row not written — atomic, no partial records |

---

## Deployment Notes

- Worker is deployed via Wrangler CLI (`wrangler deploy`)
- Both passwords stored as Worker secrets (`wrangler secret put SUBMIT_PASSWORD`, `wrangler secret put ADMIN_PASSWORD`)
- D1 database and R2 bucket created in the Cloudflare dashboard and bound to the Worker in `wrangler.toml`
- Worker route added: `mbfromit.com/ratcatcher/*`
