# Unique Scans Filter Card — Design

**Date:** 2026-04-10
**Status:** Approved for implementation planning

## Problem

The RatCatcher dashboard receives many duplicate scans (the same host scanned repeatedly). The existing `Total Scans` stat card counts every submission row, which overstates how many distinct machines have been scanned. There is no way to see, at a glance, how many distinct machines have reported to the dashboard, and no way to filter the grid to just the most recent scan per machine.

## Goal

Add a seventh stat card, **Unique Scans**, that:

1. Displays the count of distinct hostnames across all submissions (`COUNT(DISTINCT hostname)`).
2. When clicked, filters the submissions grid to show only each machine's most recent scan (one row per hostname, newest `submitted_at`).

No schema changes. No new API endpoint. Reuse the existing filter multiplexer on `/api/submissions`.

## Non-Goals

- No change to how "Total Scans" is counted.
- No change to the existing filters (Clean, Reviewed, Positive Findings, Unreviewed, Remediated).
- No change to the `filterByHost` hostname-link behavior.
- No change to the `/api/stats` auth model or to the submissions schema.

## Uniqueness Definition

A "unique scan" is defined by **hostname**. Two submissions with the same `hostname` but different `username` are still the same machine and count as one. This matches how the existing `remediated` count is computed (`COUNT(DISTINCT hostname)` at `cloudflare/src/handlers/api.js:112`).

## Architecture

The change slots into three existing layers without introducing new ones:

```
┌─────────────────────────────────────────┐
│ dashboard.js (HTML + JS, single file)   │
│  ├── New 7th stat card (f-unique)       │
│  ├── Loader: reads d.unique from /stats │
│  └── Click handler: setFilter('','unique','')
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ api.js handleStats (/api/stats)         │
│  └── Adds COUNT(DISTINCT hostname)      │
│      AS unique_hosts → returns `unique` │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ api.js handleSubmissions                │
│ (/api/submissions?reviewed=unique)      │
│  └── New branch on filterReviewed:      │
│      WHERE submitted_at =               │
│        (SELECT MAX(s3.submitted_at)     │
│         FROM submissions s3             │
│         WHERE s3.hostname =             │
│               submissions.hostname)     │
└─────────────────────────────────────────┘
```

## Detailed Changes

### 1. Backend — `handleStats`

**File:** `cloudflare/src/handlers/api.js` (near line 85, inside the existing stats SELECT)

Add one aggregate column to the existing query:

```sql
COUNT(DISTINCT hostname) AS unique_hosts,
```

Return it in the JSON response at line ~120:

```js
unique: row?.unique_hosts ?? 0,
```

No new subquery, no new joins — the count piggybacks on the existing aggregate read.

### 2. Backend — `handleSubmissions`

**File:** `cloudflare/src/handlers/api.js` (`handleSubmissions`, lines 3–70)

**Step 1** — Extend the `filterReviewed` allowlist at line 15:

```js
const filterReviewed =
  reviewed === '1' || reviewed === '0' ||
  reviewed === 'unreviewed' || reviewed === 'remediated' ||
  reviewed === 'unique'
    ? reviewed : null
```

**Step 2** — Add a new branch to the if/else WHERE-builder (next to the `remediated` branch at line 27):

```js
} else if (filterReviewed === 'unique') {
  conditions.push(
    "submitted_at = (SELECT MAX(s3.submitted_at) FROM submissions s3 WHERE s3.hostname = submissions.hostname)"
  )
}
```

This keeps exactly one row per hostname: the newest by `submitted_at`. It mirrors the `remediated` branch at line 28 but drops the `verdict = 'CLEAN'` and `EXISTS (...COMPROMISED...)` clauses.

**Tie-breaking:** If two rows for the same hostname share an identical `submitted_at` string (extremely unlikely in practice — timestamps are ISO strings with sub-second precision from the submitter), both would be returned. This is acceptable for this feature; no explicit tie-break is added.

### 3. Frontend — HTML (new stat card)

**File:** `cloudflare/src/handlers/dashboard.js` (after line 264, making it the 7th card)

```html
<div class="stat unq" id="f-unique"><div class="lbl">Unique Scans</div><div class="val" id="s-unique">-</div></div>
```

### 4. Frontend — CSS

**File:** `cloudflare/src/handlers/dashboard.js` (near the existing stat color rules at lines 80–82)

```css
.stat.unq .val{color:#58a6ff}
```

Cyan-blue (`#58a6ff`) matches the existing color used for `Remediated` at line 264 and the `remediated` row highlight at line 78, keeping visual consistency. `Remediated` currently inlines its color via `style="color:#58a6ff"`; the `.stat.unq .val` rule is a cleaner class-based equivalent and does not affect `Remediated`.

### 5. Frontend — Stats loader

**File:** `cloudflare/src/handlers/dashboard.js` (near line 594, inside the existing stats loader)

```js
document.getElementById('s-unique').textContent = (d.unique ?? 0).toLocaleString();
```

### 6. Frontend — Filter wiring

**File:** `cloudflare/src/handlers/dashboard.js` (lines 684–700)

**In `setFilter`** — add a branch so the card gets the `selected` class when active:

```js
else if(rv==='unique')document.getElementById('f-unique').classList.add('selected');
```

**Event listener** — add near line 700:

```js
document.getElementById('f-unique').addEventListener('click',function(){setFilter('','unique','')});
```

### 7. Legend modal

**File:** `cloudflare/src/handlers/dashboard.js` (line 313, inside the Status Legend modal)

Add a new row after the existing `Total Scans` row:

```html
<div class="legend-row"><span class="legend-badge" style="color:#58a6ff">Unique Scans</span><span class="legend-desc">Distinct machines (by hostname) that have submitted any scan. Click to filter the grid to each machine's most recent scan only.</span></div>
```

### 8. Walkthrough text

**File:** `cloudflare/src/handlers/dashboard.js` (line 463)

Update the copy from:

> "The dashboard now has **6 filter cards**: Total, Clean, Reviewed, Positive Findings, Unreviewed, and Remediated."

to:

> "The dashboard now has **7 filter cards**: Total, Clean, Reviewed, Positive Findings, Unreviewed, Remediated, and Unique Scans."

### 9. Tests

**File:** `cloudflare/test/` (if stats/submissions tests exist)

- `/api/stats` response should include a `unique` field (number).
- `/api/submissions?reviewed=unique` should return one row per distinct hostname, each being the row with the maximum `submitted_at` for that hostname.
- `reviewed=unique` should compose correctly with `search=` (search narrows the result set within unique rows).

If no such tests exist yet, none are added by this change — test coverage for `/api/stats` and `/api/submissions` is out of scope for this feature.

## Data Flow

1. Page load → `loadStats()` hits `/api/stats` → response includes `unique` → `s-unique` textContent updated.
2. User clicks `f-unique` → `setFilter('', 'unique', '')` → sets `rfilter='unique'` → `loadRows()` → `/api/submissions?reviewed=unique&page=1&limit=50` → server adds the latest-per-hostname WHERE clause → grid shows one row per host.
3. User clicks any other card (or `Total Scans`) → `setFilter` clears `rfilter` → normal behavior resumes.

## Error Handling

Existing error paths (`Unauthorized`, `Database error`) already cover the new query path — the `unique_hosts` aggregate is part of the same `handleStats` try/catch, and the new `filterReviewed === 'unique'` branch is guarded by the same allowlist and auth check as all other filters.

If the `d.unique` field is missing from the response (older deployed server, race during deploy), the loader falls back to `0` via `d.unique ?? 0`, matching how other stat fields are defaulted.

## Testing Plan

Manual verification in the dashboard:

1. Seed or inspect a database with at least two hosts and at least one host with multiple submissions.
2. Open `/dashboard`, log in, confirm the 7th card reads "Unique Scans" with a count equal to the number of distinct hostnames.
3. Confirm `Total Scans` ≥ `Unique Scans`.
4. Click `Unique Scans` → confirm the grid shows exactly one row per hostname, and each row's timestamp matches the newest `submitted_at` for that host.
5. Click `Total Scans` → confirm the grid reverts to showing all rows.
6. Click `Unique Scans`, then type in the search box → confirm search filters within the unique-row set.
7. Open the Status Legend modal → confirm the new "Unique Scans" row is present and readable.

## Open Questions

None. All interpretation questions (uniqueness key, placement, click behavior) were resolved during brainstorming.
