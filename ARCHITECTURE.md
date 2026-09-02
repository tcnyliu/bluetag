# BlueTag — Architecture Sketch

A small server-rendered Express app. No client framework: every page is HTML rendered on the
server with EJS, and all state lives in one SQLite file (`node:sqlite`, no external DB server).

```
                         Browser
                            │  HTTP: form GET/POST + session cookie
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ src/index.js — Express app                                        │
│   • express.urlencoded()          parse form bodies               │
│   • express-session               cookie: httpOnly, sameSite=lax  │
│   • attachUser middleware         → res.locals.currentUser/flash  │
│                                                                   │
│   Routes:                                                         │
│     src/routes/auth.js    GET/POST /register  /login   /logout    │
│     src/routes/items.js   GET  /                (public board)    │
│                           GET  /items/:id       (public detail)   │
│                           GET  /items/new       [auth]            │
│                           POST /items           [auth]            │
│                           POST /items/:id/resolve [auth + owner]  │
│                           GET  /me              [auth]            │
└───────────────┬───────────────────────────────────────────────────┘
                │ db.prepare(...).get()/.all()/.run()
                ▼
┌─────────────────────────────────────────────────────────────────┐
│ src/db.js — node:sqlite DatabaseSync → data/bluetag.db (WAL)      │
│   tables: users · items · intake_log                              │
│   src/seed.js seeds demo data once on first boot                  │
└───────────────┬───────────────────────────────────────────────────┘
                │ rows
                ▼
        src/views/*.ejs  →  HTML (all values escaped via <%= %>)  →  Browser
```

### 1. How a request becomes a row
A signed-in user submits `POST /items`. The handler normalizes `kind`/`category` against
fixed allow-lists, validates field lengths, then runs a **parameterized**
`INSERT INTO items (...) VALUES (?, …)` bound to `req.session.user.id` plus the field values.
`info.lastInsertRowid` is the new id, and the user is redirected to `/items/:id`.

### 2. Where authentication is enforced
Sessions are cookie-based (express-session). `POST /login` looks the user up with a bound
query and checks the password with `bcrypt.compareSync`; on success a minimal
`{ id, email, displayName }` is stored in `req.session.user`.
- **Route gate:** the `requireAuth` middleware (`src/middleware/auth.js`) protects
  `/items/new`, `POST /items`, `POST /items/:id/resolve`, and `/me`.
- **Ownership gate:** `resolve` additionally checks `item.user_id === req.session.user.id`
  *and* scopes the UPDATE `WHERE id = ? AND user_id = ?`, so you can only close your own posts.
- The board (`/`) and item detail (`/items/:id`) are intentionally public (no login).

### 3. How search, filters, and item pages load data
`GET /` reads `q`, `category`, `kind` from the query string and calls `searchItems()`, which
builds `SELECT … FROM items JOIN users` restricted to `status != 'removed'`, ordered
newest-first, `LIMIT 50`. `GET /items/:id` runs one bound `SELECT` joining the poster's
`display_name`/`email`. All output is HTML-escaped by EJS (`<%= %>`).

> Security note: `searchItems()` was the one query that concatenated user input into SQL
> instead of binding it — the SQL-injection defect fixed in this submission. It now uses
> bound `?` parameters like every other query above. See [WRITEUP.md](WRITEUP.md).
