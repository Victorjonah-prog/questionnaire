'use strict';

require('dotenv').config();

const express      = require('express');
const cookieSession = require('cookie-session');
const bcrypt       = require('bcryptjs');
const initSqlJs    = require('sql.js');
const path         = require('path');
const fs           = require('fs');

// ---------------------------------------------------------------------------
// Config & validation
// ---------------------------------------------------------------------------
const PORT           = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_PASSWORD) {
  console.error('ERROR: ADMIN_PASSWORD is not set in .env');
  process.exit(1);
}
if (!SESSION_SECRET || SESSION_SECRET === 'replace-with-a-long-random-secret-string') {
  console.warn(
    'WARNING: SESSION_SECRET is not set or uses the default placeholder. ' +
    'Set a strong random string in .env before deploying.'
  );
}

// ---------------------------------------------------------------------------
// Database helpers — sql.js (pure-JS SQLite, no native compilation)
// ---------------------------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH  = path.join(DATA_DIR, 'responses.db');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Persist the in-memory database to disk after every write
let db; // sql.js Database instance

function saveDb() {
  const data = db.export(); // Uint8Array
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// Run a write statement and immediately persist
function run(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

// Return all rows as array of plain objects
function all(sql, params = []) {
  const stmt   = db.prepare(sql);
  stmt.bind(params);
  const rows   = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// Return a single row or undefined
function get(sql, params = []) {
  const rows = all(sql, params);
  return rows[0];
}

// Boot: initialise sql.js, load or create the database, run migrations
async function initDb() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // Schema
  db.run(`
    CREATE TABLE IF NOT EXISTS responses (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      name            TEXT    NOT NULL,
      email           TEXT    NOT NULL,
      contact_address TEXT    NOT NULL DEFAULT '',
      age             INTEGER NOT NULL,
      fan_answer      TEXT    NOT NULL DEFAULT '',
      wife_answer     TEXT    NOT NULL DEFAULT '',
      ideal_answer    TEXT    NOT NULL DEFAULT '',
      submitted_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
    );
  `);

  // Migration: add contact_address column if it doesn't exist yet (for existing DBs)
  try {
    db.run(`ALTER TABLE responses ADD COLUMN contact_address TEXT NOT NULL DEFAULT ''`);
    saveDb();
  } catch (e) {
    // Column already exists — ignore
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS admin_config (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  // Persist schema if newly created
  saveDb();

  // ---------------------------------------------------------------------------
  // Password hashing — read ADMIN_PASSWORD from .env, hash & store once
  // ---------------------------------------------------------------------------
  const storedRow = get("SELECT value FROM admin_config WHERE key = 'password_hash'");

  if (!storedRow) {
    // First run: hash and store
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
    run("INSERT INTO admin_config (key, value) VALUES ('password_hash', ?)", [hash]);
    console.log('Admin password hashed and stored in database.');
  } else if (!bcrypt.compareSync(ADMIN_PASSWORD, storedRow.value)) {
    // .env password was rotated — re-hash and update
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
    run("UPDATE admin_config SET value = ? WHERE key = 'password_hash'", [hash]);
    console.log('Admin password updated (hash refreshed).');
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function sanitize(val) {
  return typeof val === 'string' ? val.trim() : '';
}

function getPasswordHash() {
  const row = get("SELECT value FROM admin_config WHERE key = 'password_hash'");
  return row ? row.value : null;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(cookieSession({
  name: 'session',
  secret: SESSION_SECRET || 'fallback-secret-change-me',
  maxAge: 8 * 60 * 60 * 1000, // 8 hours
  httpOnly: true,
  sameSite: 'lax',
}));

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Routes — Questionnaire
// ---------------------------------------------------------------------------
app.post('/api/submit', (req, res) => {
  const name            = sanitize(req.body.name);
  const email           = sanitize(req.body.email);
  const contact_address = sanitize(req.body.contact_address);
  const age             = parseInt(req.body.age, 10);
  const fan_answer      = sanitize(req.body.fan_answer);
  const wife_answer     = sanitize(req.body.wife_answer);
  const ideal_answer    = sanitize(req.body.ideal_answer);

  const errors = [];
  if (!name)                                                errors.push('Name is required.');
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('A valid email is required.');
  if (!contact_address)                                     errors.push('Contact address is required.');
  if (!req.body.age || isNaN(age) || age < 1 || age > 120)  errors.push('A valid age (1–120) is required.');

  if (errors.length > 0) return res.status(400).json({ ok: false, errors });

  try {
    run(
      `INSERT INTO responses (name, email, contact_address, age, fan_answer, wife_answer, ideal_answer)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, email, contact_address, age, fan_answer, wife_answer, ideal_answer]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error('DB insert error:', err);
    return res.status(500).json({ ok: false, errors: ['Server error. Please try again.'] });
  }
});

// ---------------------------------------------------------------------------
// Routes — Admin
// ---------------------------------------------------------------------------
app.post('/api/admin/login', (req, res) => {
  const password = sanitize(req.body.password);
  const hash     = getPasswordHash();

  if (!password || !hash || !bcrypt.compareSync(password, hash)) {
    return res.status(401).json({ ok: false, error: 'Incorrect password.' });
  }

  req.session.admin = true;
  return res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  req.session = null;
  return res.json({ ok: true });
});

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.status(401).json({ ok: false, error: 'Unauthorised' });
}

app.get('/api/admin/responses', requireAdmin, (req, res) => {
  const q = req.query.q ? `%${req.query.q}%` : null;

  const rows = q
    ? all(
        'SELECT * FROM responses WHERE name LIKE ? OR email LIKE ? ORDER BY submitted_at DESC',
        [q, q]
      )
    : all('SELECT * FROM responses ORDER BY submitted_at DESC');

  return res.json({ ok: true, responses: rows });
});

app.get('/api/admin/me', (req, res) => {
  return res.json({ loggedIn: !!(req.session && req.session.admin) });
});

// Catch-all for client-side routing (non-API GETs)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Questionnaire app running → http://localhost:${PORT}`);
    console.log(`Admin dashboard          → http://localhost:${PORT}/admin.html`);
  });
}).catch(err => {
  console.error('Failed to initialise database:', err);
  process.exit(1);
});
