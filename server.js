'use strict';

require('dotenv').config();

const express       = require('express');
const cookieSession = require('cookie-session');
const bcrypt        = require('bcryptjs');
const { Pool }      = require('pg');
const path          = require('path');

// ---------------------------------------------------------------------------
// Config & validation
// ---------------------------------------------------------------------------
const PORT           = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL   = process.env.DATABASE_URL;

if (!ADMIN_PASSWORD) { console.error('ERROR: ADMIN_PASSWORD is not set'); process.exit(1); }
if (!DATABASE_URL)   { console.error('ERROR: DATABASE_URL is not set');   process.exit(1); }
if (!SESSION_SECRET || SESSION_SECRET === 'replace-with-a-long-random-secret-string') {
  console.warn('WARNING: SESSION_SECRET is not set or uses the default placeholder.');
}

// ---------------------------------------------------------------------------
// Postgres connection pool
// ---------------------------------------------------------------------------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Neon
});

// ---------------------------------------------------------------------------
// Database initialisation — create tables and handle password hashing
// ---------------------------------------------------------------------------
async function initDb() {
  // Create tables if they don't exist
  await pool.query(`
    CREATE TABLE IF NOT EXISTS responses (
      id              SERIAL PRIMARY KEY,
      name            TEXT    NOT NULL,
      email           TEXT    NOT NULL,
      contact_address TEXT    NOT NULL DEFAULT '',
      age             INTEGER NOT NULL,
      fan_answer      TEXT    NOT NULL DEFAULT '',
      wife_answer     TEXT    NOT NULL DEFAULT '',
      ideal_answer    TEXT    NOT NULL DEFAULT '',
      submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_config (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  // Hash and store the admin password (or refresh if it changed)
  const result = await pool.query("SELECT value FROM admin_config WHERE key = 'password_hash'");
  const stored = result.rows[0];

  if (!stored) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
    await pool.query(
      "INSERT INTO admin_config (key, value) VALUES ('password_hash', $1)",
      [hash]
    );
    console.log('Admin password hashed and stored in database.');
  } else if (!bcrypt.compareSync(ADMIN_PASSWORD, stored.value)) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
    await pool.query(
      "UPDATE admin_config SET value = $1 WHERE key = 'password_hash'",
      [hash]
    );
    console.log('Admin password updated (hash refreshed).');
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function sanitize(val) {
  return typeof val === 'string' ? val.trim() : '';
}

async function getPasswordHash() {
  const result = await pool.query("SELECT value FROM admin_config WHERE key = 'password_hash'");
  return result.rows[0]?.value || null;
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
app.post('/api/submit', async (req, res) => {
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
    await pool.query(
      `INSERT INTO responses (name, email, contact_address, age, fan_answer, wife_answer, ideal_answer)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
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
app.post('/api/admin/login', async (req, res) => {
  const password = sanitize(req.body.password);
  const hash     = await getPasswordHash();

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

app.get('/api/admin/responses', requireAdmin, async (req, res) => {
  try {
    const q = req.query.q ? `%${req.query.q}%` : null;

    const result = q
      ? await pool.query(
          `SELECT * FROM responses
           WHERE name ILIKE $1 OR email ILIKE $1
           ORDER BY submitted_at DESC`,
          [q]
        )
      : await pool.query('SELECT * FROM responses ORDER BY submitted_at DESC');

    return res.json({ ok: true, responses: result.rows });
  } catch (err) {
    console.error('DB query error:', err);
    return res.status(500).json({ ok: false, error: 'Failed to fetch responses.' });
  }
});

app.get('/api/admin/me', (req, res) => {
  return res.json({ loggedIn: !!(req.session && req.session.admin) });
});

// Catch-all for non-API GETs
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
