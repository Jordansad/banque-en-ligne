const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Database(path.join(__dirname, 'nationalfinance.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name         TEXT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    nom          TEXT NOT NULL,
    prenom       TEXT NOT NULL,
    email        TEXT NOT NULL,
    telephone    TEXT,
    montant      REAL,
    duree        TEXT,
    type_pret    TEXT,
    revenus      REAL,
    situation    TEXT,
    status       TEXT DEFAULT 'pending',
    notes        TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS clients (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT UNIQUE NOT NULL,
    nom           TEXT NOT NULL,
    prenom        TEXT NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    telephone     TEXT,
    password_hash TEXT NOT NULL,
    temp_password TEXT,
    situation     TEXT,
    revenus       REAL DEFAULT 0,
    balance       REAL DEFAULT 0,
    status        TEXT DEFAULT 'active',
    request_id    INTEGER REFERENCES requests(id),
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     INTEGER NOT NULL REFERENCES clients(id),
    type          TEXT NOT NULL,
    amount        REAL NOT NULL,
    balance_after REAL NOT NULL,
    description   TEXT,
    admin_id      INTEGER REFERENCES admins(id),
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id  INTEGER NOT NULL REFERENCES clients(id),
    message    TEXT NOT NULL,
    type       TEXT DEFAULT 'info',
    read       INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS admin_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id   INTEGER REFERENCES admins(id),
    action     TEXT NOT NULL,
    details    TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transfers (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id      INTEGER NOT NULL REFERENCES clients(id),
    type           TEXT NOT NULL,
    amount         REAL NOT NULL,
    recipient_ref  TEXT,
    recipient_name TEXT,
    bank_name      TEXT,
    status         TEXT DEFAULT 'pending',
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at   DATETIME
  );

  CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed default admin
const existing = db.prepare('SELECT id FROM admins WHERE email = ?').get('admin@nationalfinance.fr');
if (!existing) {
  const hash = bcrypt.hashSync('Admin@2024', 10);
  db.prepare('INSERT INTO admins (email, password_hash, name) VALUES (?, ?, ?)').run(
    'admin@nationalfinance.fr', hash, 'Administrateur Principal'
  );
  console.log('✅ Admin créé → admin@nationalfinance.fr / Admin@2024');
}

if (!db.prepare("SELECT key FROM settings WHERE key='transfer_code'").get()) {
  db.prepare("INSERT INTO settings (key, value) VALUES ('transfer_code', 'NF2024')").run();
}

module.exports = db;
