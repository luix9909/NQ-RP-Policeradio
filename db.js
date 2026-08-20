const Database = require('better-sqlite3');
const { nanoid } = require('nanoid');
const path = require('path');

const db = new Database(path.join(__dirname, 'radio.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  email TEXT,
  name TEXT NOT NULL,
  rank TEXT,
  department TEXT,
  role TEXT NOT NULL DEFAULT 'member', -- owner | admin_high | admin_low | member
  banned INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  rank TEXT,
  content TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL,
  reporter_name TEXT NOT NULL,
  location TEXT NOT NULL,
  details TEXT,
  is_panic INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | accepted | finished | rejected
  accepted_by_id INTEGER,
  accepted_by_name TEXT,
  responders TEXT NOT NULL DEFAULT '[]', -- JSON array of {id,name} for panic multi-responders
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  accepted_at TEXT,
  finished_at TEXT
);
`);

// Seed: default rooms (موجة 1..3)
const roomCount = db.prepare('SELECT COUNT(*) c FROM rooms').get().c;
if (roomCount === 0) {
  const ins = db.prepare('INSERT INTO rooms (name, is_default) VALUES (?, 1)');
  ins.run('موجة 1');
  ins.run('موجة 2');
  ins.run('موجة 3');
}

// Seed: default owner code if no users exist yet — generated ONCE, printed once, never regenerated.
let seededOwnerCode = null;
const userCount = db.prepare('SELECT COUNT(*) c FROM users').get().c;
if (userCount === 0) {
  seededOwnerCode = 'OWNER-' + nanoid(8).toUpperCase();
  db.prepare(`INSERT INTO users (code, email, name, rank, department, role)
              VALUES (?, ?, ?, ?, ?, 'owner')`)
    .run(seededOwnerCode, 'slomsalman2@gmail.com', 'المالك', 'قائد عام', 'الإدارة العامة');
}

module.exports = { db, seededOwnerCode };
