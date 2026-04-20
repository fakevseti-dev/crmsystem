'use strict';

const express    = require('express');
const Database   = require('better-sqlite3');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────
// DATABASE SETUP
// ─────────────────────────────────────
const DB_PATH = path.join(__dirname, 'crm.db');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    login           TEXT UNIQUE NOT NULL,
    password        TEXT NOT NULL,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'manager',
    created_at      TEXT DEFAULT (datetime('now')),
    plain_password  TEXT,
    login_blocked   INTEGER DEFAULT 0,
    login_err_msg   TEXT DEFAULT 'Аккаунт заблокирован администратором.',
    save_blocked    INTEGER DEFAULT 0,
    save_err_title  TEXT DEFAULT 'Ошибка подключения к серверу',
    save_err_code   TEXT DEFAULT 'ERR_CONNECTION_REFUSED',
    save_err_msg    TEXT DEFAULT 'Попробуйте повторить позже или обратитесь к администратору.'
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    expires_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS orders (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    order_num     TEXT UNIQUE NOT NULL,
    manager_id    INTEGER NOT NULL,
    carrier       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'new',
    fio           TEXT NOT NULL,
    phone         TEXT NOT NULL,
    telegram      TEXT,
    product       TEXT NOT NULL,
    size_var      TEXT,
    qty           INTEGER DEFAULT 1,
    price         REAL,
    sku           TEXT,
    product_note  TEXT,
    city          TEXT,
    delivery_type TEXT,
    address       TEXT,
    post_index    TEXT,
    region        TEXT,
    street        TEXT,
    house         TEXT,
    apt           TEXT,
    np_enabled    INTEGER DEFAULT 0,
    np_sum        REAL,
    np_payer      TEXT,
    np_note       TEXT,
    created_at    TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (manager_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    action     TEXT,
    details    TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Seed default accounts
const hashPass = p => crypto.createHash('sha256').update(p).digest('hex');

const seedUser = db.prepare(
  `INSERT OR IGNORE INTO users (login, password, name, role) VALUES (?, ?, ?, ?)`
);
// Add plain_password column if not exists (migration)
try { db.exec("ALTER TABLE users ADD COLUMN plain_password TEXT"); } catch(e) {}

const seedUser2 = db.prepare(
  `INSERT OR IGNORE INTO users (login, password, plain_password, name, role) VALUES (?, ?, ?, ?, ?)`
);
seedUser2.run('admin',    hashPass('admin123'), 'admin123', 'Администратор', 'admin');
seedUser2.run('manager1', hashPass('pass123'),  'pass123',  'Менеджер Иван', 'manager');

console.log('[DB] Ready:', DB_PATH);

// ─────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  // Clean expired
  db.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`).run();

  const session = db.prepare(
    `SELECT s.user_id, u.login, u.name, u.role,
            u.save_blocked, u.save_err_title, u.save_err_code, u.save_err_msg
     FROM sessions s
     JOIN users u ON s.user_id = u.id
     WHERE s.token = ? AND s.expires_at > datetime('now')`
  ).get(token);

  if (!session) return res.status(401).json({ error: 'Session expired' });
  req.user = session;
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ─────────────────────────────────────
// HELPERS
// ─────────────────────────────────────
function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

function genOrderNum() {
  const d = new Date();
  const yy = String(d.getFullYear()).slice(2);
  const mm = String(d.getMonth()+1).padStart(2,'0');
  const dd = String(d.getDate()).padStart(2,'0');
  const rnd = Math.floor(Math.random()*9000+1000);
  return `ORD-${yy}${mm}${dd}-${rnd}`;
}

// ─────────────────────────────────────
// ROUTES — AUTH
// ─────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password)
    return res.status(400).json({ error: 'Введите логин и пароль.' });

  const user = db.prepare('SELECT * FROM users WHERE login = ?').get(login);
  if (!user || user.password !== hashPass(password))
    return res.status(401).json({ error: 'Неверный логин или пароль.' });

  if (user.login_blocked)
    return res.status(403).json({ error: user.login_err_msg || 'Аккаунт заблокирован.' });

  // Remove old sessions for this user
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);

  const token = makeToken();
  const expires = new Date(Date.now() + 24*60*60*1000)
    .toISOString().replace('T',' ').slice(0,19);

  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)')
    .run(token, user.id, expires);

  db.prepare('INSERT INTO activity_log (user_id, action, details) VALUES (?,?,?)')
    .run(user.id, 'login', `IP: ${req.ip}`);

  res.json({
    token,
    user: { id: user.id, login: user.login, name: user.name, role: user.role }
  });
});

app.post('/api/auth/logout', auth, (req, res) => {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '');
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ user: req.user });
});

// ─────────────────────────────────────
// ROUTES — USERS
// ─────────────────────────────────────
app.get('/api/users', auth, adminOnly, (req, res) => {
  const users = db.prepare(
    `SELECT id, login, name, role, created_at,
            plain_password,
            login_blocked, login_err_msg,
            save_blocked, save_err_title, save_err_code, save_err_msg
     FROM users WHERE role != 'admin' ORDER BY id`
  ).all();
  res.json({ users });
});

app.post('/api/users', auth, adminOnly, (req, res) => {
  const { name, login, password, role = 'manager' } = req.body || {};
  if (!name || !login || !password)
    return res.status(400).json({ error: 'Заполните все обязательные поля.' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Пароль минимум 4 символа.' });

  const exists = db.prepare('SELECT id FROM users WHERE login = ?').get(login);
  if (exists) return res.status(409).json({ error: 'Логин уже занят.' });

  db.prepare(
    `INSERT INTO users (login, password, plain_password, name, role) VALUES (?,?,?,?,?)`
  ).run(login, hashPass(password), password, name, ['manager','admin'].includes(role) ? role : 'manager');

  res.json({ ok: true });
});

app.patch('/api/users/:id', auth, adminOnly, (req, res) => {
  const id   = parseInt(req.params.id);
  const data = req.body || {};
  const allowed = ['login_blocked','login_err_msg','save_blocked',
                   'save_err_title','save_err_code','save_err_msg'];

  const fields = allowed.filter(k => k in data);
  if (!fields.length) return res.status(400).json({ error: 'Нет данных.' });

  const set  = fields.map(k => `${k} = ?`).join(', ');
  const vals = fields.map(k => data[k]);
  vals.push(id);

  db.prepare(`UPDATE users SET ${set} WHERE id = ?`).run(...vals);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  db.prepare(`DELETE FROM users WHERE id = ? AND role != 'admin'`).run(parseInt(req.params.id));
  res.json({ ok: true });
});

app.post('/api/users/:id/toggle-login', auth, adminOnly, (req, res) => {
  const user = db.prepare('SELECT login_blocked FROM users WHERE id = ?').get(parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Not found' });
  const next = user.login_blocked ? 0 : 1;
  db.prepare('UPDATE users SET login_blocked = ? WHERE id = ?').run(next, parseInt(req.params.id));
  res.json({ ok: true, login_blocked: Boolean(next) });
});

app.post('/api/users/:id/toggle-save', auth, adminOnly, (req, res) => {
  const user = db.prepare('SELECT save_blocked FROM users WHERE id = ?').get(parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Not found' });
  const next = user.save_blocked ? 0 : 1;
  db.prepare('UPDATE users SET save_blocked = ? WHERE id = ?').run(next, parseInt(req.params.id));
  res.json({ ok: true, save_blocked: Boolean(next) });
});

// ─────────────────────────────────────
// ROUTES — ORDERS
// ─────────────────────────────────────
app.get('/api/orders', auth, (req, res) => {
  let orders;
  if (req.user.role === 'admin') {
    orders = db.prepare(
      `SELECT o.*, u.name as manager_name
       FROM orders o JOIN users u ON o.manager_id = u.id
       ORDER BY o.created_at DESC LIMIT 200`
    ).all();
  } else {
    orders = db.prepare(
      `SELECT o.*, u.name as manager_name
       FROM orders o JOIN users u ON o.manager_id = u.id
       WHERE o.manager_id = ?
       ORDER BY o.created_at DESC LIMIT 100`
    ).all(req.user.user_id);
  }
  res.json({ orders });
});

app.post('/api/orders', auth, (req, res) => {
  // Check save block (real-time from DB)
  const fresh = db.prepare(
    'SELECT save_blocked, save_err_title, save_err_code, save_err_msg FROM users WHERE id = ?'
  ).get(req.user.user_id);

  if (fresh && fresh.save_blocked) {
    return res.status(503).json({
      error: 'blocked',
      title: fresh.save_err_title,
      code:  fresh.save_err_code,
      msg:   fresh.save_err_msg
    });
  }

  const d = req.body || {};
  if (!d.carrier || !d.fio || !d.phone || !d.product)
    return res.status(400).json({ error: 'Не заполнены обязательные поля.' });

  // Generate unique order number
  let orderNum;
  do { orderNum = genOrderNum(); }
  while (db.prepare('SELECT id FROM orders WHERE order_num = ?').get(orderNum));

  db.prepare(`
    INSERT INTO orders (
      order_num, manager_id, carrier, status,
      fio, phone, telegram, product, size_var, qty, price, sku, product_note,
      city, delivery_type, address,
      post_index, region, street, house, apt,
      np_enabled, np_sum, np_payer, np_note
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    orderNum, req.user.user_id, d.carrier, 'new',
    d.fio, d.phone, d.telegram || null,
    d.product, d.size_var || null,
    d.qty || 1, d.price || null, d.sku || null, d.product_note || null,
    d.city || null, d.delivery_type || null, d.address || null,
    d.post_index || null, d.region || null, d.street || null,
    d.house || null, d.apt || null,
    d.np_enabled ? 1 : 0,
    d.np_sum || null, d.np_payer || null, d.np_note || null
  );

  db.prepare('INSERT INTO activity_log (user_id, action, details) VALUES (?,?,?)')
    .run(req.user.user_id, 'create_order', orderNum);

  res.json({ ok: true, order_num: orderNum });
});

app.patch('/api/orders/:id/status', auth, (req, res) => {
  const { status } = req.body || {};
  const valid = ['new','processing','shipped','delivered','cancelled'];
  if (!valid.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, parseInt(req.params.id));
  res.json({ ok: true });
});

// ─────────────────────────────────────
// ROUTES — STATS
// ─────────────────────────────────────
app.get('/api/stats', auth, adminOnly, (req, res) => {
  const managers    = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='manager'`).get().c;
  const active      = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='manager' AND login_blocked=0`).get().c;
  const blocked     = db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='manager' AND login_blocked=1`).get().c;
  const totalOrders = db.prepare(`SELECT COUNT(*) as c FROM orders`).get().c;
  const todayOrders = db.prepare(`SELECT COUNT(*) as c FROM orders WHERE date(created_at)=date('now')`).get().c;
  const byCarrier   = db.prepare(`SELECT carrier, COUNT(*) as cnt FROM orders GROUP BY carrier`).all();
  const byStatus    = db.prepare(`SELECT status, COUNT(*) as cnt FROM orders GROUP BY status`).all();

  res.json({ managers, active, blocked, total_orders: totalOrders, today_orders: todayOrders, by_carrier: byCarrier, by_status: byStatus });
});

app.get('/api/stats/manager', auth, (req, res) => {
  const uid = req.user.user_id;
  const total     = db.prepare(`SELECT COUNT(*) as c FROM orders WHERE manager_id=?`).get(uid).c;
  const shipped   = db.prepare(`SELECT COUNT(*) as c FROM orders WHERE manager_id=? AND status='shipped'`).get(uid).c;
  const delivered = db.prepare(`SELECT COUNT(*) as c FROM orders WHERE manager_id=? AND status='delivered'`).get(uid).c;
  const pending   = db.prepare(`SELECT COUNT(*) as c FROM orders WHERE manager_id=? AND status='new'`).get(uid).c;
  res.json({ total, shipped, delivered, pending });
});

// ─────────────────────────────────────
// SPA FALLBACK
// ─────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────
// START
// ─────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[CRM] Server running on http://localhost:${PORT}`);
});
