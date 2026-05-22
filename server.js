// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Pool de conexões MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Session store com MySQL (persistente em produção)
const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'troque-por-uma-chave-secreta',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
  }
}));

const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Servir arquivos estáticos (frontend)
app.use(express.static(path.join(__dirname, 'public')));

// Helpers
async function query(sql, params=[]) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}
async function getOne(sql, params=[]) {
  const rows = await query(sql, params);
  return rows[0] || null;
}

// Autenticação por sessão
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}
function requireRole(roles) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    if (req.session.user.role === 'admin' || roles.includes(req.session.user.role)) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}

// Login
app.post('/api/login', asyncHandler(async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.status(400).json({ error: 'login e password obrigatórios' });
  const user = await getOne('SELECT * FROM users WHERE login_id = ? OR phone = ? OR name = ? LIMIT 1', [login, login, login]);
  if (!user) return res.status(401).json({ error: 'Credenciais inválidas' });

  const stored = user.password || '';
  let ok = false;
  if (stored.startsWith('$2')) {
    ok = bcrypt.compareSync(password, stored);
  } else {
    ok = (password === stored);
    if (ok) {
      const hash = bcrypt.hashSync(password, 10);
      await query('UPDATE users SET password = ? WHERE id = ?', [hash, user.id]);
    }
  }
  if (!ok) return res.status(401).json({ error: 'Credenciais inválidas' });

  req.session.user = { id: user.id, name: user.name, role: user.role };
  res.json({ id: user.id, name: user.name, role: user.role });
}));

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Erro ao terminar a sessão' });
    res.json({ ok: true });
  });
});

/* Users CRUD admin only */
app.get('/api/users', requireAuth, requireRole(['admin']), asyncHandler(async (req, res) => {
  const rows = await query('SELECT id,name,phone,login_id,role,created_at FROM users');
  res.json(rows);
}));
app.post('/api/users', requireAuth, requireRole(['admin']), asyncHandler(async (req, res) => {
  const { name, phone, login_id, role, password } = req.body;
  const hash = bcrypt.hashSync(password || 'changeme', 10);
  const r = await query('INSERT INTO users (name,phone,login_id,role,password) VALUES (?,?,?,?,?)', [name,phone,login_id,role,hash]);
  res.json({ id: r.insertId });
}));
app.put('/api/users/:id', requireAuth, requireRole(['admin']), asyncHandler(async (req, res) => {
  const id = req.params.id;
  const { name, phone, login_id, role, password } = req.body;
  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    await query('UPDATE users SET name=?,phone=?,login_id=?,role=?,password=? WHERE id=?', [name,phone,login_id,role,hash,id]);
  } else {
    await query('UPDATE users SET name=?,phone=?,login_id=?,role=? WHERE id=?', [name,phone,login_id,role,id]);
  }
  res.json({ ok: true });
}));
app.delete('/api/users/:id', requireAuth, requireRole(['admin']), asyncHandler(async (req, res) => {
  await query('DELETE FROM users WHERE id=?', [req.params.id]);
  res.json({ ok: true });
}));

/* Roles */
app.get('/api/roles', requireAuth, asyncHandler(async (req, res) => {
  const rows = await query('SELECT * FROM roles');
  res.json(rows);
}));
app.post('/api/roles', requireAuth, requireRole(['chefe']), asyncHandler(async (req, res) => {
  const { name, weekly_target, monthly_target } = req.body;
  const r = await query('INSERT INTO roles (name,weekly_target,monthly_target,created_by) VALUES (?,?,?,?)', [name, weekly_target||0, monthly_target||0, req.session.user.id]);
  res.json({ id: r.insertId });
}));
app.put('/api/roles/:id', requireAuth, requireRole(['chefe']), asyncHandler(async (req, res) => {
  const { name, weekly_target, monthly_target } = req.body;
  await query('UPDATE roles SET name=?,weekly_target=?,monthly_target=? WHERE id=?', [name, weekly_target||0, monthly_target||0, req.params.id]);
  res.json({ ok: true });
}));
app.delete('/api/roles/:id', requireAuth, requireRole(['chefe']), asyncHandler(async (req, res) => {
  await query('DELETE FROM roles WHERE id=?', [req.params.id]);
  res.json({ ok: true });
}));

/* Members */
app.get('/api/members', requireAuth, asyncHandler(async (req, res) => {
  const rows = await query(`SELECT m.id,m.name,m.total_contribution,m.role_id,r.name as role_name 
    FROM members m LEFT JOIN roles r ON m.role_id=r.id`);
  res.json(rows);
}));
app.post('/api/members', requireAuth, requireRole(['chefe','subchefe','user']), asyncHandler(async (req, res) => {
  const { name, role_id } = req.body;
  const r = await query('INSERT INTO members (name,role_id) VALUES (?,?)', [name, role_id || null]);
  res.json({ id: r.insertId });
}));
app.put('/api/members/:id', requireAuth, requireRole(['chefe','subchefe','user']), asyncHandler(async (req, res) => {
  const { name, role_id } = req.body;
  await query('UPDATE members SET name=?, role_id=? WHERE id=?', [name, role_id || null, req.params.id]);
  res.json({ ok: true });
}));
app.delete('/api/members/:id', requireAuth, requireRole(['chefe','subchefe','user']), asyncHandler(async (req, res) => {
  await query('DELETE FROM members WHERE id=?', [req.params.id]);
  res.json({ ok: true });
}));

/* Contributions */
app.get('/api/contributions', requireAuth, asyncHandler(async (req, res) => {
  const rows = await query('SELECT c.*, u.name as user_name, m.name as member_name FROM contributions c LEFT JOIN users u ON c.user_id=u.id LEFT JOIN members m ON c.member_id=m.id ORDER BY c.created_at DESC');
  res.json(rows);
}));
app.post('/api/contributions', requireAuth, requireRole(['chefe','subchefe','user']), asyncHandler(async (req, res) => {
  const { member_id, amount, note } = req.body;
  const parsedAmount = parseFloat(amount);
  if (!member_id || Number.isNaN(parsedAmount) || parsedAmount <= 0) {
    return res.status(400).json({ error: 'member_id e amount válidos são obrigatórios' });
  }
  const user_id = req.session.user.id;
  const r = await query('INSERT INTO contributions (member_id,user_id,amount,note) VALUES (?,?,?,?)', [member_id, user_id, parsedAmount, note || null]);
  await query('UPDATE members SET total_contribution = COALESCE(total_contribution,0) + ? WHERE id=?', [parsedAmount, member_id]);
  res.json({ id: r.insertId });
}));

/* Dashboard */
app.get('/api/dashboard/targets', requireAuth, asyncHandler(async (req, res) => {
  const roles = await query('SELECT id,name,weekly_target,monthly_target FROM roles');
  const totals = await query(`SELECT r.id as role_id, SUM(m.total_contribution) as total FROM members m JOIN roles r ON m.role_id=r.id GROUP BY r.id`);
  const mapTotals = {};
  totals.forEach(t => mapTotals[t.role_id] = t.total || 0);
  const out = roles.map(r => ({ ...r, total: mapTotals[r.id] || 0 }));
  res.json(out);
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Erro no servidor' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port', PORT));
