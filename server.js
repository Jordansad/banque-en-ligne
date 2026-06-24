const express = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const db       = require('./database');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'nf_jwt_secret_key_2024_change_in_prod';

app.use(express.json());
app.use(express.static(path.join(__dirname)));

/* ── Auth middleware ── */
function authAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    const d = jwt.verify(token, SECRET);
    if (d.role !== 'admin') return res.status(403).json({ error: 'Accès interdit' });
    req.admin = d;
    next();
  } catch { res.status(401).json({ error: 'Token invalide' }); }
}

function authClient(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    const d = jwt.verify(token, SECRET);
    if (d.role !== 'client') return res.status(403).json({ error: 'Accès interdit' });
    req.client = d;
    next();
  } catch { res.status(401).json({ error: 'Token invalide' }); }
}

function log(adminId, action, details) {
  db.prepare('INSERT INTO admin_logs (admin_id, action, details) VALUES (?,?,?)').run(adminId, action, details);
}

function notify(clientId, message, type = 'info') {
  db.prepare('INSERT INTO notifications (client_id, message, type) VALUES (?,?,?)').run(clientId, message, type);
}

/* ════════════════════════════════════════
   AUTH
════════════════════════════════════════ */
app.post('/api/auth/admin/login', (req, res) => {
  const { email, password } = req.body;
  const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(email);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: admin.id, email: admin.email, name: admin.name, role: 'admin' }, SECRET, { expiresIn: '8h' });
  log(admin.id, 'LOGIN', 'Connexion réussie');
  res.json({ token, admin: { id: admin.id, email: admin.email, name: admin.name } });
});

app.post('/api/auth/client/login', (req, res) => {
  const { email, password } = req.body;
  const client = db.prepare('SELECT * FROM clients WHERE email = ?').get(email);
  if (!client || !bcrypt.compareSync(password, client.password_hash))
    return res.status(401).json({ error: 'Identifiants incorrects' });
  if (client.status !== 'active')
    return res.status(403).json({ error: 'Compte suspendu ou fermé. Contactez votre conseiller.' });
  const token = jwt.sign({ id: client.id, clientId: client.client_id, email: client.email, role: 'client' }, SECRET, { expiresIn: '8h' });
  res.json({ token, client: { id: client.id, clientId: client.client_id, nom: client.nom, prenom: client.prenom, email: client.email } });
});

/* ════════════════════════════════════════
   PUBLIC
════════════════════════════════════════ */
app.post('/api/requests', (req, res) => {
  const { nom, prenom, email, telephone, montant, duree, type_pret, revenus, situation } = req.body;
  if (!nom || !prenom || !email) return res.status(400).json({ error: 'Champs requis manquants' });
  const r = db.prepare(
    'INSERT INTO requests (nom,prenom,email,telephone,montant,duree,type_pret,revenus,situation) VALUES (?,?,?,?,?,?,?,?,?)'
  ).run(nom, prenom, email, telephone, montant, duree, type_pret, revenus, situation);
  res.json({ success: true, id: r.lastInsertRowid });
});

/* ════════════════════════════════════════
   ADMIN — Dashboard
════════════════════════════════════════ */
app.get('/api/admin/stats', authAdmin, (req, res) => {
  const g = (q, ...p) => db.prepare(q).get(...p);
  res.json({
    totalRequests:   g("SELECT COUNT(*) n FROM requests").n,
    pendingRequests: g("SELECT COUNT(*) n FROM requests WHERE status='pending'").n,
    totalClients:    g("SELECT COUNT(*) n FROM clients").n,
    activeClients:   g("SELECT COUNT(*) n FROM clients WHERE status='active'").n,
    totalBalance:    g("SELECT COALESCE(SUM(balance),0) s FROM clients").s,
    todayRequests:   g("SELECT COUNT(*) n FROM requests WHERE DATE(created_at)=DATE('now')").n,
  });
});

/* ════════════════════════════════════════
   ADMIN — Requests
════════════════════════════════════════ */
app.get('/api/admin/requests', authAdmin, (req, res) => {
  const { status, page = 1, limit = 50 } = req.query;
  let q = 'SELECT * FROM requests', p = [];
  if (status) { q += ' WHERE status=?'; p.push(status); }
  q += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  p.push(+limit, (+page - 1) * +limit);
  const total = db.prepare('SELECT COUNT(*) n FROM requests' + (status ? ' WHERE status=?' : '')).get(...(status ? [status] : [])).n;
  res.json({ requests: db.prepare(q).all(...p), total });
});

app.put('/api/admin/requests/:id', authAdmin, (req, res) => {
  const { status, notes } = req.body;
  db.prepare('UPDATE requests SET status=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status, notes, req.params.id);
  log(req.admin.id, 'UPDATE_REQUEST', `Demande #${req.params.id} → ${status}`);
  res.json({ success: true });
});

/* ════════════════════════════════════════
   ADMIN — Clients
════════════════════════════════════════ */
app.get('/api/admin/clients', authAdmin, (req, res) => {
  const { status, search, page = 1, limit = 50 } = req.query;
  let where = [], p = [];
  if (status) { where.push('status=?'); p.push(status); }
  if (search)  { where.push('(nom LIKE ? OR prenom LIKE ? OR email LIKE ? OR client_id LIKE ?)'); p.push(...Array(4).fill(`%${search}%`)); }
  let q = 'SELECT id,client_id,nom,prenom,email,telephone,balance,status,created_at FROM clients';
  if (where.length) q += ' WHERE ' + where.join(' AND ');
  q += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  p.push(+limit, (+page - 1) * +limit);
  res.json({ clients: db.prepare(q).all(...p) });
});

app.get('/api/admin/clients/:id', authAdmin, (req, res) => {
  const c = db.prepare('SELECT * FROM clients WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Introuvable' });
  delete c.password_hash;
  const transactions = db.prepare('SELECT t.*,a.name admin_name FROM transactions t LEFT JOIN admins a ON t.admin_id=a.id WHERE t.client_id=? ORDER BY t.created_at DESC').all(c.id);
  res.json({ client: c, transactions });
});

app.post('/api/admin/clients', authAdmin, (req, res) => {
  const { nom, prenom, email, telephone, situation, revenus, request_id } = req.body;
  const clientId  = 'NF-' + String(Date.now()).slice(-7);
  const tempPwd   = Math.random().toString(36).slice(-8).toUpperCase();
  const hash      = bcrypt.hashSync(tempPwd, 10);
  try {
    const r = db.prepare(
      'INSERT INTO clients (client_id,nom,prenom,email,telephone,situation,revenus,password_hash,temp_password,request_id) VALUES (?,?,?,?,?,?,?,?,?,?)'
    ).run(clientId, nom, prenom, email, telephone, situation, revenus || 0, hash, tempPwd, request_id || null);
    if (request_id) db.prepare("UPDATE requests SET status='processed',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(request_id);
    notify(r.lastInsertRowid, `Bienvenue ${prenom} ${nom} ! Votre compte Nationalfinance a été créé avec succès.`, 'success');
    log(req.admin.id, 'CREATE_CLIENT', `Compte ${clientId} créé pour ${prenom} ${nom}`);
    res.json({ success: true, clientId, tempPassword: tempPwd, id: r.lastInsertRowid });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Email déjà utilisé' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/admin/clients/:id', authAdmin, (req, res) => {
  const { nom, prenom, email, telephone, situation, revenus, status } = req.body;
  db.prepare('UPDATE clients SET nom=?,prenom=?,email=?,telephone=?,situation=?,revenus=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .run(nom, prenom, email, telephone, situation, revenus, status, req.params.id);
  const c = db.prepare('SELECT id FROM clients WHERE id=?').get(req.params.id);
  if (c) notify(c.id, 'Vos informations ont été mises à jour par votre conseiller.', 'info');
  log(req.admin.id, 'UPDATE_CLIENT', `Client #${req.params.id} modifié`);
  res.json({ success: true });
});

app.post('/api/admin/clients/:id/credit', authAdmin, (req, res) => {
  const { amount, description } = req.body;
  const c = db.prepare('SELECT * FROM clients WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Introuvable' });
  const amt = parseFloat(amount);
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Montant invalide' });
  const newBal = parseFloat((c.balance + amt).toFixed(2));
  db.prepare('UPDATE clients SET balance=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(newBal, c.id);
  db.prepare('INSERT INTO transactions (client_id,type,amount,balance_after,description,admin_id) VALUES (?,?,?,?,?,?)').run(c.id, 'credit', amt, newBal, description, req.admin.id);
  notify(c.id, `✅ Crédit de ${amt.toFixed(2)} € — Motif : ${description || 'Non précisé'} — Solde : ${newBal.toFixed(2)} €`, 'success');
  log(req.admin.id, 'CREDIT', `${c.client_id} +${amt}€ (${description})`);
  res.json({ success: true, newBalance: newBal });
});

app.post('/api/admin/clients/:id/debit', authAdmin, (req, res) => {
  const { amount, description } = req.body;
  const c = db.prepare('SELECT * FROM clients WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Introuvable' });
  const amt = parseFloat(amount);
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Montant invalide' });
  if (c.balance < amt) return res.status(400).json({ error: 'Solde insuffisant' });
  const newBal = parseFloat((c.balance - amt).toFixed(2));
  db.prepare('UPDATE clients SET balance=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(newBal, c.id);
  db.prepare('INSERT INTO transactions (client_id,type,amount,balance_after,description,admin_id) VALUES (?,?,?,?,?,?)').run(c.id, 'debit', amt, newBal, description, req.admin.id);
  notify(c.id, `⬇️ Débit de ${amt.toFixed(2)} € — Motif : ${description || 'Non précisé'} — Solde : ${newBal.toFixed(2)} €`, 'warning');
  log(req.admin.id, 'DEBIT', `${c.client_id} -${amt}€ (${description})`);
  res.json({ success: true, newBalance: newBal });
});

app.get('/api/admin/logs', authAdmin, (req, res) => {
  const logs = db.prepare('SELECT l.*,a.name admin_name FROM admin_logs l LEFT JOIN admins a ON l.admin_id=a.id ORDER BY l.created_at DESC LIMIT 200').all();
  res.json({ logs });
});

/* ════════════════════════════════════════
   CLIENT
════════════════════════════════════════ */
app.get('/api/client/profile', authClient, (req, res) => {
  const c = db.prepare('SELECT id,client_id,nom,prenom,email,telephone,situation,revenus,balance,status,created_at FROM clients WHERE id=?').get(req.client.id);
  if (!c) return res.status(404).json({ error: 'Introuvable' });
  res.json({ client: c });
});

app.put('/api/client/profile', authClient, (req, res) => {
  const { telephone } = req.body;
  db.prepare('UPDATE clients SET telephone=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(telephone, req.client.id);
  res.json({ success: true });
});

app.get('/api/client/transactions', authClient, (req, res) => {
  const rows = db.prepare('SELECT id,type,amount,balance_after,description,created_at FROM transactions WHERE client_id=? ORDER BY created_at DESC').all(req.client.id);
  res.json({ transactions: rows });
});

app.get('/api/client/notifications', authClient, (req, res) => {
  const rows = db.prepare('SELECT * FROM notifications WHERE client_id=? ORDER BY created_at DESC').all(req.client.id);
  const unread = db.prepare('SELECT COUNT(*) n FROM notifications WHERE client_id=? AND read=0').get(req.client.id).n;
  db.prepare('UPDATE notifications SET read=1 WHERE client_id=?').run(req.client.id);
  res.json({ notifications: rows, unread });
});

app.put('/api/client/password', authClient, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const c = db.prepare('SELECT * FROM clients WHERE id=?').get(req.client.id);
  if (!bcrypt.compareSync(currentPassword, c.password_hash))
    return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Mot de passe trop court (6 caractères min.)' });
  db.prepare('UPDATE clients SET password_hash=?,temp_password=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(bcrypt.hashSync(newPassword, 10), req.client.id);
  res.json({ success: true });
});

/* ════════════════════════════════════════
   START
════════════════════════════════════════ */
app.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════╗');
  console.log('║   Nationalfinance — Serveur démarré  ║');
  console.log('╚══════════════════════════════════════╝');
  console.log(`\n🌐 Site public  : http://localhost:${PORT}`);
  console.log(`📊 Admin        : http://localhost:${PORT}/admin.html`);
  console.log(`👤 Espace client: http://localhost:${PORT}/client.html`);
  console.log('\n🔐 Admin par défaut:');
  console.log('   Email : admin@nationalfinance.fr');
  console.log('   Mdp   : Admin@2024\n');
});
