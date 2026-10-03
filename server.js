// RCF shop server: static pages + login + MongoDB storage. Secrets come from environment variables only.
try { require('fs').readFileSync('.env', 'utf8').split(/\r?\n/).forEach(l => { const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2]; }); } catch (e) {}
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { MongoClient } = require('mongodb');

const { MONGODB_URI, SESSION_SECRET } = process.env;
const SHOP_NAME = process.env.SHOP_NAME || 'My Shop';
const MANAGER_NAME = process.env.MANAGER_NAME || 'Manager';
const MANAGER_USERNAME = process.env.MANAGER_USERNAME;
const MANAGER_PASSWORD = process.env.MANAGER_PASSWORD;
const RECOVERY_PIN = process.env.RECOVERY_PIN;
if (!MONGODB_URI || !SESSION_SECRET || !MANAGER_USERNAME || !MANAGER_PASSWORD) {
  console.error('Missing env vars: MONGODB_URI, SESSION_SECRET, MANAGER_USERNAME, MANAGER_PASSWORD are required.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '15mb' }));

let shop, auth;
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(pw, salt, 32).toString('hex') });

// ---- signed session cookie ----
const sign = p => crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('base64url');
function makeToken(sess) { const p = Buffer.from(JSON.stringify({ ...sess, exp: Date.now() + 12 * 3600e3 })).toString('base64url'); return p + '.' + sign(p); }
function readToken(req) {
  const c = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('rcf_session='));
  if (!c) return null;
  const [p, sig] = c.slice(12).split('.');
  if (!p || !sig || !safeEq(sig, sign(p))) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; } catch (e) { return null; }
}
const requireAuth = (req, res, next) => { const s = readToken(req); if (!s) return res.status(401).json({ error: 'Not logged in' }); req.sess = s; next(); };

// ---- simple rate limit on login/recover ----
const hits = new Map();
function limited(req, res) {
  const k = req.ip, now = Date.now();
  const a = (hits.get(k) || []).filter(t => now - t < 5 * 60e3);
  if (a.length >= 10) { res.status(429).json({ error: 'Too many attempts. Try again in 5 minutes.' }); return true; }
  a.push(now); hits.set(k, a); return false;
}

async function loadData() {
  const doc = await shop.findOne({ _id: 'main' });
  return { data: doc ? JSON.parse(doc.json) : {}, updatedAt: doc ? doc.updatedAt : 0 };
}
function withEnv(d) {
  d.managerUsername = MANAGER_USERNAME; d.managerName = MANAGER_NAME; d.managerPassword = ''; d.recoveryPin = '';
  if (!d.shopName || d.shopName === 'My Shop') d.shopName = SHOP_NAME;
  return d;
}
async function managerPasswordOk(pass) {
  const o = await auth.findOne({ _id: 'manager' });
  if (o) return safeEq(crypto.scryptSync(pass, o.salt, 32).toString('hex'), o.hash);
  return safeEq(pass, MANAGER_PASSWORD);
}

app.get('/api/public', async (req, res) => {
  const { data } = await loadData();
  res.json({ shopName: (data.shopName && data.shopName !== 'My Shop') ? data.shopName : SHOP_NAME });
});

app.post('/api/login', async (req, res) => {
  if (limited(req, res)) return;
  const { role, user = '', pass = '' } = req.body || {};
  const { data, updatedAt } = await loadData();
  let name = null, who = null;
  if (role === 'manager') {
    if (safeEq(user, MANAGER_USERNAME) && await managerPasswordOk(pass)) name = MANAGER_NAME;
    else { const m = (data.managers || []).find(x => x.username === user && x.password === pass); if (m) name = m.name; }
    who = 'manager';
  } else if (role === 'cashier') {
    const c = (data.cashiers || []).find(x => x.username === user && x.password === pass);
    if (c && c.blocked) return res.status(403).json({ error: 'This account has been temporarily blocked by the manager.' });
    if (c) name = c.name;
    who = 'cashier';
  }
  if (!name) return res.status(401).json({ error: 'Wrong ' + (role === 'cashier' ? 'cashier' : 'manager') + ' username or password' });
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `rcf_session=${makeToken({ role: who, user, name })}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${12 * 3600}${secure}`);
  res.json({ ok: true, role: who, name, data: withEnv(data), updatedAt });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'rcf_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/data', requireAuth, async (req, res) => {
  const { data, updatedAt } = await loadData();
  if (Number(req.query.since) === updatedAt) return res.json({ changed: false, updatedAt });
  res.json({ changed: true, updatedAt, data: withEnv(data) });
});

app.put('/api/data', requireAuth, async (req, res) => {
  const d = req.body;
  if (!d || typeof d !== 'object' || Array.isArray(d)) return res.status(400).json({ error: 'Bad data' });
  delete d.managerPassword; delete d.recoveryPin;
  const updatedAt = Date.now();
  await shop.updateOne({ _id: 'main' }, { $set: { json: JSON.stringify(d), updatedAt } }, { upsert: true });
  res.json({ ok: true, updatedAt });
});

app.post('/api/recover', async (req, res) => {
  if (limited(req, res)) return;
  const { user = '', pin = '', pass = '' } = req.body || {};
  if (!RECOVERY_PIN || !safeEq(user, MANAGER_USERNAME) || !safeEq(pin, RECOVERY_PIN)) return res.status(401).json({ error: 'Incorrect username or Recovery PIN.' });
  if (String(pass).length < 6) return res.status(400).json({ error: 'Password too short.' });
  const { salt, hash } = hashPw(pass);
  await auth.updateOne({ _id: 'manager' }, { $set: { salt, hash } }, { upsert: true });
  res.json({ ok: true });
});

// ---- static pages (explicit list so server.js / .env are never served) ----
const root = __dirname;
app.get('/', (q, r) => r.sendFile(path.join(root, 'index.html')));
['index', 'manager', 'checkbill'].forEach(n => app.get('/' + n + '.html', (q, r) => { r.set('Cache-Control', 'no-cache'); r.sendFile(path.join(root, n + '.html')); }));
app.use('/public', express.static(path.join(root, 'public')));

MongoClient.connect(MONGODB_URI).then(client => {
  const db = client.db();
  shop = db.collection('shop'); auth = db.collection('auth');
  app.listen(process.env.PORT || 3000, () => console.log('RCF server running'));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
