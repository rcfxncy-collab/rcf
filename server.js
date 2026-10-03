// RCF shop server: static pages + login + MongoDB storage. Secrets come from environment variables only.
try { require('fs').readFileSync('.env', 'utf8').split(/\r?\n/).forEach(l => { const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2]; }); } catch (e) {}
const express = require('express');
const compression = require('compression');
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
// make async route errors return JSON instead of crashing the server
['get', 'post', 'put'].forEach(m => { const orig = app[m].bind(app); app[m] = (path, ...hs) => orig(path, ...hs.map(f => (typeof f === 'function' && f.constructor.name === 'AsyncFunction') ? (req, res, next) => f(req, res, next).catch(next) : f)); });
app.use(compression());
app.use(express.json({ limit: '15mb' }));

let shop, auth, billsCol, meta, dbh;
const STORAGE_LIMIT_MB = Number(process.env.STORAGE_LIMIT_MB) || 512;
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

async function loadMain() {
  const doc = await shop.findOne({ _id: 'main' });
  return doc ? JSON.parse(doc.json) : {};
}
const normPhone = x => String(x || '').replace(/\D/g, '').slice(-10);
const normInv = x => { const t = String(x || '').trim(); return /^\d+$/.test(t) ? String(parseInt(t, 10)) : t; };
const fieldsOf = b => ({ n: normInv(b.invoiceNumber), p: normPhone(b.customerPhone) });
const requireManager = (req, res, next) => req.sess.role === 'manager' ? next() : res.status(403).json({ error: 'Manager only' });
async function getVer() { const m = await meta.findOne({ _id: 'ver' }); return m ? m.v : 0; }
async function bump() {
  const now = Date.now();
  const r = await meta.findOneAndUpdate({ _id: 'ver' }, [{ $set: { v: { $max: [{ $add: [{ $ifNull: ['$v', 0] }, 1] }, now] } } }], { upsert: true, returnDocument: 'after' });
  return r.v;
}
async function snapshot(since) {
  const updatedAt = await getVer();
  const data = await loadMain();
  const q = since ? { u: { $gt: since } } : { deleted: { $ne: true } };
  const rows = await billsCol.find(q).project({ json: 1, deleted: 1 }).toArray();
  return { updatedAt, data, bills: rows.map(b => ({ id: b._id, json: b.json, deleted: !!b.deleted })) };
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
  const data = await loadMain();
  res.json({ shopName: (data.shopName && data.shopName !== 'My Shop') ? data.shopName : SHOP_NAME });
});

app.post('/api/login', async (req, res) => {
  if (limited(req, res)) return;
  const { role, user = '', pass = '' } = req.body || {};
  const snap = await snapshot(0);
  const data = snap.data;
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
  res.json({ ok: true, role: who, name, data: withEnv(snap.data), bills: snap.bills, updatedAt: snap.updatedAt });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'rcf_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/data', requireAuth, async (req, res) => {
  const since = Number(req.query.since) || 0;
  if (since && since === await getVer()) return res.json({ changed: false, updatedAt: since });
  const snap = await snapshot(since);
  res.json({ changed: true, updatedAt: snap.updatedAt, data: withEnv(snap.data), bills: snap.bills });
});

app.put('/api/data', requireAuth, async (req, res) => {
  const { data, bills = [], deleted = [] } = req.body || {};
  if (data && (typeof data !== 'object' || Array.isArray(data))) return res.status(400).json({ error: 'Bad data' });
  const v = await bump();
  if (data) {
    delete data.managerPassword; delete data.recoveryPin; delete data.bills;
    await shop.updateOne({ _id: 'main' }, { $set: { json: JSON.stringify(data) } }, { upsert: true });
  }
  const ops = [];
  for (const b of bills) if (b && b.id) ops.push({ updateOne: { filter: { _id: String(b.id) }, update: { $set: { json: JSON.stringify(b), u: v, deleted: false, ...fieldsOf(b) } }, upsert: true } });
  for (const id of deleted) ops.push({ updateOne: { filter: { _id: String(id) }, update: { $set: { json: '', u: v, deleted: true } }, upsert: true } });
  if (ops.length) await billsCol.bulkWrite(ops, { ordered: false });
  res.json({ ok: true, updatedAt: v });
});

let stCache = { t: 0, used: 0 };
app.get('/api/storage', requireAuth, requireManager, async (req, res) => {
  if (Date.now() - stCache.t > 30000) { const st = await dbh.command({ dbStats: 1 }); stCache = { t: Date.now(), used: (st.dataSize || 0) + (st.indexSize || 0) }; }
  res.json({ usedBytes: stCache.used, limitBytes: STORAGE_LIMIT_MB * 1048576 });
});

// ---- public bill check (customer enters mobile + bill no + captcha) ----
const usedCaptcha = new Set();
setInterval(() => usedCaptcha.clear(), 10 * 60e3);
const capHash = (ans, exp) => crypto.createHmac('sha256', SESSION_SECRET).update('cap:' + ans + ':' + exp).digest('hex');
app.get('/api/captcha', (req, res) => {
  let ans = ''; for (let i = 0; i < 4; i++) ans += String(crypto.randomInt(10));
  const rnd = (a, b) => a + crypto.randomInt(Math.round((b - a) * 10)) / 10;
  let g = '';
  for (let i = 0; i < 4; i++) g += `<text x="${22 + i * 34}" y="${rnd(34, 42)}" font-size="${rnd(28, 34)}" font-weight="700" font-style="italic" font-family="Arial,sans-serif" fill="hsl(${210 + crypto.randomInt(30)},60%,${22 + crypto.randomInt(14)}%)" transform="rotate(${rnd(-16, 16)} ${34 + i * 34} 30)">${ans[i]}</text>`;
  for (let i = 0; i < 5; i++) g += `<line x1="${rnd(0, 160)}" y1="${rnd(0, 54)}" x2="${rnd(0, 160)}" y2="${rnd(0, 54)}" stroke="hsl(${200 + crypto.randomInt(40)},45%,65%)" stroke-width="1.4"/>`;
  const exp = Date.now() + 5 * 60e3;
  res.set('Cache-Control', 'no-store');
  res.json({ token: exp + '.' + capHash(ans, exp), svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 54" width="160" height="54"><rect width="160" height="54" rx="8" fill="#edf4fc"/>${g}</svg>` });
});
const lookHits = new Map();
app.post('/api/bill-lookup', async (req, res) => {
  const now = Date.now(), a = (lookHits.get(req.ip) || []).filter(t => now - t < 10 * 60e3);
  if (a.length >= 20) return res.status(429).json({ error: 'Too many tries. Please wait a few minutes.' });
  a.push(now); lookHits.set(req.ip, a);
  const { mobile, billNo, captchaToken = '', captchaAnswer = '' } = req.body || {};
  const [exp, sig] = String(captchaToken).split('.');
  const ok = exp && sig && Number(exp) > now && !usedCaptcha.has(captchaToken) && safeEq(sig, capHash(String(captchaAnswer).trim().toUpperCase(), exp));
  if (!ok) return res.status(400).json({ error: 'Wrong captcha. Please try again.', captcha: true });
  usedCaptcha.add(captchaToken);
  const p = normPhone(mobile), n = normInv(billNo);
  if (p.length < 10 || !n) return res.status(400).json({ error: 'Enter a valid 10 digit mobile number and bill number.' });
  const doc = await billsCol.findOne({ n, p, deleted: { $ne: true } });
  if (!doc) return res.status(404).json({ error: 'No bill found for this mobile number and bill number.' });
  const b = JSON.parse(doc.json), main = await loadMain();
  res.json({ ok: true,
    shop: { name: (main.shopName && main.shopName !== 'My Shop') ? main.shopName : SHOP_NAME, address: main.address || '', mobile: main.mobile || '' },
    bill: { invoiceNumber: b.invoiceNumber, date: b.date, customerName: b.customerName, customerPhone: b.customerPhone,
      items: (b.items || []).map(i => ({ name: i.name, variantName: i.variantName || '', qty: i.qty, price: i.price, gstRate: i.gstRate || 0 })),
      subtotal: b.subtotal, gst: b.gst, discountAmt: b.discountAmt || 0, additionalCharges: b.additionalCharges || 0, roundOffAmt: b.roundOffAmt || 0,
      total: b.total, paid: b.paid, due: b.due, notes: b.notes || '' } });
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

async function migrate() {
  // move bills that older versions stored inside the main document into their own collection
  const doc = await shop.findOne({ _id: 'main' });
  if (doc) {
    const d = JSON.parse(doc.json);
    if (Array.isArray(d.bills)) {
      const v = await bump();
      const ops = d.bills.filter(b => b && b.id).map(b => ({ updateOne: { filter: { _id: String(b.id) }, update: { $set: { json: JSON.stringify(b), u: v, deleted: false, ...fieldsOf(b) } }, upsert: true } }));
      for (let i = 0; i < ops.length; i += 1000) await billsCol.bulkWrite(ops.slice(i, i + 1000), { ordered: false });
      delete d.bills;
      await shop.updateOne({ _id: 'main' }, { $set: { json: JSON.stringify(d) } });
      console.log('Migrated ' + ops.length + ' bills to their own collection');
    }
  }
  // add invoice-number / phone lookup fields to older bills (for the customer bill-check page)
  let ops = [];
  for await (const row of billsCol.find({ n: { $exists: false }, deleted: { $ne: true } }).project({ json: 1 })) {
    try { ops.push({ updateOne: { filter: { _id: row._id }, update: { $set: fieldsOf(JSON.parse(row.json)) } } }); } catch (e) {}
    if (ops.length >= 1000) { await billsCol.bulkWrite(ops, { ordered: false }); ops = []; }
  }
  if (ops.length) await billsCol.bulkWrite(ops, { ordered: false });
  await billsCol.createIndex({ u: 1 });
  await billsCol.createIndex({ n: 1, p: 1 });
  await billsCol.deleteMany({ deleted: true, u: { $lt: Date.now() - 30 * 86400e3 } });
}

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({ error: /quota|space/i.test(err.message) ? 'Database storage is full.' : 'Server error. Try again.' });
});

MongoClient.connect(MONGODB_URI).then(async client => {
  const db = client.db(); dbh = db;
  shop = db.collection('shop'); auth = db.collection('auth'); billsCol = db.collection('bills'); meta = db.collection('meta');
  await migrate();
  app.listen(process.env.PORT || 3000, () => console.log('RCF server running'));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
