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
['get', 'post', 'put', 'delete'].forEach(m => { const orig = app[m].bind(app); app[m] = (path, ...hs) => orig(path, ...hs.map(f => (typeof f === 'function' && f.constructor.name === 'AsyncFunction') ? (req, res, next) => f(req, res, next).catch(next) : f)); });
app.use(compression());
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }); next(); });
app.use(express.json({ limit: '15mb' }));

let shop, auth, billsCol, meta, dbh, wpCol, cmCol, offersCol;
const STORAGE_LIMIT_MB = Number(process.env.STORAGE_LIMIT_MB) || 512;
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(pw, salt, 32).toString('hex') });

// ---- names/notes can never carry HTML: strip the characters that break out of HTML text or attributes ----
const SAFE_CH = { '<': '\uFF1C', '>': '\uFF1E', '"': '\u201D', "'": '\u2019', '`': '\u02CB' };
const cleanStr = s => /^data:image\//.test(s) ? s : s.replace(/[<>"'`]/g, c => SAFE_CH[c]);
function sanitizeDeep(v, depth = 0) {
  if (depth > 14) return null;
  if (typeof v === 'string') return cleanStr(v);
  if (Array.isArray(v)) return v.map(x => sanitizeDeep(x, depth + 1));
  if (v && typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v)) { if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue; o[cleanStr(k)] = sanitizeDeep(v[k], depth + 1); }
    return o;
  }
  return v;
}
const num = x => Number(x) || 0;
const isObj = o => !!o && typeof o === 'object' && !Array.isArray(o);
const strongPw = pw => typeof pw === 'string' && pw.length >= 6 && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
const PW_HINT = 'Password must be at least 6 characters and include both letters and numbers.';

// staff passwords are stored hashed (salted scrypt) in the auth collection, never in the shop data
const credId = id => 'cred:' + id;
async function setCred(id, pw) { const { salt, hash } = hashPw(String(pw)); await auth.updateOne({ _id: credId(id) }, { $set: { salt, hash } }, { upsert: true }); }
async function checkCred(id, pw) {
  const o = await auth.findOne({ _id: credId(id) });
  if (!o) return false;
  return safeEq(crypto.scryptSync(String(pw), o.salt, 32).toString('hex'), o.hash);
}

// one writer at a time, so two devices saving together are merged instead of overwriting each other
let _lock = Promise.resolve();
const withLock = fn => { const p = _lock.then(fn, fn); _lock = p.catch(() => {}); return p; };

// ---- merge engine: a device sends only what it changed; the server applies it to the CURRENT data ----
const NEVER_SET = new Set(['bills', 'managerPassword', 'recoveryPin', 'managerUsername', 'managerName', 'cashiers', 'managers']);
const CASHIER_SET = new Set(['lastInvoiceNo', 'theme']);
const CASHIER_ARR = { products: false, customers: false, heldBills: true, returns: false, wastageLog: false, messages: false }; // value = may remove
const DELTA_FIELDS = { products: ['stock', 'stockOther'], customers: ['dueAmount'] };
function mergeRecord(k, e, i, d) {
  const fields = DELTA_FIELDS[k];
  if (!fields) return i;
  d = isObj(d) ? sanitizeDeep(d) : {};
  const m = { ...i };
  for (const f of fields) {
    if (!(f in i) && !(f in e)) continue;
    m[f] = f in d ? Math.max(0, num(e[f]) + num(d[f])) : (f in e ? e[f] : i[f]);
  }
  if (k === 'products' && isObj(i.variantStock)) {
    const ev = isObj(e.variantStock) ? e.variantStock : {}, dv = isObj(d.variantStock) ? d.variantStock : {}, out = {};
    for (const v of Object.keys(i.variantStock)) out[v] = v in dv ? Math.max(0, num(ev[v]) + num(dv[v])) : (v in ev ? ev[v] : i.variantStock[v]);
    m.variantStock = out;
    if (Array.isArray(m.variants) && m.variants.length && Object.keys(out).length) m.stock = Object.values(out).reduce((a, b) => a + num(b), 0) + num(m.stockOther);
  }
  return m;
}
function applyPatch(doc, patch, sess) {
  const isMgr = sess.role === 'manager';
  const creds = [];
  if (!isObj(patch)) return { error: 'Bad data', status: 400 };
  const set = isObj(patch.set) ? patch.set : {};
  for (const k of Object.keys(set)) {
    if (NEVER_SET.has(k) || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (!isMgr && !CASHIER_SET.has(k)) continue;
    doc[cleanStr(k)] = sanitizeDeep(set[k]);
  }
  const arr = isObj(patch.arr) ? patch.arr : {}, dl = isObj(patch.dl) ? patch.dl : {};
  for (const k of Object.keys(arr)) {
    const spec = arr[k];
    if (!isObj(spec) || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    const up = Array.isArray(spec.up) ? spec.up : [], rm = Array.isArray(spec.rm) ? spec.rm.map(String) : [];
    if (k === 'cashiers' || k === 'managers') {
      if (!isMgr) {                       // a cashier may only touch two harmless fields of their OWN entry
        if (k !== 'cashiers') continue;
        const me = (doc.cashiers || []).find(c => c && c.username === sess.user);
        const mine = me && up.find(x => isObj(x) && x.id === me.id);
        if (mine) { if ('lastActive' in mine) me.lastActive = num(mine.lastActive); if ('tutorialSeen' in mine) me.tutorialSeen = !!mine.tutorialSeen; }
        continue;
      }
      if (!Array.isArray(doc[k])) doc[k] = [];
      for (const raw of up) {
        if (!isObj(raw) || typeof raw.id !== 'string') continue;
        const pw = typeof raw.password === 'string' ? raw.password : '';
        if (pw && !strongPw(pw)) return { error: PW_HINT, status: 400 };
        const item = sanitizeDeep(raw); delete item.password;
        const taken = [MANAGER_USERNAME, ...(doc.cashiers || []).map(c => c && c.id !== item.id && c.username), ...(doc.managers || []).map(c => c && c.id !== item.id && c.username)];
        if (item.username && taken.includes(item.username)) return { error: 'Username already taken', status: 400 };
        const idx = doc[k].findIndex(x => x && x.id === item.id);
        if (idx >= 0) doc[k][idx] = item; else doc[k].push(item);
        if (pw) creds.push({ set: [item.id, pw] });
      }
      if (rm.length) { const r = new Set(rm); doc[k] = doc[k].filter(x => !(x && r.has(x.id))); rm.forEach(id => creds.push({ del: id })); }
      continue;
    }
    if (!isMgr && !(k in CASHIER_ARR)) continue;
    if (!Array.isArray(doc[k])) doc[k] = [];
    const list = doc[k], deltas = isObj(dl[k]) ? dl[k] : {};
    const index = new Map(); list.forEach((x, n) => { if (x && x.id) index.set(x.id, n); });
    for (const raw of up) {
      if (!isObj(raw) || typeof raw.id !== 'string') continue;
      const item = sanitizeDeep(raw), n = index.get(item.id);
      if (n === undefined) { index.set(item.id, list.length); list.push(item); }
      else list[n] = mergeRecord(k, list[n], item, deltas[raw.id]);
    }
    if (rm.length && (isMgr || CASHIER_ARR[k])) { const r = new Set(rm); doc[k] = list.filter(x => !(x && r.has(x.id))); }
  }
  return { creds };
}
const BILL_CORE = ['invoiceNumber', 'date', 'customerId', 'customerName', 'customerPhone', 'items', 'subtotal', 'gst', 'discountAmt', 'discountPct', 'additionalCharges', 'roundOffAmt', 'total', 'cashier'];

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

const failHits = new Map();
const loginBlocked = (req, res) => {
  const now = Date.now(), a = (failHits.get(req.ip) || []).filter(t => now - t < 5 * 60e3);
  failHits.set(req.ip, a);
  if (a.length >= 10) { res.status(429).json({ error: 'Too many wrong attempts. Try again in 5 minutes.' }); return true; }
  return false;
};
const noteLoginFail = req => { const a = failHits.get(req.ip) || []; a.push(Date.now()); failHits.set(req.ip, a); };
setInterval(() => { const now = Date.now(); for (const m of [hits, failHits, lookHits, msgHits]) for (const [k, a] of m) if (!a.some(t => now - t < 15 * 60e3)) m.delete(k); }, 10 * 60e3).unref();
const recFails = [];

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
  for (const k of ['cashiers', 'managers']) if (Array.isArray(d[k])) d[k].forEach(x => { if (x && typeof x === 'object') delete x.password; });
  d.managerUsername = MANAGER_USERNAME; d.managerName = MANAGER_NAME; d.managerPassword = ''; d.recoveryPin = '';
  if (!d.shopName || d.shopName === 'My Shop') d.shopName = SHOP_NAME;
  return d;
}
async function managerPasswordOk(pass) {
  pass = String(pass == null ? '' : pass);
  const o = await auth.findOne({ _id: 'manager' });
  if (o) return safeEq(crypto.scryptSync(pass, o.salt, 32).toString('hex'), o.hash);
  return safeEq(pass, MANAGER_PASSWORD);
}
const WEAK_PW = new Set(['qw1234', 'admin', 'admin123', 'password', '123456', '12345678', 'changeme']);
const WEAK_PIN = new Set(['2580', '1234', '0000', '1111', '123456', '000000', '111111']);
async function configWarnings() {
  const w = [], o = await auth.findOne({ _id: 'manager' });
  if (!o && WEAK_PW.has(MANAGER_PASSWORD)) w.push('The manager password is still a default/weak one. Change MANAGER_PASSWORD in your Render environment (or use Forgot Password).');
  if (!RECOVERY_PIN || WEAK_PIN.has(RECOVERY_PIN) || !/^\d{6,}$/.test(RECOVERY_PIN)) w.push('RECOVERY_PIN is missing or weak. Set a random PIN of 6+ digits in your Render environment.');
  if (String(SESSION_SECRET).length < 24) w.push('SESSION_SECRET is short. Use a long random string (32+ characters).');
  return w;
}

app.get('/api/public', async (req, res) => {
  const data = await loadMain();
  res.json({ shopName: (data.shopName && data.shopName !== 'My Shop') ? data.shopName : SHOP_NAME });
});

app.post('/api/login', async (req, res) => {
  if (loginBlocked(req, res)) return;
  const { role } = req.body || {};
  const user = String((req.body || {}).user || ''), pass = String((req.body || {}).pass || '');
  const snap = await snapshot(0);
  const data = snap.data;
  let name = null, who = null;
  if (role === 'manager') {
    if (safeEq(user, MANAGER_USERNAME) && await managerPasswordOk(pass)) name = MANAGER_NAME;
    else { const m = (data.managers || []).find(x => x && x.username === user); if (m && await checkCred(m.id, pass)) name = m.name; }
    who = 'manager';
  } else if (role === 'cashier') {
    const c = (data.cashiers || []).find(x => x && x.username === user);
    if (c && await checkCred(c.id, pass)) {
      if (c.blocked) return res.status(403).json({ error: 'This account has been temporarily blocked by the manager.' });
      name = c.name;
    }
    who = 'cashier';
  }
  if (!name) { noteLoginFail(req); return res.status(401).json({ error: 'Wrong ' + (role === 'cashier' ? 'cashier' : 'manager') + ' username or password' }); }
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `rcf_session=${makeToken({ role: who, user, name })}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${12 * 3600}${secure}`);
  res.json({ ok: true, role: who, name, data: withEnv(snap.data), bills: snap.bills, updatedAt: snap.updatedAt, warnings: who === 'manager' ? await configWarnings() : [] });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  if (limited(req, res)) return;
  const current = String((req.body || {}).current || ''), next = String((req.body || {}).next || '');
  if (!strongPw(next)) return res.status(400).json({ error: PW_HINT });
  const data = await loadMain(), bad = () => res.status(401).json({ error: 'Current password is incorrect.' });
  if (req.sess.role === 'manager' && safeEq(req.sess.user, MANAGER_USERNAME)) {
    if (!await managerPasswordOk(current)) return bad();
    const { salt, hash } = hashPw(next);
    await auth.updateOne({ _id: 'manager' }, { $set: { salt, hash } }, { upsert: true });
  } else {
    const list = req.sess.role === 'manager' ? data.managers : data.cashiers;
    const me = (list || []).find(x => x && x.username === req.sess.user);
    if (!me || !await checkCred(me.id, current)) return bad();
    await setCred(me.id, next);
  }
  res.json({ ok: true });
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
  const body = req.body || {};
  if (body.data !== undefined && body.data !== null) return res.status(409).json({ error: 'The app was updated. Please refresh this page (pull down or press F5).', reload: true });
  const patch = body.patch || null, isMgr = req.sess.role === 'manager', pid = typeof body.pid === 'string' ? body.pid.slice(0, 64) : '';
  const bills = Array.isArray(body.bills) ? body.bills : [], deleted = isMgr && Array.isArray(body.deleted) ? body.deleted : [];
  const out = await withLock(async () => {
    const cur = await getVer(), v = Math.max(cur + 1, Date.now());
    if (pid && await meta.findOne({ _id: 'pid:' + pid })) return { ok: true, updatedAt: cur, dup: true };   // this exact save already arrived (lost reply + retry): never apply twice
    let creds = [], wrote = false, rejected = 0;
    if (patch) {
      const doc = await loadMain();
      const r = applyPatch(doc, patch, req.sess);
      if (r.error) return r;
      await shop.updateOne({ _id: 'main' }, { $set: { json: JSON.stringify(doc) } }, { upsert: true });
      creds = r.creds; wrote = true;
    }
    for (const c of creds) { if (c.set) await setCred(c.set[0], c.set[1]); else if (c.del) await auth.deleteOne({ _id: credId(c.del) }); }
    const ops = [];
    let old = new Map();
    if (!isMgr && bills.length) {
      const rows = await billsCol.find({ _id: { $in: bills.filter(b => b && b.id).map(b => String(b.id)) }, deleted: { $ne: true } }).project({ json: 1 }).toArray();
      rows.forEach(r => { try { old.set(r._id, JSON.parse(r.json)); } catch (e) {} });
    }
    for (const raw of bills) {
      if (!raw || !raw.id) continue;
      const b = sanitizeDeep(raw), prev = old.get(String(b.id));
      if (!isMgr) {
        const pc = prev ? sanitizeDeep(prev) : null;
        if (prev && prev.cashier !== req.sess.name && !BILL_CORE.every(k => JSON.stringify(pc[k]) === JSON.stringify(b[k]))) { rejected++; continue; }  // other people's bills: payments only
        if (!prev) b.cashier = req.sess.name;
        else b.cashier = prev.cashier;
      }
      ops.push({ updateOne: { filter: { _id: String(b.id) }, update: { $set: { json: JSON.stringify(b), u: v, deleted: false, ...fieldsOf(b) } }, upsert: true } });
    }
    for (const id of deleted) ops.push({ updateOne: { filter: { _id: String(id) }, update: { $set: { json: '', u: v, deleted: true } }, upsert: true } });
    if (ops.length) { await billsCol.bulkWrite(ops, { ordered: false }); wrote = true; }
    if (pid) await meta.updateOne({ _id: 'pid:' + pid }, { $set: { at: Date.now() } }, { upsert: true });
    if (!wrote) return { ok: true, updatedAt: cur, rejected };
    await meta.updateOne({ _id: 'ver' }, { $set: { v } }, { upsert: true });   // version is published LAST, so nobody can read a half-written change
    return { ok: true, updatedAt: v, rejected };
  });
  if (out.error) return res.status(out.status || 400).json({ error: out.error });
  res.json(out);
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
      items: (b.items || []).map(i => ({ name: i.name, variantName: i.variantName || '', qty: Number(i.qty) || 0, price: Number(i.price) || 0, gstRate: i.gstRate || 0 })),
      subtotal: b.subtotal, gst: b.gst, discountAmt: b.discountAmt || 0, additionalCharges: b.additionalCharges || 0, roundOffAmt: b.roundOffAmt || 0,
      total: b.total, paid: b.paid, due: b.due, notes: b.notes || '' } });
});

app.post('/api/recover', async (req, res) => {
  if (limited(req, res)) return;
  const { user = '', pin = '', pass = '' } = req.body || {};
  const nowR = Date.now();
  while (recFails.length && nowR - recFails[0] > 3600e3) recFails.shift();
  if (recFails.length >= 8) return res.status(429).json({ error: 'Password recovery is locked for up to an hour after too many wrong attempts.' });
  if (!RECOVERY_PIN || !safeEq(user, MANAGER_USERNAME) || !safeEq(pin, RECOVERY_PIN)) { recFails.push(nowR); return res.status(401).json({ error: 'Incorrect username or Recovery PIN.' }); }
  if (!strongPw(String(pass))) return res.status(400).json({ error: PW_HINT });
  const { salt, hash } = hashPw(pass);
  await auth.updateOne({ _id: 'manager' }, { $set: { salt, hash } }, { upsert: true });
  res.json({ ok: true });
});


// ---- customer messages (sent from the website footer, read by the manager in Messenger) ----
const msgHits = new Map();
function msgLimited(req, res) {
  const k = req.ip, now = Date.now();
  const a = (msgHits.get(k) || []).filter(t => now - t < 10 * 60e3);
  if (a.length >= 5) { res.status(429).json({ error: 'Too many messages. Please try again in a few minutes.' }); return true; }
  a.push(now); msgHits.set(k, a); return false;
}
app.post('/api/customer-message', async (req, res) => {
  const name = String((req.body || {}).name || '').trim().slice(0, 60);
  const text = String((req.body || {}).text || '').trim().slice(0, 500);
  const phone = normPhone((req.body || {}).phone);
  if (!text) return res.status(400).json({ error: 'Please type your message.' });
  if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ error: 'Please enter a valid 10 digit mobile number so we can reply to you.' });
  if (msgLimited(req, res)) return;
  await cmCol.insertOne({ _id: crypto.randomUUID(), name: name || 'Customer', phone, text, date: new Date().toISOString(), read: false });
  res.json({ ok: true });
});
app.get('/api/customer-messages', requireAuth, requireManager, async (req, res) => {
  const rows = await cmCol.find({}).sort({ date: -1 }).limit(200).toArray();
  res.set('Cache-Control', 'no-store');
  res.json(rows.map(r => ({ id: r._id, name: r.name, phone: r.phone || '', text: r.text, date: r.date, read: !!r.read })));
});
app.post('/api/customer-messages/read', requireAuth, requireManager, async (req, res) => {
  await cmCol.updateMany({ read: { $ne: true } }, { $set: { read: true } });
  res.json({ ok: true });
});
app.delete('/api/customer-messages/:id', requireAuth, requireManager, async (req, res) => {
  await cmCol.deleteOne({ _id: req.params.id });
  res.json({ ok: true });
});

// ---- website offers (top banner on the website, managed by manager) ----
const todayIST = () => new Date(Date.now() + 5.5 * 3600e3).toISOString().slice(0, 10);
const offerLive = (o, t = todayIST()) => o.active !== false && (!o.expires || o.expires >= t);
app.get('/api/offers', async (req, res) => {
  const rows = await offersCol.find({}).sort({ createdAt: 1 }).toArray();
  res.set('Cache-Control', 'no-cache');
  res.json(rows.filter(o => offerLive(o)).map(o => ({ text: o.text })));
});
app.get('/api/offers/all', requireAuth, requireManager, async (req, res) => {
  const rows = await offersCol.find({}).sort({ createdAt: 1 }).toArray();
  const t = todayIST();
  res.set('Cache-Control', 'no-store');
  res.json(rows.map(o => ({ id: o._id, text: o.text, active: o.active !== false, expires: o.expires || '', live: offerLive(o, t) })));
});
app.post('/api/offers', requireAuth, requireManager, async (req, res) => {
  const text = String((req.body || {}).text || '').trim().slice(0, 140);
  const expires = /^\d{4}-\d{2}-\d{2}$/.test((req.body || {}).expires || '') ? req.body.expires : '';
  if (!text) return res.status(400).json({ error: 'Type the offer text.' });
  if (await offersCol.countDocuments({}) >= 10) return res.status(400).json({ error: 'Maximum 10 offers. Delete an old one first.' });
  await offersCol.insertOne({ _id: crypto.randomUUID(), text, expires, active: true, createdAt: Date.now() });
  res.json({ ok: true });
});
app.put('/api/offers/:id', requireAuth, requireManager, async (req, res) => {
  const set = {};
  if (typeof (req.body || {}).active === 'boolean') set.active = req.body.active;
  if (typeof (req.body || {}).text === 'string' && req.body.text.trim()) set.text = req.body.text.trim().slice(0, 140);
  if (typeof (req.body || {}).expires === 'string') set.expires = /^\d{4}-\d{2}-\d{2}$/.test(req.body.expires) ? req.body.expires : '';
  if (Object.keys(set).length) await offersCol.updateOne({ _id: req.params.id }, { $set: set });
  res.json({ ok: true });
});
app.delete('/api/offers/:id', requireAuth, requireManager, async (req, res) => {
  await offersCol.deleteOne({ _id: req.params.id });
  res.json({ ok: true });
});

// ---- website products (managed by manager, shown on product.html) ----
const wpClean = (b, old = {}) => {
  const name = String(b.name || '').trim().slice(0, 120);
  const description = String(b.description || '').trim().slice(0, 600);
  const price = Math.max(0, Number(b.price) || 0);
  const discount = Math.min(95, Math.max(0, Number(b.discount) || 0));
  const out = { name, description, price, discount };
  if (typeof b.image === 'string' && /^data:image\/(jpeg|png|webp);base64,/.test(b.image)) {
    if (b.image.length > 2.5e6) return { error: 'Image too large' };
    out.image = b.image; out.imgv = Date.now();
  }
  if (!name || !price) return { error: 'Product name and price are required' };
  if (!out.image && !old.image) return { error: 'Please choose a product image' };
  return { doc: out };
};
app.get('/api/web-products', async (req, res) => {
  const rows = await wpCol.find({}).project({ image: 0 }).sort({ createdAt: -1 }).toArray();
  res.set('Cache-Control', 'no-cache');
  res.json(rows.map(r => ({ id: r._id, name: r.name, description: r.description, price: r.price, discount: r.discount, imgv: r.imgv })));
});
app.get('/api/web-products/:id/image', async (req, res) => {
  const r = await wpCol.findOne({ _id: req.params.id }, { projection: { image: 1 } });
  const m = r && r.image && r.image.match(/^data:(image\/[a-z]+);base64,(.*)$/);
  if (!m) return res.status(404).end();
  res.set('Content-Type', m[1]); res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.send(Buffer.from(m[2], 'base64'));
});
app.post('/api/web-products', requireAuth, requireManager, async (req, res) => {
  const c = wpClean(req.body || {});
  if (c.error) return res.status(400).json({ error: c.error });
  const id = crypto.randomBytes(8).toString('hex');
  await wpCol.insertOne({ _id: id, ...c.doc, createdAt: Date.now() });
  res.json({ ok: true, id });
});
app.put('/api/web-products/:id', requireAuth, requireManager, async (req, res) => {
  const old = await wpCol.findOne({ _id: req.params.id });
  if (!old) return res.status(404).json({ error: 'Product not found' });
  const c = wpClean(req.body || {}, old);
  if (c.error) return res.status(400).json({ error: c.error });
  await wpCol.updateOne({ _id: old._id }, { $set: c.doc });
  res.json({ ok: true });
});
app.delete('/api/web-products/:id', requireAuth, requireManager, async (req, res) => {
  await wpCol.deleteOne({ _id: req.params.id });
  res.json({ ok: true });
});

// ---- static pages (explicit list so server.js / .env are never served) ----
const root = __dirname;
app.get('/', (q, r) => r.sendFile(path.join(root, 'index.html')));
['index', 'manager', 'checkbill', 'product'].forEach(n => app.get('/' + n + '.html', (q, r) => { r.set('Cache-Control', 'no-cache'); r.sendFile(path.join(root, n + '.html')); }));
app.use('/public', express.static(path.join(root, 'public')));

async function migrateSecrets() {
  const doc = await shop.findOne({ _id: 'main' });
  if (!doc) return;
  let d; try { d = JSON.parse(doc.json); } catch (e) { return; }
  let changed = false, n = 0;
  for (const k of ['cashiers', 'managers']) {
    if (!Array.isArray(d[k])) continue;
    for (const x of d[k]) {
      if (!x || typeof x !== 'object') continue;
      if (!x.id) { x.id = crypto.randomBytes(6).toString('hex'); changed = true; }
      if ('password' in x) {
        if (typeof x.password === 'string' && x.password && !await auth.findOne({ _id: credId(x.id) })) { await setCred(x.id, x.password); n++; }
        delete x.password; changed = true;
      }
    }
  }
  for (const k of ['managerPassword', 'recoveryPin']) if (k in d) { delete d[k]; changed = true; }
  const clean = sanitizeDeep(d);
  if (JSON.stringify(clean) !== JSON.stringify(d)) { d = clean; changed = true; }
  if (changed) { await shop.updateOne({ _id: 'main' }, { $set: { json: JSON.stringify(d) } }); await bump(); console.log('Secured shop data: ' + n + ' staff password(s) hashed'); }
}
async function migrate() {
  await migrateSecrets();
  await meta.deleteMany({ _id: { $regex: '^pid:' }, at: { $lt: Date.now() - 2 * 86400e3 } });
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
  shop = db.collection('shop'); auth = db.collection('auth'); billsCol = db.collection('bills'); meta = db.collection('meta'); wpCol = db.collection('webproducts'); cmCol = db.collection('customermsgs'); offersCol = db.collection('offers');
  await migrate();
  (await configWarnings()).forEach(w => console.warn('SECURITY WARNING: ' + w));
  app.listen(process.env.PORT || 3000, () => console.log('RCF server running'));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
