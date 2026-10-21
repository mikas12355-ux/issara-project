// إشارة — الخادم (Node 22.13+ أو 24). قاعدة بيانات SQLite حقيقية، بدون أي تبعيات خارجية.
import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { readFile } from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const E = process.env;
const PORT = +E.PORT || 8787;
const BASE = E.BASE_URL || `http://localhost:${PORT}`;

const db = new DatabaseSync(E.DB_PATH || path.join(dir, 'issara.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT, dob TEXT, gender TEXT, pass TEXT, role TEXT DEFAULT 'user', org TEXT, verified INTEGER DEFAULT 0, lang TEXT DEFAULT 'ar');
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, uid INTEGER, exp INTEGER);
CREATE TABLE IF NOT EXISTS signs(id INTEGER PRIMARY KEY, uid INTEGER, word TEXT, type TEXT, seq TEXT);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, uid INTEGER, org TEXT, kind TEXT, text TEXT, details TEXT, attach TEXT, status TEXT DEFAULT 'new', created INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, rid INTEGER, who TEXT, kind TEXT, text TEXT, created INTEGER);`);
// إضافة حقول المدرسة والصف للبيانات القديمة دون مسح الحسابات أو البلاغات.
for (const [field, type] of [['school','TEXT'],['grade','TEXT']]) {
  if (!db.prepare('PRAGMA table_info(users)').all().some(c => c.name === field)) db.exec(`ALTER TABLE users ADD COLUMN ${field} ${type}`);
}
const q = (s, ...a) => db.prepare(s).all(...a), one = (s, ...a) => db.prepare(s).get(...a), run = (s, ...a) => db.prepare(s).run(...a);

const ORGS = { school: 'مدرسة', univ: 'جامعة', edu: 'جهة تعليمية', auth: 'جهة مختصة' };
const STATUS = {
  new: 'لم يتم الاستلام', received: 'تم استلام البلاغ من الجهة المختصة', review: 'بلاغك قيد المراجعة',
  info: 'نحتاج إلى معلومات إضافية', action: 'تم اتخاذ إجراء بشأن بلاغك', resolved: 'تم حل البلاغ', closed: 'تم إغلاق البلاغ'
};

// ---------- كلمات المرور والبريد ----------
const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
const check = (pw, h) => { const [s, x] = (h || '').split(':'); if (!s) return false; const y = hash(pw, s).split(':')[1]; return crypto.timingSafeEqual(Buffer.from(x, 'hex'), Buffer.from(y, 'hex')); };


// ---------- حسابات الجهات (تُنشأ أول تشغيل) ----------
for (const k of Object.keys(ORGS)) {
  const email = (E[k.toUpperCase() + '_ADMIN_EMAIL'] || `${k}@issara.local`).toLowerCase();
  if (one('SELECT id FROM users WHERE email=?', email)) continue;
  const pw = E[k.toUpperCase() + '_ADMIN_PASSWORD'] || crypto.randomBytes(6).toString('hex');
  run('INSERT INTO users(email,name,pass,role,org,verified) VALUES(?,?,?,?,?,1)', email, ORGS[k], hash(pw), 'org', k);
  console.log(`حساب جهة [${k}]  البريد: ${email}  كلمة المرور: ${pw}`);
}

// حساب الإدارة العامة: يُنشأ فقط إذا أُدخلت بياناته في متغيرات Render السرية.
// لا تمنح صلاحيات الإدارة من نموذج التسجيل العام أبدًا.
if (E.ADMIN_EMAIL && E.ADMIN_PASSWORD) {
  const adminEmail = E.ADMIN_EMAIL.trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(adminEmail) || E.ADMIN_PASSWORD.length < 12)
    throw new Error('ADMIN_EMAIL غير صالح أو ADMIN_PASSWORD أقل من 12 حرفًا');
  const existing = one('SELECT id,role FROM users WHERE email=?', adminEmail);
  if (existing && existing.role !== 'admin') {
    console.error('تعذر إنشاء حساب الإدارة: البريد مستخدم في حساب آخر. استخدم بريدًا آخر للإدارة.');
  } else if (existing) {
    // تحديث كلمة مرور حساب الإدارة عند تغييرها في إعدادات Render.
    run('UPDATE users SET pass=?,verified=1 WHERE id=?', hash(E.ADMIN_PASSWORD), existing.id);
  } else {
    run('INSERT INTO users(email,name,pass,role,verified) VALUES(?,?,?,?,1)', adminEmail, 'إدارة إشارة', hash(E.ADMIN_PASSWORD), 'admin');
  }
} else {
  console.warn('حساب الإدارة غير مُفعّل: اضبط ADMIN_EMAIL و ADMIN_PASSWORD في Render.');
}

// ---------- أدوات ----------
const hits = new Map();
const limited = (ip, k, n = 20) => { const key = ip + k, now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < 600000); a.push(now); hits.set(key, a); return a.length > n; };
const send = (res, st, b, type = 'application/json; charset=utf-8') => { res.writeHead(st, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff', 'Permissions-Policy': 'camera=(self)', 'Referrer-Policy': 'no-referrer' }); res.end(typeof b === 'string' ? b : JSON.stringify(b)); };
async function body(req) { let s = '', n = 0; for await (const c of req) { n += c.length; if (n > 4e6) throw Object.assign(new Error('الطلب كبير جدًا'), { st: 413 }); s += c; } return s ? JSON.parse(s) : {}; }
const pub = u => ({ id: u.id, email: u.email, name: u.name, dob: u.dob, gender: u.gender, role: u.role, org: u.org, lang: u.lang, school: u.school || "", grade: u.grade || "", verified: !!u.verified });
function auth(req) { const t = (req.headers.authorization || '').slice(7); const s = t && one('SELECT * FROM sessions WHERE token=? AND exp>?', t, Date.now()); return s ? one('SELECT * FROM users WHERE id=?', s.uid) : null; }
const need = u => { if (!u) throw Object.assign(new Error('يلزم تسجيل الدخول'), { st: 401 }); return u; };
const fail = (m, st = 400) => { throw Object.assign(new Error(m), { st }); };
const session = uid => { const t = crypto.randomBytes(32).toString('hex'); run('INSERT INTO sessions VALUES(?,?,?)', t, uid, Date.now() + 30 * 864e5); return t; };
const repOut = (r, full, role) => {
  const o = { id: r.id, org: r.org, kind: JSON.parse(r.kind || '[]'), text: r.text, details: r.details, status: r.status, created: r.created, updated: r.updated };
  if (full) {
    o.attach = JSON.parse(r.attach || '[]');
    o.msgs = q('SELECT who,kind,text,created FROM msgs WHERE rid=? ORDER BY id', r.id).filter(m => (role === 'org' || role === 'admin') || m.kind !== 'note');
    if (role === 'org' || role === 'admin') { const u = one('SELECT name,email,dob,gender,school,grade FROM users WHERE id=?', r.uid); o.reporter = u; }
  }
  return o;
};

// ---------- المسارات ----------
const routes = [];
const R = (m, p, f) => routes.push([m, new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), f]);

R('GET', '/api/health', async () => ({ ok: true, emailVerificationRequired: false }));
R('POST', '/api/register', async (req, b, p, ip) => {
  if (limited(ip, 'reg', 10)) fail('محاولات كثيرة، حاول لاحقًا', 429);
  const email = String(b.email || '').trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) fail('البريد غير صالح');
  if (!String(b.name || '').trim() || !b.dob || String(b.password || '').length < 8) fail('أكمل البيانات (كلمة المرور 8 أحرف على الأقل)');
  if (one('SELECT id FROM users WHERE email=?', email)) fail('هذا البريد مسجل مسبقًا', 409);
  const id = run('INSERT INTO users(email,name,dob,gender,pass,lang,verified) VALUES(?,?,?,?,?,?,1)', email, String(b.name).trim(), b.dob, b.gender === 'f' ? 'f' : 'm', hash(b.password), b.lang || 'ar').lastInsertRowid;
  return { token: session(id), user: pub(one('SELECT * FROM users WHERE id=?', id)) };
});
R('POST', '/api/login', async (req, b, p, ip) => {
  if (limited(ip, 'lg', 20)) fail('محاولات كثيرة، حاول لاحقًا', 429);
  const u = one('SELECT * FROM users WHERE email=?', String(b.email || '').trim().toLowerCase());
  if (!u || !check(String(b.password || ''), u.pass)) fail('البريد أو كلمة المرور غير صحيحة', 401);
  return { token: session(u.id), user: pub(u) };
});
R('POST', '/api/logout', async req => { run('DELETE FROM sessions WHERE token=?', (req.headers.authorization || '').slice(7)); return { ok: true }; });
R('GET', '/api/me', async req => ({ user: pub(need(auth(req))) }));
R('PUT', '/api/me', async (req, b) => {
  const u = need(auth(req));
  const email=String(b.email || u.email).trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) fail('البريد غير صالح');
  if (one('SELECT id FROM users WHERE email=? AND id<>?',email,u.id)) fail('البريد مستخدم في حساب آخر',409);
  run('UPDATE users SET name=?,email=?,dob=?,gender=?,lang=?,school=?,grade=? WHERE id=?', String(b.name || u.name).trim(), email, b.dob || u.dob, b.gender === 'f' ? 'f' : b.gender === 'm' ? 'm' : u.gender, b.lang || u.lang, String(b.school ?? u.school ?? '').slice(0,160), String(b.grade ?? u.grade ?? '').slice(0,100), u.id);
  return { user: pub(one('SELECT * FROM users WHERE id=?', u.id)) };
});

// عينات الإشارات (إحداثيات المفاصل فقط — لا صور ولا فيديو)
// القاموس مشترك بين جميع المستخدمين، وإدارته محصورة في حساب الإدارة العامة.
// العينات السابقة للحسابات العادية تبقى محفوظة لكنها لا تدخل في الترجمة المشتركة.
const adminId = () => one("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1")?.id;
R('GET', '/api/signs', async req => {
  need(auth(req));
  const id = adminId();
  return { signs: id ? q('SELECT word,type,seq FROM signs WHERE uid=?', id).map(s => ({ ...s, seq: JSON.parse(s.seq) })) : [] };
});
R('POST', '/api/signs', async (req, b) => {
  const u = need(auth(req)), w = String(b.word || '').trim();
  if (u.role !== 'admin') fail('القاموس مخصص للإدارة فقط', 403);
  if (!w || w.length > 40 || !Array.isArray(b.seq) || b.seq.length !== 16) fail('بيانات غير صالحة');
  if (q('SELECT id FROM signs WHERE uid=? AND word=?', u.id, w).length >= 12) fail('الحد الأقصى 12 عينة لكل إشارة');
  run('INSERT INTO signs(uid,word,type,seq) VALUES(?,?,?,?)', u.id, w, ['WORD', 'PHRASE', 'LETTER', 'NUMBER'].includes(b.type) ? b.type : 'WORD', JSON.stringify(b.seq.map(f => Array.from(f, x => +(+x).toFixed(4)))));
  return { ok: true };
});
R('POST', '/api/signs/delete', async (req, b) => { const u=need(auth(req)); if(u.role!=='admin')fail('غير مصرح',403); run('DELETE FROM signs WHERE uid=? AND word=?', u.id, String(b.word)); return { ok: true }; });

// البلاغات
R('POST', '/api/reports', async (req, b) => {
  const u = need(auth(req));
  if (u.role !== 'user') fail('حساب الجهة لا ينشئ بلاغات', 403);
  if (!String(b.text || '').trim()) fail('نص البلاغ فارغ');
  if (!ORGS[b.org]) fail('اختر الجهة');
  const at = (Array.isArray(b.attach) ? b.attach : []).filter(a => typeof a === 'string' && a.startsWith('data:image/') && a.length < 2e6).slice(0, 3);
  const id = Math.max(1023, one('SELECT MAX(id) m FROM reports').m || 0) + 1, now = Date.now();
  run('INSERT INTO reports(id,uid,org,kind,text,details,attach,created,updated) VALUES(?,?,?,?,?,?,?,?,?)', id, u.id, b.org, JSON.stringify(b.kind || []), b.text.trim(), String(b.details || '').trim(), JSON.stringify(at), now, now);
  const r = one('SELECT * FROM reports WHERE id=?', id);
  return { id, status: 'new' };
});
R('GET', '/api/reports', async req => {
  const u = need(auth(req));
  const rows = u.role === 'admin' ? q('SELECT * FROM reports ORDER BY id DESC') : u.role === 'org' ? q('SELECT * FROM reports WHERE org=? ORDER BY id DESC', u.org) : q('SELECT * FROM reports WHERE uid=? ORDER BY id DESC', u.id);
  return { reports: rows.map(r => {
    const out = repOut(r, false);
    const reply = one("SELECT text FROM msgs WHERE rid=? AND kind='reply' ORDER BY id DESC LIMIT 1", r.id);
    out.lastReply = reply?.text || '';
    if (u.role === 'org' || u.role === 'admin') out.reporter = one('SELECT name,school,grade FROM users WHERE id=?', r.uid);
    return out;
  }) };
});
const getRep = (u, id) => { const r = one('SELECT * FROM reports WHERE id=?', +id); if (!r || (u.role === 'admin' ? false : u.role === 'org' ? r.org !== u.org : r.uid !== u.id)) fail('غير موجود', 404); return r; };
R('GET', '/api/reports/:id', async (req, b, p) => { const u = need(auth(req)); return { report: repOut(getRep(u, p.id), true, u.role) }; });
R('POST', '/api/reports/:id/reply', async (req, b, p) => {
  const u = need(auth(req)), r = getRep(u, p.id), t = String(b.text || '').trim(); if (u.role !== 'user') fail('هذا المسار للمستخدمين فقط',403); if (!t) fail('اكتب الرد');
  run('INSERT INTO msgs(rid,who,kind,text,created) VALUES(?,?,?,?,?)', r.id, 'user', 'reply', t, Date.now());
  if (r.status === 'info') run('UPDATE reports SET status=?,updated=? WHERE id=?', 'review', Date.now(), r.id);
  return { ok: true };
});
R('POST', '/api/reports/:id/update', async (req, b, p) => {
  const u = need(auth(req)); if (u.role !== 'org' && u.role !== 'admin') fail('غير مصرح', 403);
  const r = getRep(u, p.id), now = Date.now();
  if (b.note && b.note.trim()) run('INSERT INTO msgs(rid,who,kind,text,created) VALUES(?,?,?,?,?)', r.id, 'org', 'note', b.note.trim(), now);
  if (b.reply && b.reply.trim()) run('INSERT INTO msgs(rid,who,kind,text,created) VALUES(?,?,?,?,?)', r.id, 'org', 'reply', b.reply.trim(), now);
  if (b.status && STATUS[b.status] && b.status !== 'new' && b.status !== r.status) {
    run('UPDATE reports SET status=?,updated=? WHERE id=?', b.status, now, r.id);
  } else if (b.reply && b.reply.trim()) { run('UPDATE reports SET updated=? WHERE id=?', now, r.id); }
  return { ok: true };
});

// ---------- التشغيل ----------
http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE), ip = req.socket.remoteAddress || '';
  try {
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html'))
      return send(res, 200, await readFile(path.join(dir, 'index.html'), 'utf8'), 'text/html; charset=utf-8');
    for (const [m, re, f] of routes) {
      const mm = m === req.method && url.pathname.match(re); if (!mm) continue;
      const b = req.method === 'GET' ? {} : await body(req);
      return send(res, 200, await f(req, b, mm.groups || {}, ip));
    }
    send(res, 404, { error: 'غير موجود' });
  } catch (e) { if (!e.st) console.error(e); send(res, e.st || 500, { error: e.st ? e.message : 'خطأ في الخادم' }); }
}).listen(PORT, () => console.log(`إشارة تعمل على ${BASE} | التحقق بالبريد ملغى`));