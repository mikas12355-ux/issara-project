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
const MAIL_OK = !!(E.RESEND_API_KEY && E.FROM_EMAIL);
const db = new DatabaseSync(E.DB_PATH || path.join(dir, 'issara.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT, dob TEXT, gender TEXT, pass TEXT, role TEXT DEFAULT 'user', org TEXT, verified INTEGER DEFAULT 0, lang TEXT DEFAULT 'ar');
CREATE TABLE IF NOT EXISTS codes(email TEXT, code TEXT, exp INTEGER, tries INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, uid INTEGER, exp INTEGER);
CREATE TABLE IF NOT EXISTS signs(id INTEGER PRIMARY KEY, uid INTEGER, word TEXT, type TEXT, seq TEXT);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, uid INTEGER, org TEXT, kind TEXT, text TEXT, details TEXT, attach TEXT, status TEXT DEFAULT 'new', created INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, rid INTEGER, who TEXT, kind TEXT, text TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS mails(id INTEGER PRIMARY KEY, to_ TEXT, subject TEXT, body TEXT, created INTEGER, sent INTEGER DEFAULT 0);`);
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

async function mail(to, subject, text) {
  const id = run('INSERT INTO mails(to_,subject,body,created) VALUES(?,?,?,?)', to, subject, text, Date.now()).lastInsertRowid;
  if (!MAIL_OK) { console.log(`\n[بريد تجريبي — لم يُضبط Resend] إلى: ${to}\n${subject}\n${text}\n`); return; }
  try {
    const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${E.RESEND_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: E.FROM_EMAIL, to: [to], subject, text }) });
    if (!r.ok) throw new Error(await r.text());
    run('UPDATE mails SET sent=1 WHERE id=?', id);
  } catch (e) { console.error('فشل إرسال البريد:', e.message); }
}
const reportMail = (r, user, msg) => mail(user.email, `${msg} — بلاغ #${r.id}`, `${msg}\n\nرقم البلاغ: #${r.id}\nرابط آمن لمتابعة البلاغ (يتطلب تسجيل الدخول): ${BASE}/#/report/${r.id}\n\nلا نضع تفاصيل البلاغ في البريد حفاظًا على خصوصيتك.`);

// ---------- حسابات الجهات (تُنشأ أول تشغيل) ----------
for (const k of Object.keys(ORGS)) {
  const email = (E[k.toUpperCase() + '_ADMIN_EMAIL'] || `${k}@issara.local`).toLowerCase();
  if (one('SELECT id FROM users WHERE email=?', email)) continue;
  const pw = E[k.toUpperCase() + '_ADMIN_PASSWORD'] || crypto.randomBytes(6).toString('hex');
  run('INSERT INTO users(email,name,pass,role,org,verified) VALUES(?,?,?,?,?,1)', email, ORGS[k], hash(pw), 'org', k);
  console.log(`حساب جهة [${k}]  البريد: ${email}  كلمة المرور: ${pw}`);
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
async function sendCode(email) {
  const code = String(crypto.randomInt(100000, 999999));
  run('DELETE FROM codes WHERE email=?', email); run('INSERT INTO codes(email,code,exp) VALUES(?,?,?)', email, code, Date.now() + 15 * 6e4);
  await mail(email, 'رمز التحقق — إشارة', `رمز التحقق الخاص بك: ${code}\nصالح لمدة 15 دقيقة. إذا لم تنشئ حسابًا تجاهل هذه الرسالة.`);
  return E.DEV_SHOW_CODE === '1' && !MAIL_OK ? code : undefined;
}
const repOut = (r, full, role) => {
  const o = { id: r.id, org: r.org, kind: JSON.parse(r.kind || '[]'), text: r.text, details: r.details, status: r.status, created: r.created, updated: r.updated };
  if (full) {
    o.attach = JSON.parse(r.attach || '[]');
    o.msgs = q('SELECT who,kind,text,created FROM msgs WHERE rid=? ORDER BY id', r.id).filter(m => role === 'org' || m.kind !== 'note');
    if (role === 'org') { const u = one('SELECT name,email,dob,gender,school,grade FROM users WHERE id=?', r.uid); o.reporter = u; }
  }
  return o;
};

// ---------- المسارات ----------
const routes = [];
const R = (m, p, f) => routes.push([m, new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), f]);

R('GET', '/api/health', async () => ({ ok: true, emailConfigured: MAIL_OK }));
R('POST', '/api/register', async (req, b, p, ip) => {
  if (limited(ip, 'reg', 10)) fail('محاولات كثيرة، حاول لاحقًا', 429);
  const email = String(b.email || '').trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) fail('البريد غير صالح');
  if (!b.name || !b.dob || String(b.password || '').length < 8) fail('أكمل البيانات (كلمة المرور 8 أحرف على الأقل)');
  const ex = one('SELECT * FROM users WHERE email=?', email);
  if (ex && ex.verified) fail('هذا البريد مسجل مسبقًا', 409);
  if (ex) run('UPDATE users SET name=?,dob=?,gender=?,pass=?,lang=? WHERE id=?', b.name, b.dob, b.gender === 'f' ? 'f' : 'm', hash(b.password), b.lang || 'ar', ex.id);
  else run('INSERT INTO users(email,name,dob,gender,pass,lang) VALUES(?,?,?,?,?,?)', email, b.name.trim(), b.dob, b.gender === 'f' ? 'f' : 'm', hash(b.password), b.lang || 'ar');
  return { ok: true, devCode: await sendCode(email) };
});
R('POST', '/api/resend', async (req, b, p, ip) => {
  if (limited(ip, 'rs', 6)) fail('محاولات كثيرة', 429);
  const email = String(b.email || '').toLowerCase(), u = one('SELECT * FROM users WHERE email=? AND verified=0', email);
  if (u) return { ok: true, devCode: await sendCode(email) }; return { ok: true };
});
R('POST', '/api/verify', async (req, b, p, ip) => {
  if (limited(ip, 'vf', 20)) fail('محاولات كثيرة', 429);
  const email = String(b.email || '').toLowerCase(), c = one('SELECT * FROM codes WHERE email=?', email);
  if (!c || c.exp < Date.now() || c.tries >= 5) fail('الرمز منتهي، اطلب رمزًا جديدًا');
  if (c.code !== String(b.code).trim()) { run('UPDATE codes SET tries=tries+1 WHERE email=?', email); fail('الرمز غير صحيح'); }
  run('UPDATE users SET verified=1 WHERE email=?', email); run('DELETE FROM codes WHERE email=?', email);
  const u = one('SELECT * FROM users WHERE email=?', email);
  return { token: session(u.id), user: pub(u) };
});
R('POST', '/api/login', async (req, b, p, ip) => {
  if (limited(ip, 'lg', 20)) fail('محاولات كثيرة، حاول لاحقًا', 429);
  const u = one('SELECT * FROM users WHERE email=?', String(b.email || '').trim().toLowerCase());
  if (!u || !check(String(b.password || ''), u.pass)) fail('البريد أو كلمة المرور غير صحيحة', 401);
  if (!u.verified) return { needVerify: true, devCode: await sendCode(u.email) };
  return { token: session(u.id), user: pub(u) };
});
R('POST', '/api/logout', async req => { run('DELETE FROM sessions WHERE token=?', (req.headers.authorization || '').slice(7)); return { ok: true }; });
R('GET', '/api/me', async req => ({ user: pub(need(auth(req))) }));
R('PUT', '/api/me', async (req, b) => {
  const u = need(auth(req));
  run('UPDATE users SET name=?,dob=?,gender=?,lang=?,school=?,grade=? WHERE id=?', String(b.name || u.name).trim(), b.dob || u.dob, b.gender === 'f' ? 'f' : b.gender === 'm' ? 'm' : u.gender, b.lang || u.lang, String(b.school ?? u.school ?? '').slice(0,160), String(b.grade ?? u.grade ?? '').slice(0,100), u.id);
  return { user: pub(one('SELECT * FROM users WHERE id=?', u.id)) };
});

// عينات الإشارات (إحداثيات المفاصل فقط — لا صور ولا فيديو)
R('GET', '/api/signs', async req => ({ signs: q('SELECT word,type,seq FROM signs WHERE uid=?', need(auth(req)).id).map(s => ({ ...s, seq: JSON.parse(s.seq) })) }));
R('POST', '/api/signs', async (req, b) => {
  const u = need(auth(req)), w = String(b.word || '').trim();
  if (!w || w.length > 40 || !Array.isArray(b.seq) || b.seq.length !== 16) fail('بيانات غير صالحة');
  if (q('SELECT id FROM signs WHERE uid=? AND word=?', u.id, w).length >= 12) fail('الحد الأقصى 12 عينة لكل إشارة');
  run('INSERT INTO signs(uid,word,type,seq) VALUES(?,?,?,?)', u.id, w, ['WORD', 'PHRASE', 'LETTER', 'NUMBER'].includes(b.type) ? b.type : 'WORD', JSON.stringify(b.seq.map(f => Array.from(f, x => +(+x).toFixed(4)))));
  return { ok: true };
});
R('POST', '/api/signs/delete', async (req, b) => { run('DELETE FROM signs WHERE uid=? AND word=?', need(auth(req)).id, String(b.word)); return { ok: true }; });

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
  reportMail(r, u, 'تم استلام بلاغك');
  const adm = one('SELECT email FROM users WHERE role=? AND org=?', 'org', b.org);
  if (adm) mail(adm.email, `بلاغ جديد #${id}`, `وصل بلاغ جديد رقم #${id}. سجّل الدخول للوحة الجهة: ${BASE}/#/report/${id}`);
  return { id, status: 'new' };
});
R('GET', '/api/reports', async req => {
  const u = need(auth(req));
  const rows = u.role === 'org' ? q('SELECT * FROM reports WHERE org=? ORDER BY id DESC', u.org) : q('SELECT * FROM reports WHERE uid=? ORDER BY id DESC', u.id);
  return { reports: rows.map(r => {
    const out = repOut(r, false);
    const reply = one("SELECT text FROM msgs WHERE rid=? AND kind='reply' ORDER BY id DESC LIMIT 1", r.id);
    out.lastReply = reply?.text || '';
    if (u.role === 'org') out.reporter = one('SELECT name,school,grade FROM users WHERE id=?', r.uid);
    return out;
  }) };
});
const getRep = (u, id) => { const r = one('SELECT * FROM reports WHERE id=?', +id); if (!r || (u.role === 'org' ? r.org !== u.org : r.uid !== u.id)) fail('غير موجود', 404); return r; };
R('GET', '/api/reports/:id', async (req, b, p) => { const u = need(auth(req)); return { report: repOut(getRep(u, p.id), true, u.role) }; });
R('POST', '/api/reports/:id/reply', async (req, b, p) => {
  const u = need(auth(req)), r = getRep(u, p.id), t = String(b.text || '').trim(); if (!t) fail('اكتب الرد');
  run('INSERT INTO msgs(rid,who,kind,text,created) VALUES(?,?,?,?,?)', r.id, 'user', 'reply', t, Date.now());
  if (r.status === 'info') run('UPDATE reports SET status=?,updated=? WHERE id=?', 'review', Date.now(), r.id);
  const adm = one('SELECT email FROM users WHERE role=? AND org=?', 'org', r.org); if (adm) mail(adm.email, `رد المستخدم على بلاغ #${r.id}`, `${BASE}/#/report/${r.id}`);
  return { ok: true };
});
R('POST', '/api/reports/:id/update', async (req, b, p) => {
  const u = need(auth(req)); if (u.role !== 'org') fail('غير مصرح', 403);
  const r = getRep(u, p.id), now = Date.now(), owner = one('SELECT * FROM users WHERE id=?', r.uid);
  if (b.note && b.note.trim()) run('INSERT INTO msgs(rid,who,kind,text,created) VALUES(?,?,?,?,?)', r.id, 'org', 'note', b.note.trim(), now);
  if (b.reply && b.reply.trim()) run('INSERT INTO msgs(rid,who,kind,text,created) VALUES(?,?,?,?,?)', r.id, 'org', 'reply', b.reply.trim(), now);
  if (b.status && STATUS[b.status] && b.status !== 'new' && b.status !== r.status) {
    run('UPDATE reports SET status=?,updated=? WHERE id=?', b.status, now, r.id); reportMail(r, owner, STATUS[b.status]);
  } else if (b.reply && b.reply.trim()) { run('UPDATE reports SET updated=? WHERE id=?', now, r.id); reportMail(r, owner, 'وصلك رد جديد على بلاغك'); }
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
}).listen(PORT, () => console.log(`إشارة تعمل على ${BASE}  | البريد: ${MAIL_OK ? 'Resend مفعّل' : 'غير مُعدّ (الرسائل تُطبع هنا)'}`));