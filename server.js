// Starfall backend: signup, login, sessions (ported from the Unique Trading auth system).
// Env vars (Render -> Environment):
//   TURSO_URL, TURSO_TOKEN        database
//   ALLOWED_ORIGINS               optional, extra browser origins, comma separated
//   SIGNUP_COOLDOWN=0             optional, turns off the "one account per day" rule (useful while testing)
//   SKIP_DNS=1                    optional, skips the e-mail domain DNS check
//   IP_HASH_SECRET                optional, secret used for lock-out keys
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const { createClient } = require('@libsql/client');

const cleanEnv = (v) => String(v || '').trim().replace(/^["']+|["']+$/g, '').trim();
const TURSO_TOKEN = cleanEnv(process.env.TURSO_TOKEN);
const db = createClient({ url: cleanEnv(process.env.TURSO_URL), authToken: TURSO_TOKEN || undefined });

const app = express();
const PORT = process.env.PORT || 10000;
const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const SESSION_MS = 30 * DAY;
const IS_SECURE = process.env.NODE_ENV === 'production' || process.env.RENDER === 'true';
const SIGNUP_COOLDOWN = process.env.SIGNUP_COOLDOWN !== '0';

app.disable('x-powered-by');
app.set('trust proxy', 1); // Render has one proxy hop

// ---------- database ----------
async function initDB() {
    const run = async (sql) => { try { await db.execute(sql); } catch (e) { /* column/table already exists */ } };
    await run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT,
        password TEXT NOT NULL
    )`);
    for (const col of ['passwordHash TEXT', 'joinedAt INTEGER', 'lastIp TEXT']) await run(`ALTER TABLE users ADD COLUMN ${col}`);
    await run(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, userId INTEGER NOT NULL, createdAt INTEGER, expiresAt INTEGER)`);
    await run(`CREATE TABLE IF NOT EXISTS login_lockouts (k TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, level INTEGER NOT NULL DEFAULT 0, lockedUntil INTEGER NOT NULL DEFAULT 0, lastFailAt INTEGER NOT NULL DEFAULT 0)`);
    await run(`CREATE TABLE IF NOT EXISTS signup_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, createdAt INTEGER)`);
    await run(`CREATE INDEX IF NOT EXISTS sessions_user ON sessions (userId)`);
    await run(`DELETE FROM sessions WHERE expiresAt < ${Date.now()}`);
    console.log('Turso Database initialized successfully');
}
setInterval(() => db.execute({ sql: 'DELETE FROM sessions WHERE expiresAt < ?', args: [Date.now()] }).catch(() => {}), HOUR);

// ---------- small helpers ----------
const route = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);   // Express 4 does not catch async errors
const sha256 = (v) => crypto.createHash('sha256').update(String(v)).digest('hex');
const tokenOk = (t) => /^[a-f0-9]{64}$/.test(String(t || ''));
const safeEqual = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
const ipOf = (req) => {
    const ip = String(req.ip || '').trim().replace(/^::ffff:/i, '').toLowerCase();
    return ip && ip.length <= 64 && !/[\s,]/.test(ip) ? ip : '';
};
function parseCookies(req) {
    const out = {};
    String(req.headers.cookie || '').split(';').forEach((part) => {
        const i = part.indexOf('=');
        if (i < 0) return;
        const k = part.slice(0, i).trim();
        if (k in out) return;
        try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { out[k] = part.slice(i + 1).trim(); }
    });
    return out;
}
function setCookie(res, name, value, maxAgeMs) {
    const flags = IS_SECURE ? '; Secure; SameSite=None' : '; SameSite=Lax';
    res.append('Set-Cookie', `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Max-Age=${Math.floor(maxAgeMs / 1000)}${flags}`);
}
const clearCookie = (res, name) => setCookie(res, name, '', 0);

// simple in-memory rate limiter
const buckets = new Map();
function limited(key, max, windowMs) {
    const now = Date.now();
    const b = (buckets.get(key) || []).filter((t) => now - t < windowMs);
    b.push(now);
    buckets.set(key, b);
    return b.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of buckets) if (!v.some((t) => now - t < DAY)) buckets.delete(k); }, 10 * 60 * 1000);

// ---------- CORS + security headers ----------
const ALLOWED_ORIGINS = new Set([
    'https://starfall-rejh.onrender.com',
    'https://knqwix.github.io',
    'https://knqwx.github.io',
    ...String(process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean)
]);
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) res.setHeader('Vary', 'Origin');
    if (origin && ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Session');
        res.setHeader('Access-Control-Max-Age', '600');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(origin && !ALLOWED_ORIGINS.has(origin) ? 403 : 204);
    // browsers always attach Origin to cross-site POSTs: refuse the ones that are not ours
    if (origin && req.method !== 'GET' && req.method !== 'HEAD' && !ALLOWED_ORIGINS.has(origin)) {
        let sameHost = false;
        try { sameHost = new URL(origin).host === req.headers.host; } catch (e) {}
        if (!sameHost) return res.status(403).json({ error: 'Request blocked.' });
    }
    next();
});
app.use((req, res, next) => {
    if (IS_SECURE) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
    next();
});
app.use(express.json({ limit: '50kb' }));

// ---------- rules ----------
const BURNER_DOMAINS = new Set('mailinator.com mailinator.net mailinator.org guerrillamail.com guerrillamail.net guerrillamail.org sharklasers.com grr.la 10minutemail.com 10minutemail.net 20minutemail.com temp-mail.org temp-mail.io tempmail.com tempmail.net throwawaymail.com trashmail.com trashmail.net yopmail.com yopmail.net yopmail.fr getnada.com dispostable.com maildrop.cc fakeinbox.com mohmal.com emailondeck.com mintemail.com spamgourmet.com tempinbox.com burnermail.io moakt.com'.split(' '));
const BURNER_KEYWORDS = ['tempmail', 'temp-mail', 'tmpmail', '10minute', 'minutemail', 'throwaway', 'trashmail', 'trash-mail', 'mailinator', 'guerrilla', 'fakeinbox', 'disposable', 'burner', 'yopmail', 'spamgourmet', 'getnada', 'tempinbox', 'sharklasers', 'dispostable', 'maildrop', 'mohmal', 'fakemail', 'emailfake', 'instantemail', 'anonmail', 'spambox'];
function isBurnerDomain(domain) {
    domain = domain.toLowerCase();
    const parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) if (BURNER_DOMAINS.has(parts.slice(i).join('.'))) return true;
    return BURNER_KEYWORDS.some((k) => domain.includes(k));
}
async function checkEmail(email) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254) return 'Please enter a valid email address.';
    const domain = email.split('@')[1].toLowerCase();
    if (isBurnerDomain(domain)) return 'Disposable or burner email addresses are not allowed. Please use your real email.';
    if (process.env.SKIP_DNS === '1') return '';
    try {
        const mx = await dns.resolveMx(domain);
        if (mx && mx.length) return '';
    } catch (e) {
        if (e.code === 'ENOTFOUND' || e.code === 'NXDOMAIN') return 'This email domain does not exist. Please check your email address.';
        if (e.code !== 'ENODATA') return ''; // DNS problem on our side: do not block real users
    }
    try { await dns.resolve4(domain); return ''; }
    catch (e) {
        if (e.code === 'ENOTFOUND' || e.code === 'ENODATA' || e.code === 'NXDOMAIN') return 'This email domain cannot receive mail. Please use a real email address.';
        return '';
    }
}

// Names that look like staff / the service itself (case, . _ - and 0/1/3/4/5/7 look-alikes are ignored)
const RESERVED_EXACT = new Set(['admin', 'administrator', 'support', 'staff', 'moderator', 'mod', 'mods', 'owner', 'system', 'official', 'root', 'help', 'helpdesk', 'service', 'team',
    'security', 'billing', 'verify', 'verified', 'starfall', 'null', 'undefined', 'anonymous', 'sysadmin', 'superuser', 'webmaster', 'contact', 'info', 'abuse', 'postmaster', 'noreply']);
const RESERVED_PREFIX = ['admin', 'administrator', 'moderator', 'starfall', 'officialsupport'];
const RESERVED_AFFIX = ['the', 'real', 'official', 'im', 'iam', 'mr', 'ms', 'x', 'xx'];
const LEET = { 0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', 7: 't' };
const normalizeName = (name) => String(name || '').toLowerCase().replace(/[._-]/g, '').replace(/[013457]/g, (c) => LEET[c]);
function isReservedUsername(name) {
    const n = normalizeName(name), raw = String(name || '').toLowerCase().replace(/[._-]/g, '');
    for (const cand of new Set([n, raw])) {
        if (RESERVED_EXACT.has(cand)) return true;
        if (RESERVED_PREFIX.some((w) => cand.startsWith(w) || cand.endsWith(w))) return true;
        for (const w of RESERVED_EXACT) {
            if (w.length < 4) continue;
            if (cand.startsWith(w) && /^\d+$/.test(cand.slice(w.length))) return true;
            for (const a of RESERVED_AFFIX) if (cand === a + w || cand === w + a) return true;
        }
    }
    return false;
}
// Any characters and any length are allowed; only an empty name and the reserved staff-like names are refused.
function checkUsername(name) {
    if (!name) return 'Please enter a username.';
    if (isReservedUsername(name)) return 'This username is reserved. Please choose another one.';
    return '';
}

// ---------- passwords (scrypt, built into Node: no extra packages) ----------
const scrypt = (pw, salt) => new Promise((resolve, reject) => crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? reject(e) : resolve(k))));
async function hashPassword(pw) {
    const salt = crypto.randomBytes(16).toString('hex');
    return `scrypt$${salt}$${(await scrypt(pw, salt)).toString('hex')}`;
}
async function checkHash(pw, stored) {
    const [, salt, hash] = String(stored).split('$');
    if (!salt || !hash) return false;
    const k = await scrypt(pw, salt);
    const real = Buffer.from(hash, 'hex');
    return real.length === k.length && crypto.timingSafeEqual(real, k);
}
let DUMMY_HASH = 'scrypt$00$00';
hashPassword('not-a-real-password').then((h) => { DUMMY_HASH = h; }).catch(() => {});
// Checks a password; old plain-text / earlier-format passwords are upgraded to the new hash column on first successful use.
async function verifyPassword(u, password) {
    let ok = false;
    if (u.passwordHash) ok = await checkHash(password, u.passwordHash);
    if (!ok && typeof u.password === 'string' && u.password) {
        ok = u.password.startsWith('scrypt$') ? await checkHash(password, u.password) : safeEqual(u.password, password);
        if (ok) await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '' WHERE id = ?", args: [await hashPassword(password), Number(u.id)] });
    }
    return ok;
}

// ---------- sign-in lock-outs (per IP + account): 3 wrong passwords = 3 h, next 3 = 24 h ----------
const LOCK_AFTER = 3, LOCK_FIRST_MS = 3 * HOUR, LOCK_NEXT_MS = DAY, LOCK_FORGET_MS = 7 * DAY;
const LOCK_SECRET = cleanEnv(process.env.IP_HASH_SECRET || TURSO_TOKEN || 'starfall-ip-guard-change-me');
const lockKey = (ip, account) => crypto.createHmac('sha256', LOCK_SECRET).update(`login|${ip}|${String(account).toLowerCase()}`).digest('hex');
const lockText = (ms) => { const total = Math.max(1, Math.ceil(ms / 60000)), h = Math.floor(total / 60), m = total % 60; return h > 0 ? `${h}h ${m}m` : `${m}m`; };
async function lockoutStatus(key) {
    const r = await db.execute({ sql: 'SELECT lockedUntil FROM login_lockouts WHERE k = ?', args: [key] });
    const until = r.rows.length ? Number(r.rows[0].lockedUntil) || 0 : 0;
    return until > Date.now() ? { locked: true, lockedUntil: until, retryAfterMs: until - Date.now() } : { locked: false, lockedUntil: 0, retryAfterMs: 0 };
}
async function lockoutFail(key) {
    const now = Date.now();
    const r = await db.execute({ sql: 'SELECT fails, level, lastFailAt FROM login_lockouts WHERE k = ?', args: [key] });
    let fails = 0, level = 0;
    if (r.rows.length && now - Number(r.rows[0].lastFailAt) < LOCK_FORGET_MS) { fails = Number(r.rows[0].fails) || 0; level = Number(r.rows[0].level) || 0; }
    fails++;
    let lockedUntil = 0;
    if (fails >= LOCK_AFTER) { level++; lockedUntil = now + (level >= 2 ? LOCK_NEXT_MS : LOCK_FIRST_MS); fails = 0; }
    await db.execute({ sql: 'INSERT INTO login_lockouts (k, fails, level, lockedUntil, lastFailAt) VALUES (?, ?, ?, ?, ?) ON CONFLICT(k) DO UPDATE SET fails = excluded.fails, level = excluded.level, lockedUntil = excluded.lockedUntil, lastFailAt = excluded.lastFailAt', args: [key, fails, level, lockedUntil, now] });
    return { locked: lockedUntil > now, lockedUntil, retryAfterMs: Math.max(0, lockedUntil - now), attemptsLeft: lockedUntil ? 0 : LOCK_AFTER - fails };
}
const lockoutClear = (key) => db.execute({ sql: 'DELETE FROM login_lockouts WHERE k = ?', args: [key] });
const lockedReply = (st) => ({ error: `Too many incorrect attempts. Sign-in is locked for this account from your network. Try again in ${lockText(st.retryAfterMs)}.`, locked: true, lockedUntil: st.lockedUntil, retryAfterMs: st.retryAfterMs });

const BAD_LOGIN = 'Incorrect username/email or password.';
// "username or email" + password. Returns { user } or { status, body }. Never reveals whether the account exists.
async function authenticate(req, id, password) {
    const ip = ipOf(req);
    if (limited('login:' + ip, 20, 15 * 60 * 1000)) return { status: 429, body: { error: 'Too many attempts. Try again in a few minutes.' } };
    if (!id || !password) return { status: 400, body: { error: 'Please fill in all fields.' } };
    const rs = await db.execute({ sql: 'SELECT * FROM users WHERE lower(username) = lower(?) OR lower(email) = lower(?) ORDER BY (lower(username) = lower(?)) DESC LIMIT 1', args: [id, id, id] });
    const u = rs.rows.length ? rs.rows[0] : null;
    const key = lockKey(ip, u ? 'u' + u.id : 'n:' + id);
    const st = await lockoutStatus(key);
    if (st.locked) { if (!u) await checkHash(password, DUMMY_HASH); return { status: 429, body: lockedReply(st) }; }
    const ok = u ? await verifyPassword(u, password) : (await checkHash(password, DUMMY_HASH), false); // same work either way
    if (!ok) {
        const f = await lockoutFail(key);
        return { status: f.locked ? 429 : 401, body: f.locked ? lockedReply(f) : { error: BAD_LOGIN, attemptsLeft: f.attemptsLeft } };
    }
    await lockoutClear(key);
    return { user: u };
}

// ---------- sessions ----------
// The browser holds a random 256-bit token; the database stores only its SHA-256.
// Same-site pages use an httpOnly cookie. A page on another site (GitHub Pages) gets the token in the response and sends it back as X-Session.
async function startSession(res, userId) {
    const raw = crypto.randomBytes(32).toString('hex'), now = Date.now();
    await db.execute({ sql: 'INSERT INTO sessions (id, userId, createdAt, expiresAt) VALUES (?, ?, ?, ?)', args: [sha256(raw), Number(userId), now, now + SESSION_MS] });
    setCookie(res, 'sid', raw, SESSION_MS);
    return raw;
}
const requestTokens = (req) => {
    const out = [];
    const h = String(req.headers['x-session'] || '');
    if (tokenOk(h)) out.push(h);
    const c = parseCookies(req).sid;
    if (tokenOk(c) && c !== h) out.push(c);
    return out;
};
async function currentUser(req) {
    for (const raw of requestTokens(req)) {
        const r = await db.execute({
            sql: 'SELECT u.id, u.username, u.email FROM sessions s JOIN users u ON u.id = s.userId WHERE s.id = ? AND s.expiresAt > ?',
            args: [sha256(raw), Date.now()]
        });
        if (r.rows.length) return { ...r.rows[0], token: raw };
    }
    return null;
}
async function requireUser(req, res, next) {
    const u = await currentUser(req);
    if (!u) return res.status(401).json({ error: 'Please log in.' });
    req.user = u;
    next();
}
const crossPage = (req) => !!req.headers.origin && req.headers.origin !== `${req.protocol}://${req.headers.host}`;

// ---------- API ----------
app.get('/api/health', route(async (req, res) => {
    try { await db.execute('SELECT 1'); res.json({ ok: true }); } catch (e) { res.status(500).json({ ok: false }); }
}));

app.get('/api/me', route(requireUser), route(async (req, res) => {
    res.json({ username: String(req.user.username) });
}));

app.get('/api/check-username', route(async (req, res) => {
    if (limited('chk:' + ipOf(req), 120, 60 * 1000)) return res.status(429).json({ error: 'Too many requests' });
    const name = String(req.query.name || '').trim();
    const err = checkUsername(name);
    if (err) return res.json({ ok: false, message: err });
    const r = await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(username) = lower(?) LIMIT 1', args: [name] });
    res.json(r.rows.length ? { ok: false, message: 'This username is already taken.' } : { ok: true, message: 'Username is available.' });
}));

app.get('/api/check-email', route(async (req, res) => {
    if (limited('chk:' + ipOf(req), 120, 60 * 1000)) return res.status(429).json({ error: 'Too many requests' });
    const email = String(req.query.email || '').trim().toLowerCase();
    const err = await checkEmail(email);
    if (err) return res.json({ ok: false, message: err });
    // only format / domain is checked here: whether an email already has an account is never revealed
    res.json({ ok: true, message: 'Email looks good.' });
}));

app.post('/api/signup', route(async (req, res) => {
    const fail = (message, code = 400) => res.status(code).json({ error: message });
    try {
        const ip = ipOf(req);
        if (limited('signup:' + ip, 15, HOUR)) return fail('Too many attempts. Try again later.', 429);
        const b = req.body || {};
        const username = String(b.username || '').trim();
        const email = String(b.email || '').trim().toLowerCase();
        const password = String(b.password || '');
        if (!username || !email || !password) return fail('Please fill in all fields.');

        const uErr = checkUsername(username); if (uErr) return fail(uErr);
        const eErr = await checkEmail(email); if (eErr) return fail(eErr);
        if (b.ageConfirmed !== true) return fail('You must confirm that you are at least 13 years old.');

        // one account per day: per IP and per device cookie
        const now = Date.now();
        if (SIGNUP_COOLDOWN) {
            let wait = 0;
            const devLast = Number(parseCookies(req).ut_su) || 0;
            if (devLast && now - devLast < DAY) wait = Math.max(wait, DAY - (now - devLast));
            if (ip) {
                const a = await db.execute({ sql: 'SELECT MAX(createdAt) AS t FROM signup_log WHERE ip = ?', args: [ip] });
                const t1 = Number(a.rows[0] && a.rows[0].t) || 0;
                if (t1 && now - t1 < DAY) wait = Math.max(wait, DAY - (now - t1));
                const c = await db.execute({ sql: 'SELECT MAX(joinedAt) AS t FROM users WHERE lastIp = ?', args: [ip] });
                const t2 = Number(c.rows[0] && c.rows[0].t) || 0;
                if (t2 && now - t2 < DAY) wait = Math.max(wait, DAY - (now - t2));
            }
            if (wait > 0) {
                const h = Math.floor(wait / HOUR), m = Math.max(1, Math.ceil((wait % HOUR) / 60000));
                return fail(`Only one account can be created per day. Please try again in ${h > 0 ? h + 'h ' : ''}${m}m.`, 429);
            }
        }

        if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(username) = lower(?) LIMIT 1', args: [username] })).rows.length) return fail('This username is already taken.');
        // neutral message: does not confirm that an account with this email exists
        if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(email) = ? LIMIT 1', args: [email] })).rows.length) return fail('We could not create an account with these details. Check them and try again, or log in if you already have an account.');

        const hash = await hashPassword(password);
        let newId;
        try {
            const ins = await db.execute({
                sql: "INSERT INTO users (username, email, password, passwordHash, lastIp, joinedAt) VALUES (?, ?, '', ?, ?, ?)",
                args: [username, email, hash, ip || null, now]
            });
            newId = Number(ins.lastInsertRowid);
        } catch (e) {
            if (String(e.message || e).toUpperCase().includes('UNIQUE')) return fail('This username is already taken.');
            throw e;
        }
        if (ip) await db.execute({ sql: 'INSERT INTO signup_log (ip, createdAt) VALUES (?, ?)', args: [ip, now] });
        setCookie(res, 'ut_su', String(now), DAY);
        const token = await startSession(res, newId);
        res.json({ username, ...(crossPage(req) ? { token } : {}) });
    } catch (e) {
        console.error('signup error:', e);
        fail('Server error during registration. Try again.', 500);
    }
}));

app.post('/api/login', route(async (req, res) => {
    try {
        const b = req.body || {};
        const id = String(b.id || b.username || '').trim(), password = String(b.password || '');
        const r = await authenticate(req, id, password);
        if (!r.user) return res.status(r.status).json(r.body);
        const u = r.user, ip = ipOf(req);
        if (ip) { try { await db.execute({ sql: 'UPDATE users SET lastIp = ? WHERE id = ?', args: [ip, Number(u.id)] }); } catch (e) {} }
        const token = await startSession(res, u.id);
        res.json({ username: String(u.username), ...(crossPage(req) ? { token } : {}) });
    } catch (e) {
        console.error('login error:', e);
        res.status(500).json({ error: 'Server error. Try again later.' });
    }
}));

app.post('/api/logout', route(async (req, res) => {
    try {
        for (const raw of requestTokens(req)) await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [sha256(raw)] });
    } catch (e) { console.error('logout error:', e); }
    clearCookie(res, 'sid');
    res.json({ ok: true });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// ---------- pages (only these files are served, never the server code) ----------
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.get(['/', '/login.html'], (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/starfall.html', (req, res) => res.sendFile(path.join(__dirname, 'starfall.html')));

// errors from any route become JSON instead of a crash / HTML page
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const status = err.status || err.statusCode || 500;
    if (status < 500) return res.status(status).json({ error: 'Bad request.' });
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Server error. Try again later.' });
});

initDB()
    .catch((err) => console.error('Database initialization error:', err))
    .finally(() => app.listen(PORT, () => console.log(`Server is running on port ${PORT}`)));
