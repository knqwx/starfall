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
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT,
        password TEXT NOT NULL,
        passwordHash TEXT,
        joinedAt INTEGER,
        lastIp TEXT,
        avatarColor TEXT
    )`);
    for (const col of ['passwordHash TEXT', 'joinedAt INTEGER', 'lastIp TEXT', 'avatarColor TEXT']) await run(`ALTER TABLE users ADD COLUMN ${col}`);

    // Migrate any legacy non-TEXT primary-key IDs to TEXT so IDs may contain letters.
    const userInfo = await db.execute('PRAGMA table_info(users)');
    const idColumn = userInfo.rows.find((c) => String(c.name) === 'id');
    if (idColumn && String(idColumn.type || '').trim().toUpperCase() !== 'TEXT') {
        // Rebuild any non-TEXT ID schema (including INTEGER PRIMARY KEY/AUTOINCREMENT).
        // Dropping a stale temp table also recovers cleanly from an interrupted prior migration.
        await db.batch([
            { sql: 'DROP TABLE IF EXISTS users_text_migration' },
            { sql: `CREATE TABLE users_text_migration (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT, password TEXT NOT NULL, passwordHash TEXT, joinedAt INTEGER, lastIp TEXT, avatarColor TEXT)` },
            { sql: `INSERT INTO users_text_migration (id, username, email, password, passwordHash, joinedAt, lastIp, avatarColor) SELECT CAST(id AS TEXT), username, email, password, passwordHash, joinedAt, lastIp, avatarColor FROM users` },
            { sql: 'DROP TABLE users' },
            { sql: 'ALTER TABLE users_text_migration RENAME TO users' }
        ], 'write');
    }
    await run(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, userId TEXT NOT NULL, createdAt INTEGER, expiresAt INTEGER)`);
    const sessionInfo = await db.execute('PRAGMA table_info(sessions)');
    const sessionUserId = sessionInfo.rows.find((c) => String(c.name) === 'userId');
    if (sessionUserId && String(sessionUserId.type || '').toUpperCase() !== 'TEXT') {
        await db.batch([
            { sql: `CREATE TABLE sessions_text_migration (id TEXT PRIMARY KEY, userId TEXT NOT NULL, createdAt INTEGER, expiresAt INTEGER)` },
            { sql: `INSERT INTO sessions_text_migration (id, userId, createdAt, expiresAt) SELECT id, CAST(userId AS TEXT), createdAt, expiresAt FROM sessions` },
            { sql: 'DROP TABLE sessions' },
            { sql: 'ALTER TABLE sessions_text_migration RENAME TO sessions' }
        ], 'write');
    }
    // Canonicalize account ID 3 to 'knqw' on startup, preserving sessions.
    // If ID 'knqw' is already occupied by a different account, move that account to a fresh ID first.
    // If ID 3 no longer exists, retain compatibility by canonicalizing the reserved knqw username.
    const idThreeResult = await db.execute({ sql: 'SELECT id, username FROM users WHERE id = ? LIMIT 1', args: ['3'] });
    const namedAdminResult = idThreeResult.rows.length
        ? { rows: [] }
        : await db.execute({ sql: 'SELECT id, username FROM users WHERE lower(username) = ? LIMIT 1', args: ['knqw'] });
    const canonicalAccount = idThreeResult.rows[0] || namedAdminResult.rows[0];
    if (canonicalAccount && String(canonicalAccount.id) !== 'knqw') {
        const oldCanonicalId = String(canonicalAccount.id);
        const collisionResult = await db.execute({ sql: 'SELECT id FROM users WHERE id = ? LIMIT 1', args: ['knqw'] });
        const migration = [];
        if (collisionResult.rows.length && String(collisionResult.rows[0].id) !== oldCanonicalId) {
            let replacementId = String(Date.now()) + String(crypto.randomInt(100, 1000));
            while ((await db.execute({ sql: 'SELECT 1 FROM users WHERE id = ?', args: [replacementId] })).rows.length) {
                replacementId = String(Date.now()) + String(crypto.randomInt(100, 1000));
            }
            migration.push({ sql: 'UPDATE users SET id = ? WHERE id = ?', args: [replacementId, 'knqw'] });
            migration.push({ sql: 'UPDATE sessions SET userId = ? WHERE userId = ?', args: [replacementId, 'knqw'] });
        }
        migration.push({ sql: 'UPDATE users SET id = ? WHERE id = ?', args: ['knqw', oldCanonicalId] });
        migration.push({ sql: 'UPDATE sessions SET userId = ? WHERE userId = ?', args: ['knqw', oldCanonicalId] });
        await db.batch(migration, 'write');
        console.log(`Canonicalized account ID ${oldCanonicalId} to 'knqw'.`);
    }

    await run(`CREATE TABLE IF NOT EXISTS login_lockouts (k TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, level INTEGER NOT NULL DEFAULT 0, lockedUntil INTEGER NOT NULL DEFAULT 0, lastFailAt INTEGER NOT NULL DEFAULT 0)`);
    await run(`CREATE TABLE IF NOT EXISTS signup_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, createdAt INTEGER)`);
    await run(`CREATE INDEX IF NOT EXISTS sessions_user ON sessions (userId)`);
    try { await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase ON users (username COLLATE NOCASE)'); } catch (e) { console.warn('Could not create case-insensitive username index; check for existing case-duplicate usernames.'); }
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
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
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
    'security', 'billing', 'verify', 'verified', 'starfall', 'knqw', 'null', 'undefined', 'anonymous', 'sysadmin', 'superuser', 'webmaster', 'contact', 'info', 'abuse', 'postmaster', 'noreply']);
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
// Usernames are ASCII English letters, digits, and underscores only, maximum 30 bytes.
const MAX_USERNAME_BYTES = 30;
function checkUsername(name) {
    if (!name) return 'Please enter a username.';
    if (Buffer.byteLength(name, 'utf8') > MAX_USERNAME_BYTES) return 'Username is too long. Maximum size is 30 bytes.';
    if (!/^[A-Za-z0-9_]+$/.test(name)) return 'Usernames can only contain English letters, numbers, and underscores.';
    if (isReservedUsername(name)) return 'This username is reserved. Please choose another one.';
    return '';
}

// ---------- passwords (scrypt, built into Node: no extra packages) ----------
const scrypt = (pw, salt) => new Promise((resolve, reject) => crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? reject(e) : resolve(k))));
const AVATAR_COLORS = ['#7c3aed', '#2563eb', '#0891b2', '#059669', '#ca8a04', '#ea580c', '#db2777', '#4f46e5', '#0d9488', '#9333ea'];
const randomAvatarColor = () => AVATAR_COLORS[crypto.randomInt(AVATAR_COLORS.length)];
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
        if (ok) await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '' WHERE id = ?", args: [await hashPassword(password), String(u.id)] });
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
    await db.execute({ sql: 'INSERT INTO sessions (id, userId, createdAt, expiresAt) VALUES (?, ?, ?, ?)', args: [sha256(raw), String(userId), now, now + SESSION_MS] });
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
            sql: 'SELECT u.id, u.username, u.email, u.joinedAt, u.avatarColor FROM sessions s JOIN users u ON u.id = s.userId WHERE s.id = ? AND s.expiresAt > ?',
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

// The only account allowed to see the users database. Usernames are unique ignoring case and "knqw" is reserved, so nobody else can register it.
const ADMIN_USERNAME = 'knqw';
const isAdminUser = (u) => String(u && u.username || '').toLowerCase() === ADMIN_USERNAME;

app.get('/api/me', route(requireUser), route(async (req, res) => {
    const u = req.user;
    res.json({
        username: String(u.username),
        email: u.email ? String(u.email) : '',
        joinedAt: Number(u.joinedAt) || 0,
        id: String(u.id),
        isAdmin: isAdminUser(u),
        avatarColor: (typeof u.avatarColor === 'string' && /^#[0-9a-f]{6}$/i.test(u.avatarColor)) ? u.avatarColor : await (async () => { const color = randomAvatarColor(); await db.execute({ sql: 'UPDATE users SET avatarColor = ? WHERE id = ?', args: [color, String(u.id)] }); return color; })()
    });
}));

// Users database: checked on the server, so hiding/showing the button in the page is only cosmetic. Never returns passwords or hashes.
app.get('/api/admin/users', route(requireUser), route(async (req, res) => {
    if (!isAdminUser(req.user)) return res.status(403).json({ error: 'Not allowed.' });
    const r = await db.execute('SELECT id, username, email, joinedAt FROM users ORDER BY id');
    res.json({
        total: r.rows.length,
        users: r.rows.map((x) => ({ id: String(x.id), username: String(x.username), email: x.email ? String(x.email) : '', joinedAt: Number(x.joinedAt) || 0 }))
    });
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
        let newId = String(Date.now()) + String(crypto.randomInt(100, 1000));
        while ((await db.execute({ sql: 'SELECT 1 FROM users WHERE id = ?', args: [newId] })).rows.length) newId = String(Date.now()) + String(crypto.randomInt(100, 1000));
        try {
            await db.execute({
                sql: "INSERT INTO users (id, username, email, password, passwordHash, lastIp, joinedAt, avatarColor) VALUES (?, ?, ?, '', ?, ?, ?, ?)",
                args: [newId, username, email, hash, ip || null, now, randomAvatarColor()]
            });
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
        if (ip) { try { await db.execute({ sql: 'UPDATE users SET lastIp = ? WHERE id = ?', args: [ip, String(u.id)] }); } catch (e) {} }
        const token = await startSession(res, u.id);
        res.json({ username: String(u.username), ...(crossPage(req) ? { token } : {}) });
    } catch (e) {
        console.error('login error:', e);
        res.status(500).json({ error: 'Server error. Try again later.' });
    }
}));

// Change password after verifying the current password; other sessions are revoked.
app.post('/api/change-password', route(requireUser), route(async (req, res) => {
    if (limited('password-change:' + String(req.user.id), 5, 15 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const currentPassword = String(b.currentPassword || '');
    const newPassword = String(b.newPassword || '');
    const confirmPassword = String(b.confirmPassword || '');
    if (!currentPassword || !newPassword || !confirmPassword) return res.status(400).json({ error: 'Fill in all password fields.' });
    if (Buffer.byteLength(newPassword, 'utf8') < 8) return res.status(400).json({ error: 'New password must be at least 8 bytes long.' });
    if (Buffer.byteLength(newPassword, 'utf8') > 1024) return res.status(400).json({ error: 'New password is too long (maximum 1024 bytes).' });
    if (newPassword !== confirmPassword) return res.status(400).json({ error: 'New passwords do not match.' });
    const row = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [String(req.user.id)] });
    if (!row.rows.length || !(await verifyPassword(row.rows[0], currentPassword))) return res.status(400).json({ error: 'Current password is incorrect.' });
    const hash = await hashPassword(newPassword);
    await db.execute({ sql: "UPDATE users SET passwordHash = ?, password = '' WHERE id = ?", args: [hash, String(req.user.id)] });
    const currentTokenHash = sha256(req.user.token);
    await db.execute({ sql: 'DELETE FROM sessions WHERE userId = ? AND id <> ?', args: [String(req.user.id), currentTokenHash] });
    res.json({ ok: true, message: 'Password changed. Other sessions have been signed out.' });
}));

app.post('/api/logout', route(async (req, res) => {
    try {
        for (const raw of requestTokens(req)) await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [sha256(raw)] });
    } catch (e) { console.error('logout error:', e); }
    clearCookie(res, 'sid');
    res.json({ ok: true });
}));

const parseUserId = (s) => {
    const value = String(s == null ? '' : s).trim();
    return /^[A-Za-z0-9_-]{1,32}$/.test(value) ? value : '';
};

// One account's profile, as seen by the admin.
app.get('/api/admin/users/:id', route(requireUser), route(async (req, res) => {
    if (!isAdminUser(req.user)) return res.status(403).json({ error: 'Not allowed.' });
    const id = parseUserId(req.params.id);
    const r = id ? await db.execute({ sql: 'SELECT id, username, email, joinedAt FROM users WHERE id = ?', args: [id] }) : { rows: [] };
    if (!r.rows.length) return res.status(404).json({ error: 'User not found.' });
    const s = await db.execute({ sql: 'SELECT COUNT(*) AS n FROM sessions WHERE userId = ? AND expiresAt > ?', args: [id, Date.now()] });
    const u = r.rows[0];
    res.json({
        id: String(u.id), username: String(u.username), email: u.email ? String(u.email) : '',
        joinedAt: Number(u.joinedAt) || 0, activeSessions: Number(s.rows[0].n) || 0,
        isSelf: String(u.id) === String(req.user.id),
        isAdmin: isAdminUser(u)
    });
}));


// Permanently deletes an account and signs it out everywhere. The admin cannot delete their own account here.
app.delete('/api/admin/users/:id', route(requireUser), route(async (req, res) => {
    if (!isAdminUser(req.user)) return res.status(403).json({ error: 'Not allowed.' });
    const id = parseUserId(req.params.id);
    const r = id ? await db.execute({ sql: 'SELECT id, username FROM users WHERE id = ?', args: [id] }) : { rows: [] };
    if (!r.rows.length) return res.status(404).json({ error: 'User not found.' });
    const target = r.rows[0];
    if (String(target.id) === String(req.user.id) || isAdminUser(target)) return res.status(400).json({ error: 'This account cannot be deleted here.' });
    await db.batch([
        { sql: 'DELETE FROM sessions WHERE userId = ?', args: [id] },
        { sql: 'DELETE FROM users WHERE id = ?', args: [id] }
    ], 'write');
    console.log(`admin ${req.user.username} deleted account #${id} (${target.username})`);
    res.json({ ok: true, deleted: String(target.username) });
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
