// Starfall backend: signup, login, sessions (ported from the Unique Trading auth system).
// Env vars (Render -> Environment):
//   TURSO_URL, TURSO_TOKEN        database
//   SIGNUP_COOLDOWN=0             optional, turns off the "one account per day" rule (useful while testing)
//   SKIP_DNS=1                    optional, skips the e-mail domain DNS check
const express = require('express');
const path = require('path');
const fs = require('fs').promises;
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
    const run = async (sql) => {
        try { await db.execute(sql); }
        catch (e) {
            // Only ignore an ALTER TABLE that repeats an existing column. All other
            // database errors must fail startup instead of silently hiding corruption.
            if (/^ALTER TABLE\s+users\s+ADD COLUMN/i.test(sql) && /duplicate column name/i.test(String(e.message || e))) return;
            throw e;
        }
    };
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
            { sql: 'DROP TABLE IF EXISTS users_text_migration', args: [] },
            { sql: `CREATE TABLE users_text_migration (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT, password TEXT NOT NULL, passwordHash TEXT, joinedAt INTEGER, lastIp TEXT, avatarColor TEXT)`, args: [] },
            { sql: `INSERT INTO users_text_migration (id, username, email, password, passwordHash, joinedAt, lastIp, avatarColor) SELECT CAST(id AS TEXT), username, email, password, passwordHash, joinedAt, lastIp, avatarColor FROM users`, args: [] },
            { sql: 'DROP TABLE users', args: [] },
            { sql: 'ALTER TABLE users_text_migration RENAME TO users', args: [] }
        ], 'write');
    }
    await run(`CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, userId TEXT NOT NULL, createdAt INTEGER, expiresAt INTEGER)`);
    const sessionInfo = await db.execute('PRAGMA table_info(sessions)');
    const sessionUserId = sessionInfo.rows.find((c) => String(c.name) === 'userId');
    const sessionForeignKeys = await db.execute('PRAGMA foreign_key_list(sessions)');
    const sessionDefinition = await db.execute({
        sql: `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sessions'`, args: []
    });
    const sessionSql = String(sessionDefinition.rows[0]?.sql || '').toUpperCase();
    // Legacy deployments may still tie session IDs to the numeric users table or use
    // strict/foreign-key constraints. Rebuild without legacy constraints so text IDs
    // are valid, preserving all session rows.
    const rebuildSessions = !sessionUserId
        || String(sessionUserId.type || '').trim().toUpperCase() !== 'TEXT'
        || sessionForeignKeys.rows.length > 0
        || sessionSql.includes('STRICT');
    if (rebuildSessions) {
        await db.batch([
            { sql: 'DROP TABLE IF EXISTS sessions_text_migration', args: [] },
            { sql: 'CREATE TABLE sessions_text_migration (id TEXT PRIMARY KEY, userId TEXT NOT NULL, createdAt INTEGER, expiresAt INTEGER)', args: [] },
            { sql: 'INSERT INTO sessions_text_migration (id, userId, createdAt, expiresAt) SELECT CAST(id AS TEXT), CAST(userId AS TEXT), createdAt, expiresAt FROM sessions', args: [] },
            { sql: 'DROP TABLE sessions', args: [] },
            { sql: 'ALTER TABLE sessions_text_migration RENAME TO sessions', args: [] }
        ], 'write');
    }

    await run(`CREATE TABLE IF NOT EXISTS request_limits (k TEXT PRIMARY KEY, windowStart INTEGER NOT NULL, hits INTEGER NOT NULL)`);
    // Retire the old account lockout table; its long lockouts enabled account-lockout abuse.
    await db.execute('DROP TABLE IF EXISTS login_lockouts');
    await run(`CREATE TABLE IF NOT EXISTS signup_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, createdAt INTEGER)`);
    await run(`CREATE INDEX IF NOT EXISTS signup_log_ip_created ON signup_log (ip, createdAt)`);
    await run(`CREATE INDEX IF NOT EXISTS sessions_user ON sessions (userId)`);
    await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase ON users (username COLLATE NOCASE)');
    await db.execute({ sql: 'DELETE FROM sessions WHERE expiresAt < ?', args: [Date.now()] });
    // Signup IP records are only needed for the one-day cooldown. Keep a small buffer.
    await db.execute({ sql: 'DELETE FROM signup_log WHERE createdAt < ?', args: [Date.now() - 2 * DAY] });
    await db.execute({ sql: 'DELETE FROM request_limits WHERE windowStart < ?', args: [Date.now() - 2 * DAY] });
    console.log('Turso Database initialized successfully');
}
setInterval(() => {
    const now = Date.now(), cutoff = now - 2 * DAY;
    Promise.all([
        db.execute({ sql: 'DELETE FROM sessions WHERE expiresAt < ?', args: [now] }),
        db.execute({ sql: 'DELETE FROM signup_log WHERE createdAt < ?', args: [cutoff] }),
        db.execute({ sql: 'DELETE FROM request_limits WHERE windowStart < ?', args: [cutoff] })
    ]).catch((e) => console.error('Scheduled database cleanup failed:', e.message || e));
}, HOUR);

// ---------- small helpers ----------
const route = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);   // Express 4 does not catch async errors
const sha256 = (v) => crypto.createHash('sha256').update(String(v)).digest('hex');
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
    const secure = IS_SECURE ? '; Secure' : '';
    res.append('Set-Cookie', `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(maxAgeMs / 1000)}${secure}`);
}
const clearCookie = (res, name) => setCookie(res, name, '', 0);

// Shared, persistent rate limits work across server restarts and multiple instances.
// Keys are hashed before storage so raw IP addresses/usernames are not written to this table.
async function limited(key, max, windowMs) {
    const now = Date.now();
    const windowStart = Math.floor(now / windowMs) * windowMs;
    const storageKey = sha256(key);
    await db.execute({
        sql: `INSERT INTO request_limits (k, windowStart, hits) VALUES (?, ?, 1)
              ON CONFLICT(k) DO UPDATE SET
                windowStart = CASE WHEN request_limits.windowStart <> excluded.windowStart THEN excluded.windowStart ELSE request_limits.windowStart END,
                hits = CASE WHEN request_limits.windowStart <> excluded.windowStart THEN 1 ELSE request_limits.hits + 1 END`,
        args: [storageKey, windowStart]
    });
    const result = await db.execute({ sql: 'SELECT hits FROM request_limits WHERE k = ?', args: [storageKey] });
    return Number(result.rows[0]?.hits || 0) > max;
}

// Same-origin only: the frontend and cookie-authenticated API are served together.
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (req.method === 'OPTIONS') {
        if (!origin) return res.sendStatus(204);
        try {
            const u = new URL(origin);
            if (u.host === req.headers.host && u.protocol === (req.secure ? 'https:' : 'http:')) return res.sendStatus(204);
        } catch (e) {}
        return res.status(403).json({ error: 'Request blocked.' });
    }
    if (origin && req.method !== 'GET' && req.method !== 'HEAD') {
        let sameOrigin = false;
        try { const u = new URL(origin); sameOrigin = u.host === req.headers.host && u.protocol === (req.secure ? 'https:' : 'http:'); } catch (e) {}
        if (!sameOrigin) return res.status(403).json({ error: 'Request blocked.' });
    }
    next();
});
// ---------- security headers ----------
app.use((req, res, next) => {
    const nonce = crypto.randomBytes(18).toString('base64');
    res.locals.cspNonce = nonce;
    if (IS_SECURE) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self'; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`);
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

// Login throttling is short-lived and does not lock an account for hours. This prevents
// a third party from repeatedly locking another person's account by guessing its username.
const BAD_LOGIN = 'Incorrect username/email or password.';
// "username or email" + password. Returns { user } or { status, body }. Never reveals whether the account exists.
async function authenticate(req, id, password) {
    const ip = ipOf(req);
    if (await limited('login:' + ip, 20, 15 * 60 * 1000)) return { status: 429, body: { error: 'Too many attempts. Try again in a few minutes.' } };
    if (!id || !password) return { status: 400, body: { error: 'Please fill in all fields.' } };
    if (Buffer.byteLength(password, 'utf8') > 1024 || Buffer.byteLength(id, 'utf8') > 254) return { status: 400, body: { error: 'Invalid sign-in details.' } };
    const accountKey = sha256(String(id).trim().toLowerCase());
    if (await limited('login-account:' + ip + ':' + accountKey, 10, 15 * 60 * 1000)) return { status: 429, body: { error: 'Too many attempts for these sign-in details. Try again in 15 minutes.' } };
    const rs = await db.execute({ sql: 'SELECT * FROM users WHERE lower(username) = lower(?) OR lower(email) = lower(?) ORDER BY (lower(username) = lower(?)) DESC LIMIT 1', args: [id, id, id] });
    const u = rs.rows.length ? rs.rows[0] : null;
    const ok = u ? await verifyPassword(u, password) : (await checkHash(password, DUMMY_HASH), false); // same work either way
    if (!ok) return { status: 401, body: { error: BAD_LOGIN } };
    return { user: u };
}

// ---------- sessions ----------
// The browser holds a random 256-bit token in an HttpOnly cookie; the database stores only its SHA-256.
async function startSession(res, userId) {
    const raw = crypto.randomBytes(32).toString('hex'), now = Date.now();
    await db.execute({ sql: 'INSERT INTO sessions (id, userId, createdAt, expiresAt) VALUES (?, ?, ?, ?)', args: [sha256(raw), String(userId), now, now + SESSION_MS] });
    setCookie(res, 'sid', raw, SESSION_MS);
}
const requestTokens = (req) => {
    const cookie = parseCookies(req).sid;
    return /^[a-f0-9]{64}$/.test(String(cookie || '')) ? [cookie] : [];
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

// ---------- API ----------
app.get('/api/health', route(async (req, res) => {
    try { await db.execute('SELECT 1'); res.json({ ok: true }); } catch (e) { res.status(500).json({ ok: false }); }
}));

// The admin account alone can access the users database. Username checks are enforced server-side.
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
    const r = await db.execute('SELECT id, username, joinedAt FROM users ORDER BY id');
    res.json({
        total: r.rows.length,
        users: r.rows.map((x) => ({ id: String(x.id), username: String(x.username), joinedAt: Number(x.joinedAt) || 0 }))
    });
}));

app.get('/api/check-username', route(async (req, res) => {
    if (await limited('chk:' + ipOf(req), 120, 60 * 1000)) return res.status(429).json({ error: 'Too many requests' });
    const name = String(req.query.name || '').trim();
    const err = checkUsername(name);
    if (err) return res.json({ ok: false, message: err });
    const r = await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(username) = lower(?) LIMIT 1', args: [name] });
    res.json(r.rows.length ? { ok: false, message: 'This username is already taken.' } : { ok: true, message: 'Username is available.' });
}));

app.get('/api/check-email', route(async (req, res) => {
    if (await limited('chk:' + ipOf(req), 120, 60 * 1000)) return res.status(429).json({ error: 'Too many requests' });
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
        if (await limited('signup:' + ip, 15, HOUR)) return fail('Too many attempts. Try again later.', 429);
        const b = req.body || {};
        const username = String(b.username || '').trim();
        const email = String(b.email || '').trim().toLowerCase();
        const password = String(b.password || '');
        if (!username || !email || !password) return fail('Please fill in all fields.');
        if (Buffer.byteLength(password, 'utf8') < 8) return fail('Password must be at least 8 bytes long.');
        if (Buffer.byteLength(password, 'utf8') > 1024) return fail('Password is too long (maximum 1024 bytes).');

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
        await startSession(res, newId);
        res.json({ username });
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
        await startSession(res, u.id);
        res.json({ username: String(u.username) });
    } catch (e) {
        console.error('login error:', e);
        res.status(500).json({ error: 'Server error. Try again later.' });
    }
}));

// Change password after verifying the current password; other sessions are revoked.
app.post('/api/change-password', route(requireUser), route(async (req, res) => {
    if (await limited('password-change:' + String(req.user.id), 5, 15 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
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
    const r = id ? await db.execute({ sql: 'SELECT id, username, joinedAt FROM users WHERE id = ?', args: [id] }) : { rows: [] };
    if (!r.rows.length) return res.status(404).json({ error: 'User not found.' });
    const s = await db.execute({ sql: 'SELECT COUNT(*) AS n FROM sessions WHERE userId = ? AND expiresAt > ?', args: [id, Date.now()] });
    const u = r.rows[0];
    res.json({
        id: String(u.id), username: String(u.username),
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
app.use('/assets', express.static(path.join(__dirname, 'assets'), { fallthrough: false, index: false }));
async function sendHtml(req, res, fileName) {
    const html = await fs.readFile(path.join(__dirname, fileName), 'utf8');
    const nonce = res.locals.cspNonce;
    const secured = html.replace(/<script(\s|>)/gi, (m, after) => `<script nonce=\"${nonce}\"${after}`);
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(secured);
}
app.get(['/', '/login.html'], route((req, res) => sendHtml(req, res, 'login.html')));
app.get('/starfall.html', route((req, res) => sendHtml(req, res, 'starfall.html')));

// errors from any route become JSON instead of a crash / HTML page
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    const status = err.status || err.statusCode || 500;
    if (status < 500) return res.status(status).json({ error: 'Bad request.' });
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Server error. Try again later.' });
});

initDB()
    .then(() => app.listen(PORT, () => console.log(`Server is running on port ${PORT}`)))
    .catch((err) => {
        console.error('Database initialization failed; refusing to start with an unusable database:', err);
        process.exit(1);
    });
