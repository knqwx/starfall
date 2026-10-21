const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');

const app = express();
const PORT = process.env.PORT || 10000;

// Подключение к Turso через Environment Variables с Render
const db = createClient({
    url: process.env.TURSO_URL,
    authToken: process.env.TURSO_TOKEN,
});

// Инициализация базы данных (создание таблицы с ID от 1 до бесконечности)
async function initDB() {
    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                password TEXT NOT NULL
            )
        `);
        console.log('Turso Database initialized successfully');
    } catch (err) {
        console.error('Database initialization error:', err);
    }
}
initDB();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// --- Пароли: scrypt-хеш (формат "scrypt$salt$hash"), старые открытые пароли тоже читаются ---
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
    if (typeof stored === 'string' && stored.startsWith('scrypt$')) {
        const [, salt, hash] = stored.split('$');
        const test = crypto.scryptSync(password, salt, 64);
        const real = Buffer.from(hash, 'hex');
        return real.length === test.length && crypto.timingSafeEqual(real, test);
    }
    return stored === password; // старые аккаунты с паролем в открытом виде
}

// Роут для проверки доступности юзернейма
async function checkUsername(req, res) {
    const username = String(req.query.username || '').trim();
    try {
        const result = await db.execute({
            sql: 'SELECT id FROM users WHERE username = ?',
            args: [username]
        });
        res.json({ available: result.rows.length === 0 });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
}

// Регистрация (выдает ID автоматически с 1 и далее)
async function register(req, res) {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim();
    const password = String(req.body.password || '');

    if (!username || !password) {
        return res.status(400).json({ success: false, error: 'Username and password are required' });
    }

    try {
        const existing = await db.execute({
            sql: 'SELECT id FROM users WHERE username = ?',
            args: [username]
        });
        if (existing.rows.length > 0) {
            return res.status(409).json({ success: false, error: 'Username already exists' });
        }

        await db.execute({
            sql: 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            args: [username, email || null, hashPassword(password)]
        });
        res.json({ success: true });
    } catch (err) {
        console.error('Registration error:', err);
        if (String(err.message || err).includes('UNIQUE')) {
            return res.status(409).json({ success: false, error: 'Username already exists' });
        }
        res.status(500).json({ success: false, error: 'Server error' });
    }
}

// Вход в систему
async function login(req, res) {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    try {
        const result = await db.execute({
            sql: 'SELECT id, username, email, password FROM users WHERE username = ?',
            args: [username]
        });
        const row = result.rows[0];
        if (row && verifyPassword(password, row.password)) {
            res.json({ success: true, user: { id: row.id, username: row.username, email: row.email } });
        } else {
            res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ success: false, error: 'Server error' });
    }
}

// login.html использует /api/auth/*; старые пути оставлены для совместимости
app.get(['/api/auth/check-username', '/api/check-username'], checkUsername);
app.post(['/api/auth/register', '/api/register'], register);
app.post(['/api/auth/login', '/api/login'], login);

// Отдаем login.html при заходе на главный адрес
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/starfall.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'starfall.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
