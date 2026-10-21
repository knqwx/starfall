const express = require('express');
const path = require('path');
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

// Роут для проверки доступности юзернейма
app.get('/api/check-username', async (req, res) => {
    const { username } = req.query;
    try {
        const result = await db.execute({
            sql: 'SELECT * FROM users WHERE username = ?',
            args: [username]
        });
        if (result.rows.length > 0) {
            res.json({ available: false });
        } else {
            res.json({ available: true });
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Регистрация (выдает ID автоматически с 1 и далее)
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        await db.execute({
            sql: 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            args: [username, email || null, password]
        });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(400).json({ success: false, error: 'User or email already exists' });
    }
});

// Вход в систему
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await db.execute({
            sql: 'SELECT * FROM users WHERE username = ? AND password = ?',
            args: [username, password]
        });
        if (result.rows.length > 0) {
            res.json({ success: true, user: result.rows[0] });
        } else {
            res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

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
