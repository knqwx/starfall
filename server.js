const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 10000;

// Раздаем статические файлы (включая папки assets, стили и т.д.)
app.use(express.static(path.join(__dirname)));

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Страница starfall.html, на которую перекидывает при регистрации
app.get('/starfall.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'starfall.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
