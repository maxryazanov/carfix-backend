require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require("path");

const app = express();
const PORT = 3001;
const SECRET_KEY = process.env.SECRET_KEY || '5604f0521101633c08916e56e8834a9617f9149b3051241a2185d1ad12a2f0be';

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, "public"))); // Папка с фронтендом

// Подключение к базе данных
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error(err.message);
    } else {
        console.log('Connected to SQLite database.');
    }
});

// Создание таблиц
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS cars (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        photo TEXT,
        make TEXT NOT NULL,
        year INTEGER NOT NULL,
        vin TEXT UNIQUE NOT NULL,
        plate TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS maintenance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        car_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        mileage INTEGER NOT NULL,
        details TEXT NOT NULL,
        FOREIGN KEY (car_id) REFERENCES cars(id) ON DELETE CASCADE
    )`);
});

// CSP для безопасности
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'");
    next();
});

// Главная страница
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Middleware для проверки токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: "Нет токена, доступ запрещен" });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Неверный токен" });
        }
        req.userId = user.userId;
        next();
    });
}

// Регистрация пользователя
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: err.message });
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err) => {
            if (err) return res.status(400).json({ error: err.message });
            res.json({ message: 'User registered successfully' });
        });
    });
});

// Авторизация пользователя
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid username or password' });

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY, { expiresIn: "1h" });
                res.json({ token });
            } else {
                res.status(400).json({ error: 'Invalid username or password' });
            }
        });
    });
});

// Функция выхода (на клиенте просто удаляется токен)
app.post('/logout', (req, res) => {
    res.json({ message: 'Logout successful' });
});

// Добавление машины
app.post('/cars', authenticateToken, (req, res) => {
    console.log("Данные из запроса:", req.body);
    
    const { make, year, vin, plate, photo } = req.body;
    if (!make || !year || !vin || !plate) {
        return res.status(400).json({ message: "Все поля обязательны" });
    }

    db.run("INSERT INTO cars (user_id, photo, make, year, vin, plate) VALUES (?, ?, ?, ?, ?, ?)", 
        [req.userId, photo, make, year, vin, plate], 
        function(err) {
            if (err) {
                console.error("Ошибка при добавлении в базу:", err);
                return res.status(500).json({ message: "Ошибка сервера: VIN уже существует" });
            }
            res.json({ id: this.lastID, message: "Машина добавлена" });
        }
    );
});

// Получение списка машин
app.get('/cars', authenticateToken, (req, res) => {
    db.all('SELECT * FROM cars WHERE user_id = ?', [req.userId], (err, cars) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(cars);
    });
});

// Обновление данных машины
app.put('/cars/:id', authenticateToken, (req, res) => {
    const { photo, make, year, vin, plate } = req.body;
    db.run('UPDATE cars SET photo = ?, make = ?, year = ?, vin = ?, plate = ? WHERE id = ? AND user_id = ?',
        [photo, make, year, vin, plate, req.params.id, req.userId],
        function (err) {
            if (err) return res.status(400).json({ error: err.message });
            res.json({ message: 'Car updated successfully' });
        }
    );
});

// Удаление машины
app.delete('/cars/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM cars WHERE id = ? AND user_id = ?', [req.params.id, req.userId], function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ message: 'Car deleted successfully' });
    });
});

// Добавление записи о ТО
app.post('/maintenance', authenticateToken, (req, res) => {
    const { car_id, date, mileage, details } = req.body;
    if (!car_id || !date || !mileage || !details) {
        return res.status(400).json({ message: "Все поля обязательны" });
    }

    db.run("INSERT INTO maintenance (car_id, date, mileage, details) VALUES (?, ?, ?, ?)",
        [car_id, date, mileage, details], 
        function(err) {
            if (err) {
                console.error("Ошибка при добавлении ТО:", err);
                return res.status(500).json({ message: "Ошибка сервера" });
            }
            res.json({ id: this.lastID, message: "Запись о ТО добавлена" });
        }
    );
});

// Получение записей о ТО для конкретной машины
app.get('/maintenance', authenticateToken, (req, res) => {
    const carId = req.query.car_id;

    db.all('SELECT * FROM maintenance WHERE car_id = ?', [carId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
}); 

// Удаление записи ТО
app.delete('/maintenance/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM maintenance WHERE id = ?', [req.params.id], function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ message: 'Maintenance record deleted' });
    });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
