
const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg'); // Используем pg для работы с PostgreSQL
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // Подключаем bcrypt для хеширования паролей
const session = require('express-session');
require('dotenv').config();

// Настройка сервера
const app = express();
const PORT = process.env.PORT || 3000;

// Подключение к PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Убедитесь, что в .env файле правильно указан DATABASE_URL
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, '../public')));

// Настройка сессий
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'default-secret', // Убедитесь, что секретный ключ скрыт в переменных окружения
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' }, // Устанавливайте secure в true, если используете HTTPS
  })
);

// Middleware для проверки авторизации
function authenticate(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login'); // Перенаправляем на страницу входа
  }
  next();
}

// Главная страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Страница входа
app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/my-account'); // Если пользователь уже авторизован, перенаправляем на /my-account
  }
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

// Страница аккаунта
app.get('/my-account', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/my-account.html'));
});

// Проверка авторизации
app.get('/check-auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: 'Необходимо войти в систему.' });
  }
  res.status(200).json({ user: req.session.user });
});

// Регистрация
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Валидация входных данных
  if (!email || !password) {
    return res.status(400).json({ message: 'Пожалуйста, укажите и email, и пароль.' });
  }

  try {
    // Проверка существования пользователя
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'Пользователь с таким email уже существует.' });
    }

    // Генерация токена подтверждения
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Хешируем пароль с использованием bcrypt
    const hashedPassword = await bcrypt.hash(password, 10); // 10 - это соль для bcrypt

    // Создание нового пользователя
    await pool.query(
      'INSERT INTO users (email, password, verified, verification_token) VALUES ($1, $2, $3, $4)',
      [email, hashedPassword, false, verificationToken]
    );

    // Отправка письма (опционально)
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER, // Используйте переменные окружения для конфиденциальных данных
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Подтверждение почты для Secubox',
      text: `Привет!\n\nПожалуйста, подтвердите ваш email, перейдя по следующей ссылке: \n\nhttp://localhost:3000/verify/${verificationToken}\n\nС уважением, команда Secubox.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Ошибка отправки письма:', error);
        return res.status(500).json({ message: 'Ошибка отправки письма', error: error.message });
      }
      console.log('Письмо отправлено:', info.response);
      res.redirect('/login'); // Перенаправляем на страницу входа
    });

  } catch (err) {
    console.error('Ошибка при регистрации:', err);
    res.status(500).json({ message: 'Ошибка при регистрации', error: err.message });
  }
  console.log('Регистрация пользователя:', { email, password });
});

// Вход пользователя
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Валидация входных данных
  if (!email || !password) {
    return res.status(400).json({ message: 'Пожалуйста, укажите email и пароль.' });
  }

  try {
    // Поиск пользователя по email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ message: 'Пользователь с таким email не найден.' });
    }

    // Проверка пароля с использованием bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Неверный пароль.' });
    }

    // Проверка статуса подтверждения email
    if (!user.verified) {
      return res.status(403).json({ message: 'Пожалуйста, подтвердите ваш email.' });
    }

    // Сохранение пользователя в сессии
    req.session.user = { id: user.id, email: user.email };
    res.redirect('/my-account'); // Перенаправляем на страницу аккаунта

  } catch (err) {
    console.error('Ошибка при входе:', err);
    res.status(500).json({ message: 'Ошибка при входе', error: err.message });
  }
});

// Подтверждение email
app.get('/verify/:token', async (req, res) => {
  const { token } = req.params;

  try {
    // Поиск пользователя по токену
    const result = await pool.query('SELECT * FROM users WHERE verification_token = $1', [token]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).sendFile(path.join(__dirname, '../public/verify-error.html')); // Страница ошибки
    }

    // Активация пользователя
    await pool.query(
      'UPDATE users SET verified = true, verification_token = NULL WHERE id = $1',
      [user.id]
    );

    res.sendFile(path.join(__dirname, '../public/verify-success.html')); // Страница успеха

  } catch (err) {
    console.error('Ошибка при подтверждении email:', err);
    res.status(500).sendFile(path.join(__dirname, '../public/verify-error.html')); // Страница ошибки
  }
});

// Выход пользователя
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Ошибка при выходе.' });
    }
    res.redirect('/'); // Перенаправляем на главную страницу
  });
});
    

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
});