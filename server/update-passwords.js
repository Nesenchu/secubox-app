const bcrypt = require('bcrypt');
const { Pool } = require('pg');

// Подключение к базе данных
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function updatePasswords() {
  try {
    // Получаем всех пользователей
    const result = await pool.query('SELECT id, password FROM users');
    const users = result.rows;

    for (const user of users) {
      // Проверяем, является ли пароль захешированным
      if (!user.password.startsWith('$2b$')) {
        console.log(`Обновление пароля для пользователя с ID ${user.id}`);
        const hashedPassword = await bcrypt.hash(user.password, 10); // Хешируем пароль
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, user.id]);
      }
    }

    console.log('Все пароли обновлены.');
  } catch (err) {
    console.error('Ошибка при обновлении паролей:', err);
  } finally {
    await pool.end();
  }
}

updatePasswords();