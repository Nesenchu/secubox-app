const mongoose = require('mongoose');

// Создание схемы для пользователя
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true, // Почта должна быть уникальной
  },
  password: {
    type: String,
    required: true,
  },
  verified: {
    type: Boolean,
    default: false, // Пользователь должен подтвердить email
  },
  verificationToken: {
    type: String, // Токен для подтверждения почты
  }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
