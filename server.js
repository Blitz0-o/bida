const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

// 1. Kết nối MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/tournament_db', {
}).then(() => console.log("✅ Đã kết nối MongoDB"))
  .catch(err => console.error(err));

// 2. Tạo Schema + Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

// Hash mật khẩu trước khi lưu
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const saltRounds = 10;
  this.password = await bcrypt.hash(this.password, saltRounds);
  next();
});

// So sánh mật khẩu khi đăng nhập
userSchema.methods.comparePassword = function (plainPassword) {
  return bcrypt.compare(plainPassword, this.password);
};

const User = mongoose.model('User', userSchema);

// 3. API đăng ký
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Kiểm tra trùng username
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "❌ Username đã tồn tại" });
    }

    // Tạo user mới (mật khẩu sẽ tự hash nhờ middleware)
    const newUser = new User({ username, password });
    await newUser.save();

    res.json({ message: "✅ Đăng ký thành công" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. API đăng nhập
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Tìm user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "❌ Sai username hoặc password" });
    }

    // Kiểm tra mật khẩu
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: "❌ Sai username hoặc password" });
    }

    res.json({ message: "✅ Đăng nhập thành công" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 5. Chạy server
app.listen(3000, () => {
  console.log("🚀 Server chạy tại http://localhost:3000");
});
