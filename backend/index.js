const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'your_password', // Thay bằng mật khẩu MySQL
  database: 'slearn_db',
});

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token required' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Đăng ký
app.post('/api/register', async (req, res) => {
  const { username, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await db.query('INSERT INTO Users (username, email, password, role) VALUES (?, ?, ?, ?)', 
      [username, email, hashedPassword, role]);
    res.status(201).json({ message: 'User registered' });
  } catch (error) {
    res.status(500).json({ message: 'Error registering' });
  }
});

// Đăng nhập
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const [users] = await db.query('SELECT * FROM Users WHERE email = ?', [email]);
  const user = users[0];
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Tạo khóa học
app.post('/api/courses', authenticateToken, async (req, res) => {
  if (req.user.role !== 'instructor') return res.status(403).json({ message: 'Access denied' });
  const { title, description, max_students } = req.body;
  try {
    await db.query(
      'INSERT INTO Courses (title, description, instructor_id, max_students) VALUES (?, ?, ?, ?)',
      [title, description, req.user.id, max_students]
    );
    res.status(201).json({ message: 'Course created' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating course' });
  }
});

// Lấy danh sách khóa học
app.get('/api/courses', async (req, res) => {
  const [courses] = await db.query('SELECT * FROM Courses');
  res.json(courses);
});

// Đăng ký khóa học
app.post('/api/enrollments', authenticateToken, async (req, res) => {
  const { course_id } = req.body;
  try {
    await db.query('INSERT INTO Enrollments (user_id, course_id) VALUES (?, ?)', [req.user.id, course_id]);
    res.status(201).json({ message: 'Enrolled successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error enrolling' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));