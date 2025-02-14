const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

// Initialize the app
const app = express();
app.use(express.json());

// Define the Mongoose Schema for Student
const studentSchema = new mongoose.Schema({
  studentId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

// Create the Student model
const Student = mongoose.model('Student', studentSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// 1. Student Registration (POST)
app.post('/students/register', async (req, res) => {
  const { studentId, name, email, password } = req.body;

  if (!studentId || !name || !email || !password) {
    return res.status(400).send('All fields are required');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newStudent = new Student({ studentId, name, email, password: hashedPassword });

    await newStudent.save();
    res.status(201).send('Student Registered');
  } catch (err) {
    res.status(500).send('Error registering student');
  }
});

// 2. Student Login (POST)
app.post('/students/login', async (req, res) => {
  const { studentId, password } = req.body;

  try {
    const student = await Student.findOne({ studentId });
    if (!student) return res.status(401).send('Invalid credentials');

    const isMatch = await bcrypt.compare(password, student.password);
    if (!isMatch) return res.status(401).send('Invalid credentials');

    const token = jwt.sign({ studentId: student.studentId }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login success', token });
  } catch (err) {
    res.status(500).send('Error logging in');
  }
});

// 3. Student Search (GET)
app.get('/students/search', async (req, res) => {
  const { studentId } = req.query;

  if (!studentId) {
    return res.status(400).send('Student ID is required');
  }

  try {
    // Case-insensitive search
    const student = await Student.findOne({ studentId: { $regex: new RegExp(studentId, 'i') } });
    if (!student) return res.status(404).send('Student not found');

    res.json(student);
  } catch (err) {
    res.status(500).send('Error searching student');
  }
});


// 4. Student Profile Update (PUT)
app.put('/students/update', async (req, res) => {
  const { studentId, newData } = req.body;

  try {
    const student = await Student.findOneAndUpdate({ studentId }, newData, { new: true });
    if (!student) return res.status(404).send('Student not found');

    res.json({ message: 'Profile updated', student });
  } catch (err) {
    res.status(500).send('Error updating profile');
  }
});

// 5. Delete Student (DELETE)
app.delete('/students/delete', async (req, res) => {
  const { studentId } = req.body;

  try {
    const student = await Student.findOneAndDelete({ studentId });
    if (!student) return res.status(404).send('Student not found');

    res.send('Student deleted');
  } catch (err) {
    res.status(500).send('Error deleting student');
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
