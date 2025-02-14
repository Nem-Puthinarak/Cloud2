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
  
const savedStudent = await newStudent.save();
console.log('Registered Student:', {
  studentId: savedStudent.studentId,
  passwordHash: savedStudent.password
});
});

// 2. Student Login (POST)
app.post('/students/login', async (req, res) => {
  const { studentId: rawStudentId, password: rawPassword } = req.body;

  try {
    // 1. Input Validation and Sanitization
    const studentId = String(rawStudentId).trim();
    const password = String(rawPassword).trim();

    if (!studentId || !password) {
      return res.status(400).json({
        success: false,
        error: "Student ID and password are required"
      });
    }

    // 2. Student Lookup with Detailed Logging
    console.log(`[LOGIN ATTEMPT] Student ID: ${studentId}`);
    const student = await Student.findOne({ studentId }).select('+password');

    if (!student) {
      console.log(`[LOGIN FAIL] No student found for ID: ${studentId}`);
      return res.status(401).json({
        success: false,
        error: "Invalid credentials"
      });
    }

    // 3. Password Verification with Bcrypt
    console.log(`[DEBUG] Comparing password for: ${studentId}`);
    const isMatch = await bcrypt.compare(password, student.password)
      .catch(err => {
        console.error(`[BCRYPT ERROR] ${err.message}`);
        throw new Error('Password comparison failed');
      });

    if (!isMatch) {
      console.log(`[LOGIN FAIL] Password mismatch for: ${studentId}`);
      return res.status(401).json({
        success: false,
        error: "Invalid credentials"
      });
    }

    // 4. JWT Token Generation
    const tokenPayload = {
      studentId: student.studentId,
      role: 'student'
    };

    const token = jwt.sign(
      tokenPayload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 5. Secure Response
    console.log(`[LOGIN SUCCESS] ${studentId}`);
    res.json({
      success: true,
      message: 'Authentication successful',
      token,
      student: {
        studentId: student.studentId,
        name: student.name,
        email: student.email
      }
    });

  } catch (err) {
    console.error(`[LOGIN ERROR] ${err.message}`);
    res.status(500).json({
      success: false,
      error: process.env.NODE_ENV === 'development' 
        ? err.message 
        : 'Server error during authentication'
    });
  }
});
// 3. Student Search (GET)
app.get('/students/search', async (req, res) => {
  const { studentId } = req.query;

  try {
    const student = await Student.findOne({ studentId });
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
