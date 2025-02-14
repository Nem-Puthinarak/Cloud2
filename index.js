const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

// Initialize Express app
const app = express();

// Security middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// Database Configuration
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  }
};

// Student Schema
const studentSchema = new mongoose.Schema({
  studentId: {
    type: String,
    required: [true, 'Student ID is required'],
    unique: true,
    trim: true,
    index: true
  },
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Invalid email format']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    select: false
  }
});

// Password hashing middleware
studentSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

const Student = mongoose.model('Student', studentSchema);

// Authentication Middleware
const authenticate = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const student = await Student.findById(decoded.id).select('-password');
    
    if (!student) {
      return res.status(401).json({
        success: false,
        error: 'Student not found'
      });
    }

    req.student = student;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired token'
    });
  }
};

// Routes
// Register Student
app.post('/api/v1/students/register', async (req, res) => {
  try {
    const { studentId, name, email, password } = req.body;

    // Validation
    if (!studentId || !name || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'All fields are required'
      });
    }

    // Check for existing student
    const existingStudent = await Student.findOne({ 
      $or: [{ studentId }, { email }]
    });

    if (existingStudent) {
      return res.status(409).json({
        success: false,
        error: 'Student ID or email already exists'
      });
    }

    const newStudent = await Student.create({
      studentId,
      name,
      email,
      password
    });

    res.status(201).json({
      success: true,
      data: {
        studentId: newStudent.studentId,
        name: newStudent.name,
        email: newStudent.email
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      success: false,
      error: 'Server error during registration'
    });
  }
});

// Login Student
app.post('/api/v1/students/login', async (req, res) => {
  try {
    const { studentId, password } = req.body;

    if (!studentId || !password) {
      return res.status(400).json({
        success: false,
        error: 'Student ID and password are required'
      });
    }

    const student = await Student.findOne({ studentId }).select('+password');

    if (!student || !(await bcrypt.compare(password, student.password))) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const token = jwt.sign(
      { id: student._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      success: true,
      token,
      data: {
        studentId: student.studentId,
        name: student.name,
        email: student.email
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      error: 'Server error during login'
    });
  }
});

// Protected Routes
app.get('/api/v1/students/profile', authenticate, async (req, res) => {
  res.json({
    success: true,
    data: req.student
  });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
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
// Server Initialization
const startServer = async () => {
  try {
    await connectDB();
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
    });
  } catch (err) {
    console.error('Server startup failed:', err);
    process.exit(1);
  }
};
startServer();