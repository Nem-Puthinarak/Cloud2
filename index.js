const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

// Initialize the app
const app = express();

// Enhanced security middleware
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// Handle JSON parsing errors
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      success: false,
      error: 'Invalid JSON format in request body'
    });
  }
  next();
});

// Enhanced Mongoose Schema
const studentSchema = new mongoose.Schema({
  studentId: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true
  },
  name: { 
    type: String, 
    required: true,
    trim: true
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Invalid email format']
  },
  password: { 
    type: String, 
    required: true,
    select: false
  }
});

// Password hashing middleware
studentSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

const Student = mongoose.model('Student', studentSchema);

// Enhanced MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected'))
.catch(err => {
  console.error('MongoDB Connection Error:', err);
  process.exit(1);
});

// 1. Student Registration (POST)
app.post('/students/register', async (req, res) => {
  try {
    const { studentId, name, email, password } = req.body;

    // Validation
    const missingFields = [];
    if (!studentId) missingFields.push('studentId');
    if (!name) missingFields.push('name');
    if (!email) missingFields.push('email');
    if (!password) missingFields.push('password');

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Missing required fields: ${missingFields.join(', ')}`
      });
    }

    // Check for existing user
    const existingStudent = await Student.findOne({ 
      $or: [{ studentId }, { email }]
    });

    if (existingStudent) {
      return res.status(409).json({
        success: false,
        error: 'Student ID or email already exists'
      });
    }

    const newStudent = new Student({ studentId, name, email, password });
    await newStudent.save();

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
      error: 'Error registering student'
    });
  }
});

// 2. Student Login (POST)
app.post('/students/login', async (req, res) => {
  try {
    const { studentId, password } = req.body;

    if (!studentId || !password) {
      return res.status(400).json({
        success: false,
        error: 'Student ID and password are required'
      });
    }

    const student = await Student.findOne({ studentId }).select('+password');

    if (!student) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const isMatch = await bcrypt.compare(password, student.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const token = jwt.sign(
      { id: student._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
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
      error: 'Error logging in'
    });
  }
});

// 3. Student Search (GET)
app.get('/students/search', async (req, res) => {
  try {
    const { studentId } = req.query;
    
    if (!studentId) {
      return res.status(400).json({
        success: false,
        error: 'Student ID is required'
      });
    }

    const student = await Student.findOne({ studentId });
    
    if (!student) {
      return res.status(404).json({
        success: false,
        error: 'Student not found'
      });
    }

    res.json({
      success: true,
      data: student
    });

  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({
      success: false,
      error: 'Error searching student'
    });
  }
});

// 4. Student Profile Update (PUT)
app.put('/students/update', async (req, res) => {
  try {
    const { studentId, newData } = req.body;

    if (!studentId || !newData) {
      return res.status(400).json({
        success: false,
        error: 'Student ID and update data are required'
      });
    }

    const student = await Student.findOneAndUpdate(
      { studentId },
      newData,
      { new: true, runValidators: true }
    );

    if (!student) {
      return res.status(404).json({
        success: false,
        error: 'Student not found'
      });
    }

    res.json({
      success: true,
      data: student
    });

  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({
      success: false,
      error: 'Error updating profile'
    });
  }
});

// 5. Delete Student (DELETE)
app.delete('/students/delete', async (req, res) => {
  try {
    const { studentId } = req.body;

    if (!studentId) {
      return res.status(400).json({
        success: false,
        error: 'Student ID is required'
      });
    }

    const student = await Student.findOneAndDelete({ studentId });

    if (!student) {
      return res.status(404).json({
        success: false,
        error: 'Student not found'
      });
    }

    res.json({
      success: true,
      message: 'Student deleted successfully'
    });

  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({
      success: false,
      error: 'Error deleting student'
    });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});