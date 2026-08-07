require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });

const app = express();
const prisma = new PrismaClient({ adapter });

const JWT_SECRET = process.env.JWT_SECRET;
const HEADTEACHER_EMAIL = process.env.HEADTEACHER_EMAIL;
const HEADTEACHER_PASSWORD = process.env.HEADTEACHER_PASSWORD;

app.use(cors());
app.use(express.json());

// ================== FILE UPLOAD SETUP ==================

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

app.use('/uploads', express.static(UPLOAD_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  },
});

const ALLOWED_MIME_TYPES = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
];

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF and Word documents are allowed'));
    }
  },
});

// Separate uploader for profile photos (images only)
const PHOTO_DIR = path.join(UPLOAD_DIR, 'photos');
if (!fs.existsSync(PHOTO_DIR)) {
  fs.mkdirSync(PHOTO_DIR, { recursive: true });
}

const photoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, PHOTO_DIR),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  },
});

const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

const photoUpload = multer({
  storage: photoStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPG, PNG, or WEBP images are allowed'));
    }
  },
});

// ================== AUTH HELPERS ==================

// Removes the password field before sending a teacher object back to the client
function sanitizeTeacher(teacher) {
  const { password, ...safe } = teacher;
  return safe;
}

// Checks the Authorization header for a valid token.
// On success, sets req.user = { role: 'headteacher' } or { role: 'teacher', teacherId }
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireHeadteacher(req, res, next) {
  if (req.user?.role !== 'headteacher') {
    return res.status(403).json({ error: 'Headteacher access only' });
  }
  next();
}

function requireTeacher(req, res, next) {
  if (req.user?.role !== 'teacher') {
    return res.status(403).json({ error: 'Teacher access only' });
  }
  next();
}

// Test route
app.get('/', (req, res) => {
  res.send('Teacher Management System API is running 🎉');
});

// ================== AUTH ROUTES ==================

// Login for both headteacher and teachers
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check headteacher first
    if (email === HEADTEACHER_EMAIL && password === HEADTEACHER_PASSWORD) {
      const token = jwt.sign({ role: 'headteacher' }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, role: 'headteacher', name: 'Headteacher' });
    }

    // Otherwise check the Teacher table
    const teacher = await prisma.teacher.findUnique({ where: { email } });
    if (!teacher) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const passwordMatches = await bcrypt.compare(password, teacher.password);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { role: 'teacher', teacherId: teacher.id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, role: 'teacher', name: teacher.name, teacherId: teacher.id });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// A teacher changes their own password (must know their current one)
app.put('/teachers/me/password', authenticate, requireTeacher, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }

    const teacher = await prisma.teacher.findUnique({ where: { id: req.user.teacherId } });
    const matches = await bcrypt.compare(currentPassword, teacher.password);
    if (!matches) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.teacher.update({
      where: { id: teacher.id },
      data: { password: hashed },
    });
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// A teacher uploads/updates their own profile photo
app.post('/teachers/me/photo', authenticate, requireTeacher, photoUpload.single('photo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'A photo (JPG, PNG, or WEBP) is required' });
    }
    const teacher = await prisma.teacher.update({
      where: { id: req.user.teacherId },
      data: { photoUrl: `uploads/photos/${req.file.filename}` },
    });
    res.json(sanitizeTeacher(teacher));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Headteacher can also set/update a teacher's photo
app.post('/teachers/:id/photo', authenticate, requireHeadteacher, photoUpload.single('photo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'A photo (JPG, PNG, or WEBP) is required' });
    }
    const teacher = await prisma.teacher.update({
      where: { id: Number(req.params.id) },
      data: { photoUrl: `uploads/photos/${req.file.filename}` },
    });
    res.json(sanitizeTeacher(teacher));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


app.get('/teachers/me', authenticate, requireTeacher, async (req, res) => {
  try {
    const teacher = await prisma.teacher.findUnique({ where: { id: req.user.teacherId } });
    if (!teacher) return res.status(404).json({ error: 'Teacher not found' });
    res.json(sanitizeTeacher(teacher));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ================== TEACHER ROUTES (headteacher only) ==================

app.post('/teachers', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const {
      name, email, password, subject, phone, photoUrl,
      dateOfBirth, nationality, qualification, rank,
      firstAppointmentDate, dateAppointedCurrentRank,
      ghanaCardNumber, ssnitNumber,
    } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const teacher = await prisma.teacher.create({
      data: {
        name,
        email,
        password: hashedPassword,
        subject,
        phone,
        photoUrl,
        dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : undefined,
        nationality,
        qualification,
        rank,
        firstAppointmentDate: firstAppointmentDate ? new Date(firstAppointmentDate) : undefined,
        dateAppointedCurrentRank: dateAppointedCurrentRank ? new Date(dateAppointedCurrentRank) : undefined,
        ghanaCardNumber,
        ssnitNumber,
      },
    });
    res.status(201).json(sanitizeTeacher(teacher));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/teachers', authenticate, requireHeadteacher, async (req, res) => {
  const teachers = await prisma.teacher.findMany();
  res.json(teachers.map(sanitizeTeacher));
});

app.get('/teachers/:id', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const teacher = await prisma.teacher.findUnique({
      where: { id: Number(req.params.id) },
    });
    if (!teacher) {
      return res.status(404).json({ error: 'Teacher not found' });
    }
    res.json(sanitizeTeacher(teacher));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/teachers/:id', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const {
      name, email, subject, phone, photoUrl,
      dateOfBirth, nationality, qualification, rank,
      firstAppointmentDate, dateAppointedCurrentRank,
      ghanaCardNumber, ssnitNumber,
    } = req.body;

    const teacher = await prisma.teacher.update({
      where: { id: Number(req.params.id) },
      data: {
        name, email, subject, phone, photoUrl,
        dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : undefined,
        nationality,
        qualification,
        rank,
        firstAppointmentDate: firstAppointmentDate ? new Date(firstAppointmentDate) : undefined,
        dateAppointedCurrentRank: dateAppointedCurrentRank ? new Date(dateAppointedCurrentRank) : undefined,
        ghanaCardNumber,
        ssnitNumber,
      },
    });
    res.json(sanitizeTeacher(teacher));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/teachers/:id', authenticate, requireHeadteacher, async (req, res) => {
  try {
    await prisma.teacher.delete({
      where: { id: Number(req.params.id) },
    });
    res.json({ message: 'Teacher deleted successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ================== ATTENDANCE ROUTES ==================

const LATE_CUTOFF_HOUR = 8;
const LATE_CUTOFF_MINUTE = 0;

// Headteacher manually marks attendance for any teacher
app.post('/attendance', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const { teacherId, status, checkIn, date } = req.body;

    let finalStatus = status;
    let checkInTime = checkIn ? new Date(checkIn) : null;

    if (!finalStatus && checkInTime) {
      const cutoff = new Date(checkInTime);
      cutoff.setHours(LATE_CUTOFF_HOUR, LATE_CUTOFF_MINUTE, 0, 0);
      finalStatus = checkInTime > cutoff ? 'late' : 'present';
    }

    if (!finalStatus) {
      return res.status(400).json({ error: 'Provide either a status or a checkIn time' });
    }

    const attendance = await prisma.attendance.create({
      data: {
        teacherId: Number(teacherId),
        status: finalStatus,
        checkIn: checkInTime,
        date: date ? new Date(date) : new Date(),
      },
    });
    res.status(201).json(attendance);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Headteacher sees anyone's attendance; a teacher only ever sees their own
app.get('/attendance', authenticate, async (req, res) => {
  try {
    const { date } = req.query;
    const where = {};

    if (req.user.role === 'teacher') {
      where.teacherId = req.user.teacherId; // force to own records
    } else if (req.query.teacherId) {
      where.teacherId = Number(req.query.teacherId);
    }

    if (date) {
      const start = new Date(date);
      const end = new Date(date);
      end.setDate(end.getDate() + 1);
      where.date = { gte: start, lt: end };
    }

    const records = await prisma.attendance.findMany({
      where,
      include: { teacher: { select: { id: true, name: true, subject: true, photoUrl: true } } },
      orderBy: { date: 'desc' },
    });
    res.json(records);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/attendance/:id', authenticate, async (req, res) => {
  try {
    const record = await prisma.attendance.findUnique({
      where: { id: Number(req.params.id) },
      include: { teacher: { select: { id: true, name: true, subject: true, photoUrl: true } } },
    });
    if (!record) {
      return res.status(404).json({ error: 'Attendance record not found' });
    }
    if (req.user.role === 'teacher' && record.teacherId !== req.user.teacherId) {
      return res.status(403).json({ error: 'Not your attendance record' });
    }
    res.json(record);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/attendance/:id', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const { status, checkIn, date } = req.body;
    const record = await prisma.attendance.update({
      where: { id: Number(req.params.id) },
      data: {
        status,
        checkIn: checkIn ? new Date(checkIn) : undefined,
        date: date ? new Date(date) : undefined,
      },
    });
    res.json(record);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/attendance/:id', authenticate, requireHeadteacher, async (req, res) => {
  try {
    await prisma.attendance.delete({
      where: { id: Number(req.params.id) },
    });
    res.json({ message: 'Attendance record deleted successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ================== PUNCTUALITY CHART DATA (headteacher only) ==================

app.get('/attendance/stats/punctuality', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const teachers = await prisma.teacher.findMany({
      include: { attendance: { orderBy: { date: 'desc' } } },
    });

    const stats = teachers.map((t) => {
      const total = t.attendance.length;
      const lateCount = t.attendance.filter(
        (a) => a.status === 'late' || a.status === 'absent'
      ).length;
      const latePercentage = total > 0 ? Math.round((lateCount / total) * 100) : 0;
      return {
        teacherId: t.id,
        name: t.name,
        subject: t.subject,
        photoUrl: t.photoUrl,
        rank: t.rank,
        totalRecords: total,
        lateCount,
        latePercentage,
        punctualityScore: total > 0 ? 100 - latePercentage : null,
        records: t.attendance.map((a) => ({
          id: a.id,
          date: a.date,
          status: a.status,
          checkIn: a.checkIn,
        })),
      };
    });

    const withHistory = stats.filter((s) => s.totalRecords > 0);

    const mostPunctual = [...withHistory]
      .sort((a, b) => b.punctualityScore - a.punctualityScore)
      .slice(0, 5);

    const leastPunctual = [...withHistory]
      .sort((a, b) => a.punctualityScore - b.punctualityScore)
      .slice(0, 5);

    const all = [...stats].sort((a, b) => a.name.localeCompare(b.name));

    res.json({ mostPunctual, leastPunctual, all });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ================== LESSON NOTE ROUTES ==================

// A teacher uploads their own lesson note (teacherId comes from their token, not the request body)
app.post('/lesson-notes', authenticate, requireTeacher, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'A file (PDF or Word doc) is required' });
    }
    const { title, subject, week } = req.body;

    const note = await prisma.lessonNote.create({
      data: {
        teacherId: req.user.teacherId,
        title,
        subject,
        week,
        fileName: req.file.originalname,
        filePath: `uploads/${req.file.filename}`,
      },
    });
    res.status(201).json(note);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Headteacher sees all notes (optionally filtered); a teacher only ever sees their own
app.get('/lesson-notes', authenticate, async (req, res) => {
  try {
    const { status } = req.query;
    const where = {};
    if (status) where.status = status;

    if (req.user.role === 'teacher') {
      where.teacherId = req.user.teacherId;
    } else if (req.query.teacherId) {
      where.teacherId = Number(req.query.teacherId);
    }

    const notes = await prisma.lessonNote.findMany({
      where,
      include: { teacher: { select: { id: true, name: true, subject: true, photoUrl: true } } },
      orderBy: { createdAt: 'desc' },
    });
    res.json(notes);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/lesson-notes/:id', authenticate, async (req, res) => {
  try {
    const note = await prisma.lessonNote.findUnique({
      where: { id: Number(req.params.id) },
      include: { teacher: { select: { id: true, name: true, subject: true, photoUrl: true } } },
    });
    if (!note) {
      return res.status(404).json({ error: 'Lesson note not found' });
    }
    if (req.user.role === 'teacher' && note.teacherId !== req.user.teacherId) {
      return res.status(403).json({ error: 'Not your lesson note' });
    }
    res.json(note);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Headteacher reviews a lesson note
app.put('/lesson-notes/:id/review', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const { status, comment } = req.body;
    if (!['approved', 'needs_revision'].includes(status)) {
      return res.status(400).json({ error: 'Status must be "approved" or "needs_revision"' });
    }
    const note = await prisma.lessonNote.update({
      where: { id: Number(req.params.id) },
      data: { status, comment, reviewedAt: new Date() },
    });
    res.json(note);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/lesson-notes/:id', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const note = await prisma.lessonNote.findUnique({
      where: { id: Number(req.params.id) },
    });
    if (note) {
      const fullPath = path.join(__dirname, note.filePath);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
    await prisma.lessonNote.delete({ where: { id: Number(req.params.id) } });
    res.json({ message: 'Lesson note deleted successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
