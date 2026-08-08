require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const Anthropic = require('@anthropic-ai/sdk');
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });

const app = express();
const prisma = new PrismaClient({ adapter });
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

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
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB
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

// A teacher corrects their own profile details (e.g. fixing a typo the
// headteacher made when first adding them). Password is changed separately
// via /teachers/me/password, not here.
app.put('/teachers/me', authenticate, requireTeacher, async (req, res) => {
  try {
    const {
      name, email, phone, subject,
      dateOfBirth, nationality, qualification, rank,
      firstAppointmentDate, dateAppointedCurrentRank,
      ghanaCardNumber, ssnitNumber,
    } = req.body;

    const teacher = await prisma.teacher.update({
      where: { id: req.user.teacherId },
      data: {
        name, email, phone, subject,
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
    const teacherId = Number(req.params.id);

    // Delete the lesson note files from disk first
    const notes = await prisma.lessonNote.findMany({ where: { teacherId } });
    for (const note of notes) {
      const fullPath = path.join(__dirname, note.filePath);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }

    // A teacher can't be deleted while attendance/lesson note records still
    // point to them, so remove those first, then the teacher itself.
    await prisma.lessonNote.deleteMany({ where: { teacherId } });
    await prisma.attendance.deleteMany({ where: { teacherId } });
    await prisma.teacher.delete({ where: { id: teacherId } });

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

// ================== ATTENDANCE ANOMALY DETECTION ==================
// Pure statistics, no AI call needed — flags a teacher/weekday combo where
// their late-or-absent rate on that specific weekday is notably higher
// than their overall average (e.g. "always late on Mondays").
const WEEKDAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const MIN_OCCURRENCES_ON_WEEKDAY = 2; // need at least this many records on that weekday to flag it
const ANOMALY_THRESHOLD_MULTIPLIER = 1.5; // weekday rate must be this many times the overall rate

app.get('/attendance/anomalies', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const teachers = await prisma.teacher.findMany({
      include: { attendance: true },
    });

    const anomalies = [];

    for (const teacher of teachers) {
      const total = teacher.attendance.length;
      if (total < 4) continue; // not enough history to say anything meaningful

      const overallLateCount = teacher.attendance.filter(
        (a) => a.status === 'late' || a.status === 'absent'
      ).length;
      const overallRate = overallLateCount / total;

      // Group this teacher's records by day of week
      const byWeekday = {}; // 0-6 -> { total, late }
      for (const record of teacher.attendance) {
        const day = new Date(record.date).getDay();
        if (!byWeekday[day]) byWeekday[day] = { total: 0, late: 0 };
        byWeekday[day].total += 1;
        if (record.status === 'late' || record.status === 'absent') {
          byWeekday[day].late += 1;
        }
      }

      for (const [day, counts] of Object.entries(byWeekday)) {
        if (counts.total < MIN_OCCURRENCES_ON_WEEKDAY) continue;
        const weekdayRate = counts.late / counts.total;

        const isNotablyWorse =
          weekdayRate >= 0.5 && // at least half the time on this day
          (overallRate === 0 ? weekdayRate > 0 : weekdayRate >= overallRate * ANOMALY_THRESHOLD_MULTIPLIER);

        if (isNotablyWorse) {
          anomalies.push({
            teacherId: teacher.id,
            name: teacher.name,
            subject: teacher.subject,
            photoUrl: teacher.photoUrl,
            weekday: WEEKDAY_NAMES[day],
            weekdayLateRate: Math.round(weekdayRate * 100),
            overallLateRate: Math.round(overallRate * 100),
            occurrences: counts.total,
            lateOnThatDay: counts.late,
          });
        }
      }
    }

    // Sort so the most severe patterns show first
    anomalies.sort((a, b) => b.weekdayLateRate - a.weekdayLateRate);

    res.json({ anomalies });
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

    // Let the teacher know their note was reviewed
    await prisma.notification.create({
      data: {
        recipientRole: 'teacher',
        teacherId: note.teacherId,
        type: 'note_reviewed',
        relatedId: note.id,
        message:
          status === 'approved'
            ? `Your lesson note "${note.title}" was approved.`
            : `Your lesson note "${note.title}" needs revision.`,
      },
    });

    res.json(note);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ================== ANNOUNCEMENTS & EVENTS ==================

// Headteacher posts an announcement or event. If eventDate is included,
// it's treated as a calendar event; otherwise it's a plain announcement.
app.post('/announcements', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const { title, message, eventDate } = req.body;
    if (!title || !message) {
      return res.status(400).json({ error: 'Title and message are required' });
    }

    const announcement = await prisma.announcement.create({
      data: {
        title,
        message,
        eventDate: eventDate ? new Date(eventDate) : null,
      },
    });

    // Notify every teacher
    const teachers = await prisma.teacher.findMany({ select: { id: true } });
    if (teachers.length > 0) {
      await prisma.notification.createMany({
        data: teachers.map((t) => ({
          recipientRole: 'teacher',
          teacherId: t.id,
          type: 'new_announcement',
          relatedId: announcement.id,
          message: eventDate
            ? `New event: "${title}"`
            : `New announcement: "${title}"`,
        })),
      });
    }

    res.status(201).json(announcement);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// List announcements. Headteacher sees who has/hasn't acknowledged each one.
// Teachers see whether they personally have acknowledged each one.
app.get('/announcements', authenticate, async (req, res) => {
  try {
    const announcements = await prisma.announcement.findMany({
      include: {
        acknowledgements: {
          include: { teacher: { select: { id: true, name: true, photoUrl: true } } },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (req.user.role === 'headteacher') {
      return res.json(announcements);
    }

    // Teacher view: just flag whether they've acknowledged each one
    const forTeacher = announcements.map((a) => ({
      id: a.id,
      title: a.title,
      message: a.message,
      eventDate: a.eventDate,
      createdAt: a.createdAt,
      acknowledged: a.acknowledgements.some((ack) => ack.teacherId === req.user.teacherId),
      acknowledgedCount: a.acknowledgements.length,
    }));
    res.json(forTeacher);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// A teacher marks an announcement/event as seen
app.post('/announcements/:id/acknowledge', authenticate, requireTeacher, async (req, res) => {
  try {
    const announcementId = Number(req.params.id);

    const announcement = await prisma.announcement.findUnique({ where: { id: announcementId } });
    if (!announcement) return res.status(404).json({ error: 'Announcement not found' });

    // Avoid duplicate acknowledgements if they click it twice
    const existing = await prisma.announcementAck.findUnique({
      where: { announcementId_teacherId: { announcementId, teacherId: req.user.teacherId } },
    });
    if (existing) {
      return res.json({ message: 'Already acknowledged', acknowledgedAt: existing.acknowledgedAt });
    }

    const ack = await prisma.announcementAck.create({
      data: { announcementId, teacherId: req.user.teacherId },
    });

    const teacher = await prisma.teacher.findUnique({ where: { id: req.user.teacherId } });
    await prisma.notification.create({
      data: {
        recipientRole: 'headteacher',
        type: 'announcement_ack',
        relatedId: announcementId,
        message: `${teacher.name} acknowledged "${announcement.title}".`,
      },
    });

    res.status(201).json(ack);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Headteacher can delete an announcement/event
app.delete('/announcements/:id', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const announcementId = Number(req.params.id);
    await prisma.announcementAck.deleteMany({ where: { announcementId } });
    await prisma.announcement.delete({ where: { id: announcementId } });
    res.json({ message: 'Announcement deleted successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ================== NOTIFICATIONS ==================

// Get the current user's notifications (headteacher or teacher, scoped automatically)
app.get('/notifications', authenticate, async (req, res) => {
  try {
    const where =
      req.user.role === 'headteacher'
        ? { recipientRole: 'headteacher' }
        : { recipientRole: 'teacher', teacherId: req.user.teacherId };

    const notifications = await prisma.notification.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
    const unreadCount = await prisma.notification.count({ where: { ...where, read: false } });

    res.json({ notifications, unreadCount });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Mark a single notification as read
app.put('/notifications/:id/read', authenticate, async (req, res) => {
  try {
    const notification = await prisma.notification.findUnique({ where: { id: Number(req.params.id) } });
    if (!notification) return res.status(404).json({ error: 'Notification not found' });

    const belongsToUser =
      req.user.role === 'headteacher'
        ? notification.recipientRole === 'headteacher'
        : notification.recipientRole === 'teacher' && notification.teacherId === req.user.teacherId;

    if (!belongsToUser) return res.status(403).json({ error: 'Not your notification' });

    const updated = await prisma.notification.update({
      where: { id: notification.id },
      data: { read: true },
    });
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Mark all of the current user's notifications as read
app.put('/notifications/read-all', authenticate, async (req, res) => {
  try {
    const where =
      req.user.role === 'headteacher'
        ? { recipientRole: 'headteacher' }
        : { recipientRole: 'teacher', teacherId: req.user.teacherId };

    await prisma.notification.updateMany({ where, data: { read: true } });
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Pulls the plain text out of a PDF or Word (.docx) lesson note so it can
// be sent to Claude. Old-style .doc files aren't supported by mammoth.
async function extractTextFromNote(note) {
  const fullPath = path.join(__dirname, note.filePath);
  const ext = path.extname(note.fileName).toLowerCase();

  if (ext === '.pdf') {
    const buffer = fs.readFileSync(fullPath);
    const result = await pdfParse(buffer);
    return result.text;
  }

  if (ext === '.docx') {
    const result = await mammoth.extractRawText({ path: fullPath });
    return result.value;
  }

  throw new Error('This file type (.doc) can\'t be read automatically yet — only PDF and .docx are supported for AI features.');
}

// Keeps the prompt a reasonable size — lesson notes are usually short,
// but this protects against extremely long documents.
function truncateText(text, maxChars = 12000) {
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars) + '\n\n[...truncated...]';
}

// Headteacher asks Claude to generate a one-line summary of a lesson note
app.post('/lesson-notes/:id/summarize', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const note = await prisma.lessonNote.findUnique({ where: { id: Number(req.params.id) } });
    if (!note) return res.status(404).json({ error: 'Lesson note not found' });

    const text = truncateText(await extractTextFromNote(note));
    if (!text.trim()) {
      return res.status(400).json({ error: 'No readable text found in this file.' });
    }

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-5',
      max_tokens: 150,
      messages: [
        {
          role: 'user',
          content: `Here is the content of a teacher's lesson note titled "${note.title}" (subject: ${note.subject || 'unspecified'}). Summarize what this lesson covers in ONE short sentence (under 25 words), written for a busy headteacher skimming a review queue. Only output the sentence, nothing else.\n\nLesson note content:\n${text}`,
        },
      ],
    });

    const summary = response.content[0]?.text?.trim() || 'Summary unavailable.';

    const updated = await prisma.lessonNote.update({
      where: { id: note.id },
      data: { summary },
    });
    res.json(updated);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Headteacher asks Claude to draft a first-pass review comment
app.post('/lesson-notes/:id/suggest-feedback', authenticate, requireHeadteacher, async (req, res) => {
  try {
    const note = await prisma.lessonNote.findUnique({ where: { id: Number(req.params.id) } });
    if (!note) return res.status(404).json({ error: 'Lesson note not found' });

    const text = truncateText(await extractTextFromNote(note));
    if (!text.trim()) {
      return res.status(400).json({ error: 'No readable text found in this file.' });
    }

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-5',
      max_tokens: 300,
      messages: [
        {
          role: 'user',
          content: `You are helping a headteacher review a teacher's lesson note titled "${note.title}" (subject: ${note.subject || 'unspecified'}, ${note.week || 'week unspecified'}). Draft a short, constructive review comment (2-4 sentences) the headteacher could send to the teacher — note one specific strength and one specific, actionable suggestion for improvement. Keep it warm but professional. Only output the comment itself, nothing else (no preamble like "Here's a draft").\n\nLesson note content:\n${text}`,
        },
      ],
    });

    const suggestion = response.content[0]?.text?.trim() || '';
    res.json({ suggestion });
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

// ================== GLOBAL ERROR HANDLER ==================
// Catches errors thrown by middleware like Multer (e.g. wrong file type,
// file too large) that would otherwise crash the request and return
// an HTML error page instead of JSON.
app.use((err, req, res, next) => {
  if (err) {
    console.error('Unhandled error:', err.message);
    return res.status(400).json({ error: err.message || 'Something went wrong' });
  }
  next();
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
