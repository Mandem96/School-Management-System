// One-time script: deletes ALL teachers, attendance records, and lesson notes
// so you can start fresh. Run with: node reset-data.js
// ⚠️ This permanently deletes data — there's no undo.

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
const prisma = new PrismaClient({ adapter });

async function main() {
  // Delete lesson note files from disk first
  const notes = await prisma.lessonNote.findMany();
  for (const note of notes) {
    const fullPath = path.join(__dirname, note.filePath);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  }

  const deletedNotes = await prisma.lessonNote.deleteMany();
  const deletedAttendance = await prisma.attendance.deleteMany();
  const deletedTeachers = await prisma.teacher.deleteMany();

  console.log(`Deleted ${deletedNotes.count} lesson note(s).`);
  console.log(`Deleted ${deletedAttendance.count} attendance record(s).`);
  console.log(`Deleted ${deletedTeachers.count} teacher(s).`);
  console.log('\nDatabase is now empty. Ready for a fresh start.');

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
