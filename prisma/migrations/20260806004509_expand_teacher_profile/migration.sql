/*
  Warnings:

  - A unique constraint covering the columns `[ghanaCardNumber]` on the table `Teacher` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[ssnitNumber]` on the table `Teacher` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "Teacher" ADD COLUMN     "dateAppointedCurrentRank" TIMESTAMP(3),
ADD COLUMN     "dateOfBirth" TIMESTAMP(3),
ADD COLUMN     "firstAppointmentDate" TIMESTAMP(3),
ADD COLUMN     "ghanaCardNumber" TEXT,
ADD COLUMN     "nationality" TEXT,
ADD COLUMN     "qualification" TEXT,
ADD COLUMN     "rank" TEXT,
ADD COLUMN     "ssnitNumber" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "Teacher_ghanaCardNumber_key" ON "Teacher"("ghanaCardNumber");

-- CreateIndex
CREATE UNIQUE INDEX "Teacher_ssnitNumber_key" ON "Teacher"("ssnitNumber");
