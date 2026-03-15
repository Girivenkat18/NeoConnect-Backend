import mongoose from "mongoose";
import { Case, User } from "./db";
import { hasExceededWorkingDays } from "./working-days";

export async function nextTrackingId() {
  const year = new Date().getFullYear();
  const start = new Date(`${year}-01-01T00:00:00.000Z`);
  const end = new Date(`${year + 1}-01-01T00:00:00.000Z`);
  const count = await Case.countDocuments({
    createdAt: { $gte: start, $lt: end },
  });
  return `NEO-${year}-${String(count + 1).padStart(3, "0")}`;
}

export function serializeCase(caseRecord: any) {
  return {
    id: String(caseRecord._id),
    trackingId: caseRecord.trackingId,
    title: caseRecord.title,
    description: caseRecord.description,
    category: caseRecord.category,
    department: caseRecord.department,
    location: caseRecord.location,
    severity: caseRecord.severity,
    anonymous: Boolean(caseRecord.isAnonymous),
    submitterName: caseRecord.isAnonymous ? "Anonymous" : caseRecord.submitterName,
    status: caseRecord.status,
    assignedToId: caseRecord.assignedToId ? String(caseRecord.assignedToId) : null,
    assignedAt: caseRecord.assignedAt,
    lastResponseAt: caseRecord.lastResponseAt,
    escalatedAt: caseRecord.escalatedAt,
    attachmentPath: caseRecord.attachmentPath,
    attachmentName: caseRecord.attachmentOriginalName,
    createdAt: caseRecord.createdAt,
    updatedAt: caseRecord.updatedAt,
    closedAt: caseRecord.closedAt,
    caseManagerName: caseRecord.assignedToName ?? null,
  };
}

export async function getCaseById(id: string) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return null;
  }
  return Case.findById(id).lean<any>();
}

export async function runEscalationSweep() {
  const admin = await User.findOne({ role: "admin" }).lean<any>();
  if (!admin) {
    return;
  }

  const cases = await Case.find({
    assignedAt: { $ne: null },
    status: { $in: ["Assigned", "In Progress", "Pending"] },
    escalatedAt: null,
  });

  for (const caseRecord of cases) {
    const referenceDate = caseRecord.lastResponseAt || caseRecord.assignedAt;
    if (!referenceDate || !hasExceededWorkingDays(referenceDate.toISOString(), 7)) {
      continue;
    }

    caseRecord.status = "Escalated";
    caseRecord.escalatedAt = new Date();
    caseRecord.escalationReminderSentAt = new Date();
    caseRecord.notes.push({
      authorId: admin._id,
      authorName: admin.name,
      body: "7 working days passed without a Case Manager response. The case was escalated automatically and management has been notified.",
      statusAfter: "Escalated",
      createdAt: new Date(),
    });
    await caseRecord.save();
  }
}
