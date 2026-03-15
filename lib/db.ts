import bcrypt from "bcryptjs";
import mongoose, { InferSchemaType, Schema, model, models } from "mongoose";

const userSchema = new Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    role: { type: String, required: true },
    department: { type: String, required: true },
    active: { type: Boolean, default: true },
  },
  { timestamps: { createdAt: "createdAt", updatedAt: false } },
);

const caseNoteSchema = new Schema(
  {
    authorId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    authorName: { type: String, required: true },
    body: { type: String, required: true },
    statusAfter: { type: String },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: true },
);

const caseSchema = new Schema(
  {
    trackingId: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true },
    department: { type: String, required: true },
    location: { type: String, required: true },
    severity: { type: String, required: true },
    isAnonymous: { type: Boolean, default: false },
    submitterId: { type: Schema.Types.ObjectId, ref: "User", default: null },
    submitterName: { type: String, default: null },
    attachmentPath: { type: String, default: null },
    attachmentOriginalName: { type: String, default: null },
    status: { type: String, required: true },
    assignedToId: { type: Schema.Types.ObjectId, ref: "User", default: null },
    assignedToName: { type: String, default: null },
    assignedAt: { type: Date, default: null },
    lastResponseAt: { type: Date, default: null },
    escalatedAt: { type: Date, default: null },
    escalationReminderSentAt: { type: Date, default: null },
    closedAt: { type: Date, default: null },
    notes: { type: [caseNoteSchema], default: [] },
  },
  { timestamps: true },
);

const pollVoteSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    optionIndex: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false },
);

const pollOptionSchema = new Schema(
  {
    label: { type: String, required: true },
    votes: { type: Number, default: 0 },
  },
  { _id: false },
);

const pollSchema = new Schema(
  {
    question: { type: String, required: true },
    options: { type: [pollOptionSchema], required: true },
    votes: { type: [pollVoteSchema], default: [] },
    createdById: { type: Schema.Types.ObjectId, ref: "User", required: true },
    createdByName: { type: String, required: true },
  },
  { timestamps: { createdAt: "createdAt", updatedAt: false } },
);

const digestSchema = new Schema(
  {
    title: { type: String, required: true },
    summary: { type: String, required: true },
    caseId: { type: Schema.Types.ObjectId, ref: "Case", default: null },
    createdById: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: { createdAt: "publishedAt", updatedAt: false } },
);

const impactSchema = new Schema(
  {
    raised: { type: String, required: true },
    actionTaken: { type: String, required: true },
    changed: { type: String, required: true },
    caseId: { type: Schema.Types.ObjectId, ref: "Case", default: null },
  },
  { timestamps: { createdAt: "createdAt", updatedAt: false } },
);

const minuteSchema = new Schema(
  {
    title: { type: String, required: true },
    description: { type: String, required: true },
    filePath: { type: String, required: true },
    originalName: { type: String, required: true },
    uploadedById: { type: Schema.Types.ObjectId, ref: "User", required: true },
    uploadedByName: { type: String, required: true },
  },
  { timestamps: { createdAt: "createdAt", updatedAt: false } },
);

const announcementSchema = new Schema(
  {
    title: { type: String, required: true },
    body: { type: String, required: true },
    createdById: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: { createdAt: "createdAt", updatedAt: false } },
);

export const User = models.User || model("User", userSchema);
export const Case = models.Case || model("Case", caseSchema);
export const Poll = models.Poll || model("Poll", pollSchema);
export const Digest = models.Digest || model("Digest", digestSchema);
export const Impact = models.Impact || model("Impact", impactSchema);
export const Minute = models.Minute || model("Minute", minuteSchema);
export const Announcement = models.Announcement || model("Announcement", announcementSchema);

export type UserDocument = InferSchemaType<typeof userSchema> & { _id: mongoose.Types.ObjectId };
export type CaseDocument = InferSchemaType<typeof caseSchema> & { _id: mongoose.Types.ObjectId };

let connectionPromise: Promise<typeof mongoose> | null = null;

export async function connectDb() {
  if (mongoose.connection.readyState === 1) {
    return mongoose;
  }

  if (!connectionPromise) {
    const uri = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/neoconnect";
    const dbName = process.env.MONGODB_DB || "neoconnect";
    let useDbName = false;

    try {
      const parsed = new URL(uri);
      useDbName = !parsed.pathname || parsed.pathname === "/" || parsed.pathname === "";
    } catch {
      useDbName = false;
    }

    connectionPromise = mongoose.connect(uri, useDbName ? { dbName } : undefined);
  }

  return connectionPromise;
}

export function getConnectedDatabaseName() {
  return mongoose.connection.name || process.env.MONGODB_DB || "neoconnect";
}

export async function seedDatabase() {
  await connectDb();
  const existingUsers = await User.countDocuments();
  if (existingUsers === 0) {
    const passwordHash = await bcrypt.hash("password123", 10);
    await User.create([
      { name: "Aarav Staff", email: "staff@neoconnect.local", role: "staff", department: "Facilities", passwordHash },
      { name: "Sana Secretariat", email: "secretariat@neoconnect.local", role: "secretariat", department: "Operations", passwordHash },
      { name: "Mira Case Manager", email: "manager@neoconnect.local", role: "case_manager", department: "HR", passwordHash },
      { name: "Ishaan Admin", email: "admin@neoconnect.local", role: "admin", department: "IT", passwordHash },
    ]);
  }

  const existingAnnouncements = await Announcement.countDocuments();
  if (existingAnnouncements === 0) {
    const secretariat = await User.findOne({ role: "secretariat" }).lean<UserDocument>();
    if (secretariat) {
      await Announcement.create({
        title: "Welcome to NeoConnect",
        body: "Use this space to raise concerns, review updates, follow decisions, and stay informed about the actions taken across the organization.",
        createdById: secretariat._id,
      });
    }
  }
}
