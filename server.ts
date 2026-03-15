import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import { config as loadEnv } from "dotenv";
import express, { type NextFunction, type Request, type Response } from "express";
import mongoose from "mongoose";
import multer from "multer";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { clearAuthCookie, getTokenFromRequest, setAuthCookie, signToken, verifyToken, type SessionUser } from "./lib/auth";
import { connectDb, getConnectedDatabaseName, seedDatabase, User, Case, Poll, Digest, Impact, Minute, Announcement } from "./lib/db";
import { CASE_CATEGORIES, CASE_SEVERITIES, CASE_STATUSES, USER_ROLES, type UserRole } from "./lib/constants";
import { getCaseById, nextTrackingId, runEscalationSweep, serializeCase } from "./lib/server-case";

loadEnv({ path: path.resolve(process.cwd(), ".env") });
loadEnv({ path: path.resolve(process.cwd(), "../.env"), override: false });

const uploadDir = path.join(process.cwd(), "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_")}`),
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

type AuthedRequest = Request & { user?: SessionUser };

function asyncHandler(handler: (req: AuthedRequest, res: Response, next: NextFunction) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handler(req as AuthedRequest, res, next)).catch(next);
  };
}

function getPublicAppUrl() {
  return (process.env.APP_URL || `http://localhost:${process.env.PORT || 4000}`).replace(/\/$/, "");
}

function withPublicFileUrl(filePath: string | null) {
  if (!filePath) {
    return null;
  }
  if (filePath.startsWith("http://") || filePath.startsWith("https://")) {
    return filePath;
  }
  return `${getPublicAppUrl()}${filePath}`;
}

async function getUserRow(id: string) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return null;
  }
  return User.findById(id).select("name email role department active createdAt").lean<any>();
}

function authMiddleware(req: AuthedRequest, _res: Response, nextFn: NextFunction) {
  const token = getTokenFromRequest(req);
  if (!token) {
    nextFn();
    return;
  }

  try {
    const payload = verifyToken(token);
    req.user = { id: String(payload.sub), name: payload.name, role: payload.role as UserRole };
  } catch {
    req.user = undefined;
  }

  nextFn();
}

async function requireAuth(req: AuthedRequest, res: Response, nextFn: NextFunction) {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }

  const user = await getUserRow(req.user.id);
  if (!user || !user.active) {
    clearAuthCookie(res);
    res.status(401).json({ error: "Your account is unavailable." });
    return;
  }

  req.user = { id: String(user._id), name: user.name, role: user.role as UserRole };
  nextFn();
}

function requireRole(roles: UserRole[]) {
  return (req: AuthedRequest, res: Response, nextFn: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(403).json({ error: "You do not have access to this action." });
      return;
    }
    nextFn();
  };
}

async function canViewCase(user: SessionUser, caseId: string) {
  if (user.role === "secretariat" || user.role === "admin") {
    return true;
  }

  const caseRecord = await getCaseById(caseId);
  if (!caseRecord) {
    return false;
  }

  if (user.role === "case_manager") {
    return String(caseRecord.assignedToId || "") === user.id;
  }

  return String(caseRecord.submitterId || "") === user.id;
}

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const createUserSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8),
  role: z.enum(USER_ROLES),
  department: z.string().min(2),
});

const caseSchema = z.object({
  title: z.string().min(5),
  description: z.string().min(10),
  category: z.enum(CASE_CATEGORIES),
  department: z.string().min(2),
  location: z.string().min(2),
  severity: z.enum(CASE_SEVERITIES),
  anonymous: z
    .union([z.literal("true"), z.literal("false"), z.boolean()])
    .transform((value) => value === true || value === "true"),
});

const assignCaseSchema = z.object({
  assignedToId: z.string().min(1),
});

const noteSchema = z.object({
  body: z.string().min(2),
  status: z.enum(CASE_STATUSES).optional(),
});

const pollSchema = z.object({
  question: z.string().min(5),
  options: z.array(z.string().min(1)).min(2).max(6),
});

const voteSchema = z.object({
  optionIndex: z.coerce.number().int().min(0),
});

const digestSchema = z.object({
  title: z.string().min(3),
  summary: z.string().min(10),
  caseId: z.string().optional(),
});

const impactSchema = z.object({
  raised: z.string().min(3),
  actionTaken: z.string().min(3),
  changed: z.string().min(3),
  caseId: z.string().optional(),
});

const announcementSchema = z.object({
  title: z.string().min(3),
  body: z.string().min(6),
});

async function pollResultsForUser(userId: string) {
  const polls = await Poll.find().sort({ createdAt: -1 }).lean<any[]>();
  return polls.map((poll) => {
    const myVote = poll.votes.find((vote: any) => String(vote.userId) === userId);
    return {
      id: String(poll._id),
      question: poll.question,
      createdAt: poll.createdAt,
      createdByName: poll.createdByName,
      totalVotes: poll.options.reduce((sum: number, option: any) => sum + option.votes, 0),
      myVote: myVote?.optionIndex ?? null,
      options: poll.options.map((option: any) => ({
        label: option.label,
        votes: option.votes,
      })),
    };
  });
}

async function start() {
    await connectDb();
    await seedDatabase();
    await runEscalationSweep();
    setInterval(() => {
      void runEscalationSweep();
    }, 1000 * 60 * 60);

    const server = express();
    const allowedOrigins = [
      ...(process.env.FRONTEND_URL || "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean),
      "http://localhost:3000",
      "http://127.0.0.1:3000",
    ];

    server.use((req, res, next) => {
      const origin = req.headers.origin;
      if (origin && allowedOrigins.includes(origin)) {
        res.header("Access-Control-Allow-Origin", origin);
      }
      res.header("Vary", "Origin");
      res.header("Access-Control-Allow-Credentials", "true");
      res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.header("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,DELETE,OPTIONS");
      if (req.method === "OPTIONS") {
        res.sendStatus(204);
        return;
      }
      next();
    });
    server.use(cookieParser());
    server.use(express.json());
    server.use(express.urlencoded({ extended: true }));
    server.use(authMiddleware);
    server.use("/uploads", express.static(uploadDir));

    server.get("/api/health", (_req, res) => {
      res.json({ ok: true, service: "neoconnect-backend" });
    });

    server.post(
      "/api/auth/login",
      asyncHandler(async (req, res) => {
        const parsed = loginSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: "Invalid email or password format." });
          return;
        }

        const user = await User.findOne({ email: parsed.data.email });
        if (!user || !user.active || !(await bcrypt.compare(parsed.data.password, user.passwordHash))) {
          res.status(401).json({ error: "Incorrect credentials." });
          return;
        }

        const token = signToken({ id: String(user._id), role: user.role as UserRole, name: user.name });
        setAuthCookie(res, token);
        res.json({
          user: {
            id: String(user._id),
            name: user.name,
            email: user.email,
            role: user.role,
            department: user.department,
          },
        });
      }),
    );

    server.post("/api/auth/logout", (_req, res) => {
      clearAuthCookie(res);
      res.json({ ok: true });
    });

    server.get(
      "/api/auth/me",
      requireAuth,
      asyncHandler(async (req, res) => {
        const user = await User.findById(req.user?.id).select("name email role department").lean<any>();
        res.json({
          user: {
            id: String(user?._id),
            name: user?.name,
            email: user?.email,
            role: user?.role,
            department: user?.department,
          },
        });
      }),
    );

    server.get(
      "/api/users",
      requireAuth,
      requireRole(["admin", "secretariat"]),
      asyncHandler(async (_req, res) => {
        const users = await User.find().sort({ name: 1 }).select("name email role department active createdAt").lean<any[]>();
        res.json({
          users: users.map((user) => ({
            id: String(user._id),
            name: user.name,
            email: user.email,
            role: user.role,
            department: user.department,
            active: user.active ? 1 : 0,
            created_at: user.createdAt,
          })),
        });
      }),
    );

    server.post(
      "/api/users",
      requireAuth,
      requireRole(["admin"]),
      asyncHandler(async (req, res) => {
        const parsed = createUserSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: "Please provide valid user details." });
          return;
        }

        const existing = await User.findOne({ email: parsed.data.email }).lean<any>();
        if (existing) {
          res.status(409).json({ error: "A user with that email already exists." });
          return;
        }

        const user = await User.create({
          name: parsed.data.name,
          email: parsed.data.email,
          passwordHash: await bcrypt.hash(parsed.data.password, 10),
          role: parsed.data.role,
          department: parsed.data.department,
          active: true,
        });

        res.status(201).json({
          user: {
            id: String(user._id),
            name: user.name,
            email: user.email,
            role: user.role,
            department: user.department,
            active: 1,
            created_at: user.createdAt,
          },
        });
      }),
    );

    server.patch(
      "/api/users/:id/toggle",
      requireAuth,
      requireRole(["admin"]),
      asyncHandler(async (req, res) => {
        const targetUserId = String(req.params.id);
        if (!mongoose.Types.ObjectId.isValid(targetUserId)) {
          res.status(404).json({ error: "User not found." });
          return;
        }

        const user = await User.findById(targetUserId);
        if (!user) {
          res.status(404).json({ error: "User not found." });
          return;
        }

        user.active = !user.active;
        await user.save();
        res.json({
          user: {
            id: String(user._id),
            name: user.name,
            email: user.email,
            role: user.role,
            department: user.department,
            active: user.active ? 1 : 0,
            created_at: user.createdAt,
          },
        });
      }),
    );

    server.get(
      "/api/case-managers",
      requireAuth,
      requireRole(["secretariat", "admin"]),
      asyncHandler(async (_req, res) => {
        const users = await User.find({ role: "case_manager", active: true }).sort({ name: 1 }).select("name email department").lean<any[]>();
        res.json({
          users: users.map((user) => ({
            id: String(user._id),
            name: user.name,
            email: user.email,
            department: user.department,
          })),
        });
      }),
    );

    server.get(
      "/api/cases",
      requireAuth,
      asyncHandler(async (req, res) => {
        await runEscalationSweep();
        const query: Record<string, unknown> = {};

        if (req.user?.role === "staff") {
          query.submitterId = req.user.id;
        }
        if (req.user?.role === "case_manager") {
          query.assignedToId = req.user.id;
        }

        const cases = await Case.find(query).sort({ createdAt: -1 }).lean<any[]>();
        const priority = { Escalated: 0, New: 1, Assigned: 2, "In Progress": 3, Pending: 4, Resolved: 5 } as Record<string, number>;
        cases.sort((a, b) => {
          const byStatus = (priority[a.status] ?? 9) - (priority[b.status] ?? 9);
          if (byStatus !== 0) return byStatus;
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
        });

        res.json({
          cases: cases.map((item) => {
            const serialized = serializeCase(item);
            return {
              ...serialized,
              attachmentPath: withPublicFileUrl(serialized.attachmentPath),
            };
          }),
        });
      }),
    );

    server.post(
      "/api/cases",
      requireAuth,
      upload.single("attachment"),
      asyncHandler(async (req, res) => {
        const parsed = caseSchema.safeParse(req.body);
        if (!parsed.success || !req.user) {
          res.status(400).json({ error: "Please complete every required case field." });
          return;
        }

        if (req.file && !["application/pdf"].includes(req.file.mimetype) && !req.file.mimetype.startsWith("image/")) {
          fs.unlinkSync(req.file.path);
          res.status(400).json({ error: "Attachments must be a photo or PDF." });
          return;
        }

        const user = await User.findById(req.user.id).lean<any>();
        const caseRecord = await Case.create({
          trackingId: await nextTrackingId(),
          title: parsed.data.title,
          description: parsed.data.description,
          category: parsed.data.category,
          department: parsed.data.department,
          location: parsed.data.location,
          severity: parsed.data.severity,
          isAnonymous: parsed.data.anonymous,
          submitterId: req.user.id,
          submitterName: parsed.data.anonymous ? "Anonymous" : user?.name ?? req.user.name,
          attachmentPath: req.file ? `/uploads/${path.basename(req.file.path)}` : null,
          attachmentOriginalName: req.file?.originalname ?? null,
          status: "New",
        });

        const serialized = serializeCase(caseRecord.toObject());
        res.status(201).json({
          case: {
            ...serialized,
            attachmentPath: withPublicFileUrl(serialized.attachmentPath),
          },
        });
      }),
    );

    server.get(
      "/api/cases/:id",
      requireAuth,
      asyncHandler(async (req, res) => {
        const caseId = String(req.params.id);
        if (!req.user || !(await canViewCase(req.user, caseId))) {
          res.status(403).json({ error: "You do not have access to this case." });
          return;
        }

        const caseRecord = await getCaseById(caseId);
        if (!caseRecord) {
          res.status(404).json({ error: "Case not found." });
          return;
        }

        const notes = [...(caseRecord.notes || [])]
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
          .map((note) => ({
            id: String(note._id),
            body: note.body,
            status_after: note.statusAfter ?? null,
            created_at: note.createdAt,
            author_name: note.authorName,
          }));

        const serialized = serializeCase(caseRecord);
        res.json({
          case: {
            ...serialized,
            attachmentPath: withPublicFileUrl(serialized.attachmentPath),
          },
          notes,
        });
      }),
    );

    server.post(
      "/api/cases/:id/assign",
      requireAuth,
      requireRole(["secretariat", "admin"]),
      asyncHandler(async (req, res) => {
        const parsed = assignCaseSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: "Please choose a valid Case Manager." });
          return;
        }

        const caseRecord = await Case.findById(req.params.id);
        if (!caseRecord) {
          res.status(404).json({ error: "Case not found." });
          return;
        }

        const manager = await User.findById(parsed.data.assignedToId).lean<any>();
        if (!manager || manager.role !== "case_manager" || !manager.active) {
          res.status(400).json({ error: "Assigned user must be an active Case Manager." });
          return;
        }

        caseRecord.assignedToId = manager._id;
        caseRecord.assignedToName = manager.name;
        caseRecord.assignedAt = new Date();
        caseRecord.lastResponseAt = null;
        caseRecord.status = "Assigned";
        caseRecord.notes.push({
          authorId: new mongoose.Types.ObjectId(req.user?.id),
          authorName: req.user?.name ?? "System",
          body: `Case assigned to ${manager.name}.`,
          statusAfter: "Assigned",
          createdAt: new Date(),
        });
        await caseRecord.save();

        const serialized = serializeCase(caseRecord.toObject());
        res.json({
          case: {
            ...serialized,
            attachmentPath: withPublicFileUrl(serialized.attachmentPath),
          },
        });
      }),
    );

    server.post(
      "/api/cases/:id/notes",
      requireAuth,
      asyncHandler(async (req, res) => {
        const caseId = String(req.params.id);
        if (!req.user || !(await canViewCase(req.user, caseId))) {
          res.status(403).json({ error: "You do not have access to this case." });
          return;
        }

        if (req.user.role === "staff") {
          res.status(403).json({ error: "Staff cannot update case handling notes." });
          return;
        }

        const parsed = noteSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: "Please add a valid note." });
          return;
        }

        const caseRecord = await Case.findById(caseId);
        if (!caseRecord) {
          res.status(404).json({ error: "Case not found." });
          return;
        }

        const nextStatus = parsed.data.status ?? caseRecord.status;
        caseRecord.status = nextStatus;
        caseRecord.notes.push({
          authorId: new mongoose.Types.ObjectId(req.user.id),
          authorName: req.user.name,
          body: parsed.data.body,
          statusAfter: nextStatus,
          createdAt: new Date(),
        });
        if (req.user.role === "case_manager") {
          caseRecord.lastResponseAt = new Date();
        }
        if (nextStatus === "Resolved") {
          caseRecord.closedAt = new Date();
        }
        await caseRecord.save();

        const serialized = serializeCase(caseRecord.toObject());
        res.json({
          case: {
            ...serialized,
            attachmentPath: withPublicFileUrl(serialized.attachmentPath),
          },
        });
      }),
    );

    server.get(
      "/api/polls",
      requireAuth,
      asyncHandler(async (req, res) => {
        res.json({ polls: await pollResultsForUser(req.user!.id) });
      }),
    );

    server.post(
      "/api/polls",
      requireAuth,
      requireRole(["secretariat", "admin"]),
      asyncHandler(async (req, res) => {
        const parsed = pollSchema.safeParse({
          ...req.body,
          options: Array.isArray(req.body.options)
            ? req.body.options
            : typeof req.body.options === "string"
              ? req.body.options.split("\n").map((value: string) => value.trim()).filter(Boolean)
              : [],
        });
        if (!parsed.success || !req.user) {
          res.status(400).json({ error: "Polls need a question and at least two options." });
          return;
        }

        const poll = await Poll.create({
          question: parsed.data.question,
          options: parsed.data.options.map((label) => ({ label, votes: 0 })),
          votes: [],
          createdById: req.user.id,
          createdByName: req.user.name,
        });

        const polls = await pollResultsForUser(req.user.id);
        res.status(201).json({ poll: polls.find((item) => item.id === String(poll._id)) });
      }),
    );

    server.post(
      "/api/polls/:id/vote",
      requireAuth,
      asyncHandler(async (req, res) => {
        const parsed = voteSchema.safeParse(req.body);
        if (!parsed.success || !req.user) {
          res.status(400).json({ error: "Choose a valid poll option." });
          return;
        }

        const poll = await Poll.findById(req.params.id);
        if (!poll) {
          res.status(404).json({ error: "Poll not found." });
          return;
        }

        if (!poll.options[parsed.data.optionIndex]) {
          res.status(400).json({ error: "That option is not available." });
          return;
        }

        const alreadyVoted = poll.votes.some((vote: any) => String(vote.userId) === req.user?.id);
        if (alreadyVoted) {
          res.status(409).json({ error: "You can only vote once per poll." });
          return;
        }

        poll.votes.push({
          userId: new mongoose.Types.ObjectId(req.user.id),
          optionIndex: parsed.data.optionIndex,
          createdAt: new Date(),
        });
        poll.options[parsed.data.optionIndex].votes += 1;
        await poll.save();

        const polls = await pollResultsForUser(req.user.id);
        res.json({ poll: polls.find((item) => item.id === String(poll._id)) });
      }),
    );

    server.get(
      "/api/public-hub",
      requireAuth,
      asyncHandler(async (req, res) => {
        const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
        const minutesQuery = q
          ? {
              $or: [
                { title: { $regex: q, $options: "i" } },
                { description: { $regex: q, $options: "i" } },
                { originalName: { $regex: q, $options: "i" } },
              ],
            }
          : {};

        const [digests, impacts, announcements, minutes] = await Promise.all([
          Digest.find().sort({ publishedAt: -1 }).lean(),
          Impact.find().sort({ createdAt: -1 }).lean(),
          Announcement.find().sort({ createdAt: -1 }).lean(),
          Minute.find(minutesQuery).sort({ createdAt: -1 }).lean(),
        ]);

        res.json({
          digests: digests.map((item) => ({
            id: String(item._id),
            title: item.title,
            summary: item.summary,
            published_at: item.publishedAt,
          })),
          impacts: impacts.map((item) => ({
            id: String(item._id),
            raised: item.raised,
            action_taken: item.actionTaken,
            changed: item.changed,
          })),
          announcements: announcements.map((item) => ({
            id: String(item._id),
            title: item.title,
            body: item.body,
            created_at: item.createdAt,
          })),
          minutes: minutes.map((item) => ({
            id: String(item._id),
            title: item.title,
            description: item.description,
            file_path: withPublicFileUrl(item.filePath),
            original_name: item.originalName,
            uploaded_by_name: item.uploadedByName,
            created_at: item.createdAt,
          })),
        });
      }),
    );

    server.post(
      "/api/public-hub/digests",
      requireAuth,
      requireRole(["secretariat", "admin"]),
      asyncHandler(async (req, res) => {
        const parsed = digestSchema.safeParse(req.body);
        if (!parsed.success || !req.user) {
          res.status(400).json({ error: "Digest title and summary are required." });
          return;
        }

        await Digest.create({
          title: parsed.data.title,
          summary: parsed.data.summary,
          caseId: parsed.data.caseId && mongoose.Types.ObjectId.isValid(parsed.data.caseId) ? parsed.data.caseId : null,
          createdById: req.user.id,
        });

        res.status(201).json({ ok: true });
      }),
    );

    server.post(
      "/api/public-hub/impacts",
      requireAuth,
      requireRole(["secretariat", "admin"]),
      asyncHandler(async (req, res) => {
        const parsed = impactSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ error: "Impact rows need all three columns completed." });
          return;
        }

        await Impact.create({
          raised: parsed.data.raised,
          actionTaken: parsed.data.actionTaken,
          changed: parsed.data.changed,
          caseId: parsed.data.caseId && mongoose.Types.ObjectId.isValid(parsed.data.caseId) ? parsed.data.caseId : null,
        });

        res.status(201).json({ ok: true });
      }),
    );

    server.post(
      "/api/public-hub/minutes",
      requireAuth,
      requireRole(["secretariat", "admin"]),
      upload.single("file"),
      asyncHandler(async (req, res) => {
        if (!req.file || req.file.mimetype !== "application/pdf" || !req.user) {
          if (req.file) {
            fs.unlinkSync(req.file.path);
          }
          res.status(400).json({ error: "Minutes must be uploaded as a PDF." });
          return;
        }

        const title = typeof req.body.title === "string" ? req.body.title.trim() : "";
        const description = typeof req.body.description === "string" ? req.body.description.trim() : "";
        if (!title || !description) {
          fs.unlinkSync(req.file.path);
          res.status(400).json({ error: "Minutes need a title and short description." });
          return;
        }

        await Minute.create({
          title,
          description,
          filePath: `/uploads/${path.basename(req.file.path)}`,
          originalName: req.file.originalname,
          uploadedById: req.user.id,
          uploadedByName: req.user.name,
        });

        res.status(201).json({ ok: true });
      }),
    );

    server.post(
      "/api/public-hub/announcements",
      requireAuth,
      requireRole(["secretariat", "admin"]),
      asyncHandler(async (req, res) => {
        const parsed = announcementSchema.safeParse(req.body);
        if (!parsed.success || !req.user) {
          res.status(400).json({ error: "Announcement title and body are required." });
          return;
        }

        await Announcement.create({
          title: parsed.data.title,
          body: parsed.data.body,
          createdById: req.user.id,
        });

        res.status(201).json({ ok: true });
      }),
    );

    server.get(
      "/api/analytics",
      requireAuth,
      requireRole(["secretariat", "admin"]),
      asyncHandler(async (_req, res) => {
        await runEscalationSweep();
        const cases = await Case.find().lean();
        const openCases = cases.filter((item) => item.status !== "Resolved");

        const countBy = (items: typeof cases, key: "status" | "category" | "department") => {
          const map = new Map<string, number>();
          for (const item of items) {
            map.set(item[key], (map.get(item[key]) || 0) + 1);
          }
          return [...map.entries()].map(([label, total]) => ({ label, total })).sort((a, b) => b.total - a.total);
        };

        const openByDepartment = countBy(openCases, "department").map((item) => ({
          department: item.label,
          total: item.total,
        }));

        const hotspotMap = new Map<string, { department: string; category: string; total: number }>();
        for (const item of cases) {
          const key = `${item.department}:::${item.category}`;
          const current = hotspotMap.get(key) || { department: item.department, category: item.category, total: 0 };
          current.total += 1;
          hotspotMap.set(key, current);
        }

        res.json({
          openByDepartment,
          byStatus: countBy(cases, "status"),
          byCategory: countBy(cases, "category"),
          byDepartment: countBy(cases, "department"),
          hotspots: [...hotspotMap.values()].filter((item) => item.total >= 5).sort((a, b) => b.total - a.total),
        });
      }),
    );

    server.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
      console.error(error);
      res.status(500).json({ error: "Internal Server Error" });
    });

    const port = Number(process.env.PORT ?? 4000);
    server.listen(port, () => {
      console.log(`NeoConnect ready on http://localhost:${port}`);
      console.log(`MongoDB database: ${getConnectedDatabaseName()}`);
    });
}

start().catch((error) => {
  console.error("Failed to start server", error);
  process.exit(1);
});
