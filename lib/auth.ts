import jwt from "jsonwebtoken";
import type { Response, Request } from "express";
import { z } from "zod";
import type { UserRole } from "./constants";

const cookieName = "neoconnect_token";

const payloadSchema = z.object({
  sub: z.string(),
  role: z.string(),
  name: z.string(),
});

export type SessionUser = {
  id: string;
  role: UserRole;
  name: string;
};

function getSecret() {
  return process.env.JWT_SECRET || "dev-only-jwt-secret-change-me";
}

export function signToken(user: SessionUser) {
  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      name: user.name,
    },
    getSecret(),
    { expiresIn: "7d" },
  );
}

export function verifyToken(token: string) {
  const decoded = jwt.verify(token, getSecret());
  return payloadSchema.parse(decoded);
}

export function setAuthCookie(res: Response, token: string) {
  const secure = process.env.NODE_ENV === "production";
  res.cookie(cookieName, token, {
    httpOnly: true,
    path: "/",
    sameSite: secure ? "none" : "lax",
    secure,
    maxAge: 1000 * 60 * 60 * 24 * 7,
  });
}

export function clearAuthCookie(res: Response) {
  const secure = process.env.NODE_ENV === "production";
  res.clearCookie(cookieName, {
    httpOnly: true,
    path: "/",
    sameSite: secure ? "none" : "lax",
    secure,
  });
}

export function getTokenFromRequest(req: Request) {
  const token = req.cookies?.[cookieName];
  return typeof token === "string" ? token : null;
}
