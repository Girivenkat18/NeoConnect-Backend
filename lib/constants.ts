export const CASE_CATEGORIES = ["Safety", "Policy", "Facilities", "HR", "Other"] as const;
export const CASE_SEVERITIES = ["Low", "Medium", "High"] as const;
export const CASE_STATUSES = [
  "New",
  "Assigned",
  "In Progress",
  "Pending",
  "Resolved",
  "Escalated",
] as const;
export const USER_ROLES = ["staff", "secretariat", "case_manager", "admin"] as const;

export type UserRole = (typeof USER_ROLES)[number];
export type CaseStatus = (typeof CASE_STATUSES)[number];
