import { and, desc, eq, gte, lte, sql } from "drizzle-orm";
import { db } from "../db/index.js";
import { activityLogs, users } from "../schema/index.js";

/**
 * Canonical action names — keep every call site using these constants (not ad-hoc
 * strings) so the admin filter dropdown and any alerting logic stay in sync.
 */
const ACTIONS = {
  REGISTER: "register",
  LOGIN_SUCCESS: "login_success",
  LOGIN_FAILED: "login_failed",
  LOGIN_MFA_REQUIRED: "login_mfa_required",
  ACCOUNT_LOCKED: "account_locked",
  LOGOUT: "logout",
  PASSWORD_RESET_REQUESTED: "password_reset_requested",
  PASSWORD_RESET_COMPLETED: "password_reset_completed",
  PASSWORD_RESET_FAILED: "password_reset_failed",
  MFA_SETUP_STARTED: "mfa_setup_started",
  MFA_ENABLED: "mfa_enabled",
  MFA_SETUP_FAILED: "mfa_setup_failed",
  MFA_DISABLED: "mfa_disabled",
  MFA_DISABLE_FAILED: "mfa_disable_failed",
  MFA_LOGIN_VERIFY_FAILED: "mfa_login_verify_failed",
  PROFILE_UPDATED: "profile_updated",
  ADMIN_VERIFY_PROFILE: "admin_verify_profile",
  ADMIN_VERIFY_LICENSE: "admin_verify_license",
  ADMIN_DELETE_USER: "admin_delete_user",
  ADMIN_VERIFY_VEHICLE: "admin_verify_vehicle",
  PAYMENT_VERIFIED: "payment_verified",
};

/** Keys that must never end up in metadata, even by caller mistake — defense in depth. */
const FORBIDDEN_METADATA_KEYS = /password|token|secret|otp|mfa.?code|backupcode|cvv|card|pin|externalid|authtag/i;

const isPrimitive = (v) => v === null || ["string", "number", "boolean"].includes(typeof v);

const sanitizeMetadata = (metadata) => {
  if (!metadata || typeof metadata !== "object") return null;
  const clean = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (FORBIDDEN_METADATA_KEYS.test(key)) continue;
    if (value === undefined) continue;
    // Keep metadata small and shallow — primitives, or arrays of primitives (e.g. a
    // list of field names that changed). No nested objects/buffers that could smuggle
    // sensitive data through unreviewed.
    if (Array.isArray(value)) {
      if (value.every(isPrimitive)) clean[key] = value;
      continue;
    }
    if (!isPrimitive(value)) continue;
    clean[key] = value;
  }
  return Object.keys(clean).length > 0 ? clean : null;
};

/** Real client IP, respecting the "trust proxy" setting already configured in index.js. */
const getClientIp = (req) => req?.ip || req?.socket?.remoteAddress || null;

/**
 * Writes one audit log row. Never throws — a logging failure must not break the
 * request it's attached to. Pass `req` when available so IP/User-Agent are captured.
 * @param {Object} params
 * @param {string|null} [params.userId] - Actor. Null for e.g. failed logins against a nonexistent account.
 * @param {string} params.action - One of ACTIONS.
 * @param {"success"|"failure"} [params.status]
 * @param {string|null} [params.targetId] - Resource acted upon, if different from the actor.
 * @param {import("express").Request} [params.req]
 * @param {Object} [params.metadata] - Small, non-sensitive context (e.g. { email, reason }).
 */
const logActivity = async ({ userId = null, action, status = "success", targetId = null, req = null, metadata = null }) => {
  try {
    await db.insert(activityLogs).values({
      userId,
      action,
      status,
      targetId,
      ipAddress: getClientIp(req),
      userAgent: req?.headers?.["user-agent"] || null,
      metadata: sanitizeMetadata(metadata),
    });
  } catch (err) {
    console.error("[activityLog] Failed to write log entry:", err.message);
  }
};

/**
 * Paginated, filterable log listing for the admin audit view.
 * @param {Object} filters
 * @param {string} [filters.userId]
 * @param {string} [filters.action]
 * @param {"success"|"failure"} [filters.status]
 * @param {string} [filters.from] - ISO date/time, inclusive.
 * @param {string} [filters.to] - ISO date/time, inclusive.
 * @param {number} [filters.limit]
 * @param {number} [filters.offset]
 */
const getActivityLogs = async (filters = {}) => {
  const { userId, action, status, from, to } = filters;
  const limit = Math.min(Math.max(Number(filters.limit) || 50, 1), 200);
  const offset = Math.max(Number(filters.offset) || 0, 0);

  const conditions = [];
  if (userId) conditions.push(eq(activityLogs.userId, userId));
  if (action) conditions.push(eq(activityLogs.action, action));
  if (status) conditions.push(eq(activityLogs.status, status));
  if (from) conditions.push(gte(activityLogs.createdAt, new Date(from)));
  if (to) conditions.push(lte(activityLogs.createdAt, new Date(to)));

  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

  const rows = await db
    .select({
      id: activityLogs.id,
      userId: activityLogs.userId,
      actorEmail: users.email,
      action: activityLogs.action,
      status: activityLogs.status,
      targetId: activityLogs.targetId,
      ipAddress: activityLogs.ipAddress,
      userAgent: activityLogs.userAgent,
      metadata: activityLogs.metadata,
      createdAt: activityLogs.createdAt,
    })
    .from(activityLogs)
    .leftJoin(users, eq(activityLogs.userId, users.id))
    .where(whereClause)
    .orderBy(desc(activityLogs.createdAt))
    .limit(limit)
    .offset(offset);

  const [{ count }] = await db
    .select({ count: sql`count(*)::int` })
    .from(activityLogs)
    .where(whereClause);

  return { rows, total: count, limit, offset };
};

/**
 * Simple suspicious-pattern flags for the admin dashboard: accounts with several
 * failed logins in the last hour, and accounts currently locked out. Pairs with
 * the brute-force protection in authController.js (feature #3) — those events
 * are exactly what land in activity_logs as login_failed / account_locked.
 */
const getSuspiciousActivity = async () => {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

  const repeatedFailures = await db
    .select({
      userId: activityLogs.userId,
      email: users.email,
      failedCount: sql`count(*)::int`,
      lastAttempt: sql`max(${activityLogs.createdAt})`,
    })
    .from(activityLogs)
    .leftJoin(users, eq(activityLogs.userId, users.id))
    .where(
      and(
        eq(activityLogs.action, ACTIONS.LOGIN_FAILED),
        gte(activityLogs.createdAt, oneHourAgo)
      )
    )
    .groupBy(activityLogs.userId, users.email)
    .having(sql`count(*) >= 3`)
    .orderBy(desc(sql`count(*)`));

  const recentLockouts = await db
    .select({
      id: activityLogs.id,
      userId: activityLogs.userId,
      email: users.email,
      ipAddress: activityLogs.ipAddress,
      createdAt: activityLogs.createdAt,
    })
    .from(activityLogs)
    .leftJoin(users, eq(activityLogs.userId, users.id))
    .where(
      and(eq(activityLogs.action, ACTIONS.ACCOUNT_LOCKED), gte(activityLogs.createdAt, oneHourAgo))
    )
    .orderBy(desc(activityLogs.createdAt));

  return { repeatedFailures, recentLockouts };
};

export { ACTIONS, getActivityLogs, getSuspiciousActivity, logActivity };
