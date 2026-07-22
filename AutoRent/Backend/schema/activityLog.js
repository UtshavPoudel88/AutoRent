import { randomUUID } from "crypto";
import { index, jsonb, pgEnum, pgTable, timestamp, varchar } from "drizzle-orm/pg-core";
import { users } from "./user.js";

export const activityLogStatusEnum = pgEnum("activity_log_status", ["success", "failure"]);

/**
 * Security audit trail. Never write passwords, tokens, MFA secrets, decrypted
 * PII, or full payment credentials into this table — see services/activityLogService.js
 * for the sanitization applied to every write.
 */
const activityLogs = pgTable(
  "activity_logs",
  {
    id: varchar("id", { length: 255 }).primaryKey().$defaultFn(() => randomUUID()),
    // Actor. Nullable — e.g. a failed login against an email that doesn't exist has no user to attribute it to.
    userId: varchar("user_id", { length: 255 }).references(() => users.id, { onDelete: "SET NULL" }),
    action: varchar("action", { length: 100 }).notNull(), // e.g. "login_failed", "admin_delete_user" — see ACTIONS in activityLogService.js
    status: activityLogStatusEnum("status").default("success").notNull(),
    // Resource the action targeted, when different from the actor (e.g. admin deleting another user's account).
    targetId: varchar("target_id", { length: 255 }),
    ipAddress: varchar("ip_address", { length: 45 }), // long enough for IPv6
    userAgent: varchar("user_agent", { length: 500 }),
    metadata: jsonb("metadata"), // small non-sensitive context only — sanitized before insert
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (t) => ({
    userIdIdx: index("activity_logs_user_id_idx").on(t.userId),
    actionIdx: index("activity_logs_action_idx").on(t.action),
    createdAtIdx: index("activity_logs_created_at_idx").on(t.createdAt),
  })
);

export { activityLogs };
