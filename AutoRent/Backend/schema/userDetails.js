import { boolean, date, pgTable, text, timestamp, varchar } from "drizzle-orm/pg-core";
import { users } from "./user.js";

// User details table (one-to-one relationship with users)
// phoneNumber, dateOfBirth, address, licenseNumber hold AES-256-GCM ciphertext
// (see services/encryptionService.js) — stored as `text` since ciphertext runs
// longer than the original plaintext and dateOfBirth can no longer be a `date`.
const userDetails = pgTable("user_details", {
  userId: varchar("user_id", { length: 255 })
    .primaryKey()
    .references(() => users.id, { onDelete: "CASCADE" }),
  phoneNumber: text("phone_number"),
  dateOfBirth: text("date_of_birth"),
  profilePicture: varchar("profile_picture", { length: 500 }),
  address: text("address"),
  city: varchar("city", { length: 100 }),
  licenseNumber: text("license_number"),
  licenseExpiry: date("license_expiry"),
  licenseImage: varchar("license_image", { length: 500 }),
  isLicenseVerified: boolean("is_license_verified").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export { userDetails };

