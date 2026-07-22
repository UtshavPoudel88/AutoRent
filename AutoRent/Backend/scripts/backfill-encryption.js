/**
 * One-off backfill: encrypts any existing plaintext values in the fields that
 * are now encrypted at rest (see services/encryptionService.js for the list
 * and justification). Safe to run multiple times — encryptField/decryptField
 * only touch rows whose value doesn't already have the "enc:v1:" prefix, so
 * already-encrypted rows are skipped, not double-encrypted.
 *
 * Usage: node scripts/backfill-encryption.js
 */
import "dotenv/config";
import { eq, isNotNull } from "drizzle-orm";
import { db, client } from "../db/index.js";
import { payments, userDetails, users } from "../schema/index.js";
import { encryptField, isEncrypted } from "../services/encryptionService.js";

const USER_DETAILS_FIELDS = ["phoneNumber", "dateOfBirth", "address", "licenseNumber"];

const backfillUserDetails = async () => {
  const rows = await db.select().from(userDetails);
  let updated = 0;

  for (const row of rows) {
    const patch = {};
    for (const field of USER_DETAILS_FIELDS) {
      const value = row[field];
      if (value != null && value !== "" && !isEncrypted(value)) {
        patch[field] = encryptField(value);
      }
    }
    if (Object.keys(patch).length > 0) {
      // eslint-disable-next-line no-await-in-loop
      await db.update(userDetails).set(patch).where(eq(userDetails.userId, row.userId));
      updated += 1;
    }
  }

  console.log(`[backfill] user_details: ${updated}/${rows.length} row(s) had plaintext fields encrypted`);
};

const backfillUsersMfaSecrets = async () => {
  const rows = await db
    .select({ id: users.id, mfaSecret: users.mfaSecret, mfaTempSecret: users.mfaTempSecret })
    .from(users);
  let updated = 0;

  for (const row of rows) {
    const patch = {};
    if (row.mfaSecret != null && row.mfaSecret !== "" && !isEncrypted(row.mfaSecret)) {
      patch.mfaSecret = encryptField(row.mfaSecret);
    }
    if (row.mfaTempSecret != null && row.mfaTempSecret !== "" && !isEncrypted(row.mfaTempSecret)) {
      patch.mfaTempSecret = encryptField(row.mfaTempSecret);
    }
    if (Object.keys(patch).length > 0) {
      // eslint-disable-next-line no-await-in-loop
      await db.update(users).set(patch).where(eq(users.id, row.id));
      updated += 1;
    }
  }

  console.log(`[backfill] users (mfaSecret/mfaTempSecret): ${updated}/${rows.length} row(s) updated`);
};

const backfillPayments = async () => {
  const rows = await db
    .select({ id: payments.id, externalId: payments.externalId })
    .from(payments)
    .where(isNotNull(payments.externalId));
  let updated = 0;

  for (const row of rows) {
    if (row.externalId !== "" && !isEncrypted(row.externalId)) {
      // eslint-disable-next-line no-await-in-loop
      await db
        .update(payments)
        .set({ externalId: encryptField(row.externalId) })
        .where(eq(payments.id, row.id));
      updated += 1;
    }
  }

  console.log(`[backfill] payments.externalId: ${updated}/${rows.length} row(s) with a value were encrypted`);
};

const main = async () => {
  if (!process.env.ENCRYPTION_KEY) {
    console.error("ENCRYPTION_KEY is not set — aborting backfill.");
    process.exit(1);
  }

  console.log("Starting encryption backfill...");
  await backfillUserDetails();
  await backfillUsersMfaSecrets();
  await backfillPayments();
  console.log("Backfill complete.");
  await client.end();
};

main().catch(async (err) => {
  console.error("[backfill] Failed:", err);
  await client.end();
  process.exit(1);
});
