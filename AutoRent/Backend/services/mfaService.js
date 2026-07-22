import bcrypt from "bcryptjs";
import crypto from "crypto";
import { eq } from "drizzle-orm";
import QRCode from "qrcode";
import speakeasy from "speakeasy";
import { db } from "../db/index.js";
import { users } from "../schema/index.js";
import { decryptField, encryptField } from "./encryptionService.js";

const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_BYTES = 5; // -> 10 hex chars per code

/**
 * Generate a new TOTP secret + otpauth QR code for enrollment.
 * Stored as mfaTempSecret until confirmed via verifyAndEnableMfa.
 */
const generateEnrollmentSecret = async (userId, email) => {
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `AutoRent (${email})`,
    issuer: "AutoRent",
  });

  await db
    .update(users)
    .set({ mfaTempSecret: encryptField(secret.base32), updatedAt: new Date() })
    .where(eq(users.id, userId));

  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

  return { secret: secret.base32, qrCodeDataUrl, otpauthUrl: secret.otpauth_url };
};

/** Verify a 6-digit TOTP code against a given base32 secret (window=1 allows ±30s clock drift). */
const verifyTotpCode = (secret, code) => {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) return false;
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: code,
    window: 1,
  });
};

/** Generate N plaintext backup codes + their bcrypt hashes (hashes are what gets stored). */
const generateBackupCodes = async (count = BACKUP_CODE_COUNT) => {
  const plainCodes = Array.from({ length: count }, () =>
    crypto.randomBytes(BACKUP_CODE_BYTES).toString("hex")
  );
  const hashedCodes = await Promise.all(
    plainCodes.map((code) => bcrypt.hash(code, 10))
  );
  return { plainCodes, hashedCodes };
};

/**
 * Confirm enrollment: verify the code against mfaTempSecret, then promote it to
 * mfaSecret, enable MFA, and issue fresh backup codes (replacing any old ones).
 */
const verifyAndEnableMfa = async (userId, code) => {
  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!user || !user.mfaTempSecret) {
    return { success: false, message: "No pending MFA enrollment found" };
  }

  const tempSecret = decryptField(user.mfaTempSecret);
  if (!verifyTotpCode(tempSecret, code)) {
    return { success: false, message: "Invalid or expired code" };
  }

  const { plainCodes, hashedCodes } = await generateBackupCodes();

  await db
    .update(users)
    .set({
      mfaEnabled: true,
      mfaSecret: encryptField(tempSecret), // re-encrypted with a fresh IV, not just copied ciphertext
      mfaTempSecret: null,
      mfaBackupCodes: JSON.stringify(hashedCodes),
      updatedAt: new Date(),
    })
    .where(eq(users.id, userId));

  return { success: true, backupCodes: plainCodes };
};

/** Disable MFA entirely and wipe secret + backup codes. */
const disableMfa = async (userId) => {
  await db
    .update(users)
    .set({
      mfaEnabled: false,
      mfaSecret: null,
      mfaTempSecret: null,
      mfaBackupCodes: null,
      updatedAt: new Date(),
    })
    .where(eq(users.id, userId));
};

/**
 * Verify a login-time code, accepting either a 6-digit TOTP code or a one-time
 * backup code. Backup codes are consumed (removed from storage) on success.
 */
const verifyLoginCode = async (userId, code) => {
  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!user || !user.mfaEnabled || !user.mfaSecret) {
    return false;
  }

  const trimmed = typeof code === "string" ? code.trim() : "";

  if (/^\d{6}$/.test(trimmed)) {
    return verifyTotpCode(decryptField(user.mfaSecret), trimmed);
  }

  // Otherwise, try it as a backup code
  if (!user.mfaBackupCodes) return false;
  let hashedCodes;
  try {
    hashedCodes = JSON.parse(user.mfaBackupCodes);
  } catch {
    return false;
  }
  if (!Array.isArray(hashedCodes) || hashedCodes.length === 0) return false;

  for (let i = 0; i < hashedCodes.length; i++) {
    // eslint-disable-next-line no-await-in-loop
    const matches = await bcrypt.compare(trimmed, hashedCodes[i]);
    if (matches) {
      const remaining = hashedCodes.filter((_, idx) => idx !== i);
      await db
        .update(users)
        .set({ mfaBackupCodes: JSON.stringify(remaining), updatedAt: new Date() })
        .where(eq(users.id, userId));
      return true;
    }
  }

  return false;
};

export {
  disableMfa,
  generateBackupCodes,
  generateEnrollmentSecret,
  verifyAndEnableMfa,
  verifyLoginCode,
  verifyTotpCode,
};
