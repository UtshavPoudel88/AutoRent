import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // 96-bit nonce, the recommended size for GCM
const AUTH_TAG_LENGTH = 16;
/** Tags every ciphertext so decryptField can tell it apart from unmigrated plaintext. */
const PREFIX = "enc:v1:";

let cachedKey = null;

/**
 * Loads the AES-256 key from ENCRYPTION_KEY (64 hex chars = 32 bytes). Throws
 * loudly on startup misconfiguration rather than silently storing plaintext.
 */
const getKey = () => {
  if (cachedKey) return cachedKey;
  const keyHex = process.env.ENCRYPTION_KEY;
  if (!keyHex) {
    throw new Error("ENCRYPTION_KEY is not set in environment variables");
  }
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) {
    throw new Error(
      "ENCRYPTION_KEY must be a 64-character hex string (32 bytes) for AES-256"
    );
  }
  cachedKey = key;
  return key;
};

/**
 * Encrypts a value with AES-256-GCM. Output format: "enc:v1:<iv>:<authTag>:<ciphertext>"
 * (each part base64). GCM's auth tag gives tamper-detection on top of confidentiality —
 * decryptField will fail loudly if the ciphertext was altered, not silently return garbage.
 * null/undefined/"" pass through unchanged so optional fields stay optional.
 */
const encryptField = (plaintext) => {
  if (plaintext === null || plaintext === undefined) return null;
  const text = String(plaintext);
  if (text === "") return "";

  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const ciphertext = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `${PREFIX}${iv.toString("base64")}:${authTag.toString("base64")}:${ciphertext.toString("base64")}`;
};

/**
 * Decrypts a value produced by encryptField. Values without the "enc:v1:" prefix
 * are treated as not-yet-migrated plaintext and returned as-is (fail-open on
 * format, fail-closed on tampering) — see the backfill script for converting them.
 */
const decryptField = (stored) => {
  if (stored === null || stored === undefined || stored === "") return stored;
  const value = String(stored);
  if (!value.startsWith(PREFIX)) return value; // legacy plaintext, not yet backfilled

  const parts = value.slice(PREFIX.length).split(":");
  if (parts.length !== 3) {
    console.error("[encryption] Malformed ciphertext (wrong part count)");
    return null;
  }

  try {
    const [ivB64, tagB64, dataB64] = parts;
    const key = getKey();
    const iv = Buffer.from(ivB64, "base64");
    const authTag = Buffer.from(tagB64, "base64");
    const ciphertext = Buffer.from(dataB64, "base64");
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString("utf8");
  } catch (err) {
    // Wrong key, or the ciphertext/auth tag was tampered with — GCM refuses to
    // return unauthenticated plaintext rather than silently corrupting data.
    console.error("[encryption] Failed to decrypt field:", err.message);
    return null;
  }
};

/** True if the stored value is our ciphertext format (vs. legacy plaintext). */
const isEncrypted = (stored) => typeof stored === "string" && stored.startsWith(PREFIX);

export { decryptField, encryptField, isEncrypted };
