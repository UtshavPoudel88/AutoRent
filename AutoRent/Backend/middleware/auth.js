import crypto from "crypto";
import { eq } from "drizzle-orm";
import jwt from "jsonwebtoken";
import { db } from "../db/index.js";
import { users } from "../schema/index.js";

/** Soft device binding: truncated hash of the User-Agent seen at login time. Spoofable, but raises the bar against naive token copy-paste reuse. */
const hashUserAgent = (userAgent) =>
  crypto.createHash("sha256").update(userAgent || "").digest("hex").slice(0, 16);

/**
 * Verifies a session JWT end-to-end:
 *  1. Signature + expiry (jwt.verify — throws if either fails)
 *  2. tokenVersion against the DB — so logout / password reset invalidate the
 *     token immediately, regardless of its own exp claim (a JWT can't be
 *     revoked by itself; this is what makes revocation possible)
 *  3. User-Agent binding — rejects the token if replayed from a different client
 * Throws on any failure; the caller (HTTP middleware or Socket.IO handshake) maps
 * that to the appropriate rejection.
 */
const verifySessionToken = async (token, userAgent) => {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  if (decoded.mfaPending) {
    throw Object.assign(new Error("Not a session token"), { code: "INVALID_TOKEN" });
  }

  if (decoded.uaHash && decoded.uaHash !== hashUserAgent(userAgent)) {
    throw Object.assign(new Error("Session bound to a different device"), {
      code: "UA_MISMATCH",
    });
  }

  const userId = decoded.userId || decoded.id;
  const [user] = await db
    .select({ tokenVersion: users.tokenVersion })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!user || (decoded.tokenVersion ?? 0) !== (user.tokenVersion ?? 0)) {
    throw Object.assign(new Error("Session has been logged out. Please log in again."), {
      code: "TOKEN_REVOKED",
    });
  }

  return decoded;
};

/**
 * Middleware to authenticate JWT tokens
 */
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access token required",
    });
  }

  try {
    const decoded = await verifySessionToken(token, req.headers["user-agent"]);
    req.user = {
      userId: decoded.userId || decoded.id,
      email: decoded.email,
      role: decoded.role,
    };
    next();
  } catch (err) {
    const message =
      err.code === "TOKEN_REVOKED" || err.code === "UA_MISMATCH"
        ? err.message
        : "Invalid or expired token";
    return res.status(403).json({ success: false, message });
  }
};

export { authenticateToken, hashUserAgent, verifySessionToken };
