import bcrypt from "bcryptjs";
import { eq, sql } from "drizzle-orm";
import jwt from "jsonwebtoken";
import { db } from "../db/index.js";
import { hashUserAgent } from "../middleware/auth.js";
import { users } from "../schema/index.js";
import { verifyCaptcha } from "../services/captchaService.js";
import { sendOTPEmail, sendPasswordResetOTPEmail } from "../services/emailService.js";
import {
  disableMfa,
  generateEnrollmentSecret,
  verifyAndEnableMfa,
  verifyLoginCode,
} from "../services/mfaService.js";
import {
  createOTP,
  generateOTP,
  getOtpExpiresAt,
  validateOTP,
  verifyOTP,
} from "../services/otpService.js";
import { isPasswordExpired } from "../services/passwordPolicyService.js";
import { ACTIONS, logActivity } from "../services/activityLogService.js";

/** After this many consecutive failed attempts, the account is temporarily locked. */
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_MINUTES = 15;
/** Before the lockout threshold, start requiring CAPTCHA to slow down automated guessing. */
const CAPTCHA_ATTEMPTS_THRESHOLD = 3;

/** Short-lived token proving password was verified; only good for completing MFA login. */
const issueMfaPendingToken = (user) => {
  const jwtSecret = process.env.JWT_SECRET;
  return jwt.sign(
    { id: user.id, mfaPending: true },
    jwtSecret,
    { expiresIn: "5m" }
  );
};

/**
 * Issues the real session JWT. Embeds tokenVersion (so logout/password-reset can
 * revoke it server-side before its natural expiry) and a UA hash (soft device
 * binding — see middleware/auth.js for how both are checked on every request).
 */
const issueSessionToken = (user, userAgent) => {
  const jwtSecret = process.env.JWT_SECRET;
  return jwt.sign(
    {
      id: user.id,
      userId: user.id, // Alias for consistency
      email: user.email,
      role: user.role,
      tokenVersion: user.tokenVersion ?? 0,
      uaHash: hashUserAgent(userAgent),
    },
    jwtSecret,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || "7d",
    }
  );
};

/**
 * Register a new user
 */
const register = async (req, res) => {
  try {
    const { email, password, firstName, lastName, role } = req.body;
    console.log(`[Register] Start for ${email}`);

    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email.toLowerCase()))
      .limit(1);

    if (existingUser.length > 0) {
      console.log(`[Register] Duplicate email: ${email}`);
      await logActivity({
        action: ACTIONS.REGISTER,
        status: "failure",
        req,
        metadata: { email: email.toLowerCase(), reason: "duplicate_email" },
      });
      return res.status(409).json({
        success: false,
        message: "User with this email already exists",
      });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const otp = generateOTP();
    const otpExpiresAt = getOtpExpiresAt();

    const validRoles = ["renter", "owner"];
    const userRole = role && validRoles.includes(role) ? role : "renter";

    const [newUser] = await db
      .insert(users)
      .values({
        email: email.toLowerCase(),
        password: hashedPassword,
        firstName: firstName || null,
        lastName: lastName || null,
        role: userRole,
        isEmailVerified: false,
        otp: otp,
        otpExpiresAt: otpExpiresAt,
      })
      .returning();

    const emailLower = email.toLowerCase();
    console.log(`[Register] User created (id: ${newUser.id}), sending OTP email (non-blocking)…`);
    void sendOTPEmail(emailLower, otp).then(
      () => console.log(`[Register] OTP email sent to ${email}`),
      (emailError) =>
        console.error(`[Register] OTP email FAILED for ${email}:`, emailError.message)
    );

    const { password: _, otp: __, otpExpiresAt: ___, mfaSecret: ____, mfaTempSecret: _____, mfaBackupCodes: ______, ...userResponse } = newUser;

    await logActivity({
      userId: newUser.id,
      action: ACTIONS.REGISTER,
      req,
      metadata: { email: emailLower, role: userRole },
    });

    res.status(201).json({
      success: true,
      message: "User registered successfully. Please check your email for OTP verification.",
      user: userResponse,
    });
  } catch (error) {
    console.error("[Register] Error:", error.message);
    res.status(500).json({
      success: false,
      message: "Internal server error during registration",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Verify email with OTP
 */
const verifyEmail = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Check if user exists
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email.toLowerCase()))
      .limit(1);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Check if already verified
    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: "Email is already verified",
      });
    }

    // Verify OTP
    const isValid = await verifyOTP(email.toLowerCase(), otp);

    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // Update user as verified
    const [updatedUser] = await db
      .update(users)
      .set({
        isEmailVerified: true,
        updatedAt: new Date(),
      })
      .where(eq(users.id, user.id))
      .returning();

    // Remove password, otp, and otpExpiresAt from response
    const { password: _, otp: __, otpExpiresAt: ___, mfaSecret: ____, mfaTempSecret: _____, mfaBackupCodes: ______, ...userResponse } = updatedUser;

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
      user: userResponse,
    });
  } catch (error) {
    console.error("Email verification error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error during email verification",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Resend OTP
 */
const resendOTP = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    console.log(`[ResendOTP] Request for ${email}`);

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email.toLowerCase()))
      .limit(1);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: "Email is already verified",
      });
    }

    const emailLower = email.toLowerCase();
    const otp = await createOTP(emailLower);

    void sendOTPEmail(emailLower, otp).then(
      () => console.log(`[ResendOTP] OTP sent to ${email}`),
      (emailError) =>
        console.error(`[ResendOTP] Email FAILED for ${email}:`, emailError.message)
    );
    res.status(200).json({
      success: true,
      message: "OTP sent successfully. Please check your email.",
    });
  } catch (error) {
    console.error("[ResendOTP] Error:", error.message);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Login user
 */
const login = async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;

    // Check if user exists
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email.toLowerCase()))
      .limit(1);

    if (!user) {
      await logActivity({
        action: ACTIONS.LOGIN_FAILED,
        status: "failure",
        req,
        metadata: { email: email.toLowerCase(), reason: "user_not_found" },
      });
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Account temporarily locked from repeated failed attempts
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      // Clamp to at least 1: lockedUntil can tick into the past between the check
      // above and this calculation, which would otherwise floor to 0 or go negative.
      const minutesLeft = Math.max(
        1,
        Math.ceil((new Date(user.lockedUntil) - new Date()) / 60000)
      );
      await logActivity({
        userId: user.id,
        action: ACTIONS.LOGIN_FAILED,
        status: "failure",
        req,
        metadata: { reason: "account_locked" },
      });
      return res.status(423).json({
        success: false,
        message: `Too many failed attempts. Try again in ${minutesLeft} minute${minutesLeft === 1 ? "" : "s"}.`,
      });
    }

    // Past the CAPTCHA threshold: require a verified CAPTCHA before even checking the password
    const captchaRequired = user.failedLoginAttempts >= CAPTCHA_ATTEMPTS_THRESHOLD;
    if (captchaRequired) {
      const captchaOk = await verifyCaptcha(captchaToken);
      if (!captchaOk) {
        await logActivity({
          userId: user.id,
          action: ACTIONS.LOGIN_FAILED,
          status: "failure",
          req,
          metadata: { reason: "captcha_required" },
        });
        return res.status(400).json({
          success: false,
          captchaRequired: true,
          message: "Please complete the CAPTCHA to continue",
        });
      }
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      await logActivity({
        userId: user.id,
        action: ACTIONS.LOGIN_FAILED,
        status: "failure",
        req,
        metadata: { reason: "email_not_verified" },
      });
      return res.status(403).json({
        success: false,
        message: "Please verify your email before logging in",
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      const newFailedAttempts = user.failedLoginAttempts + 1;
      const shouldLock = newFailedAttempts >= LOCKOUT_THRESHOLD;

      await db
        .update(users)
        .set({
          failedLoginAttempts: shouldLock ? 0 : newFailedAttempts,
          lockedUntil: shouldLock
            ? new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000)
            : null,
          updatedAt: new Date(),
        })
        .where(eq(users.id, user.id));

      if (shouldLock) {
        await logActivity({
          userId: user.id,
          action: ACTIONS.ACCOUNT_LOCKED,
          status: "failure",
          req,
          metadata: { lockoutMinutes: LOCKOUT_MINUTES },
        });
        return res.status(423).json({
          success: false,
          message: `Too many failed attempts. Your account is locked for ${LOCKOUT_MINUTES} minutes.`,
        });
      }

      await logActivity({
        userId: user.id,
        action: ACTIONS.LOGIN_FAILED,
        status: "failure",
        req,
        metadata: { reason: "invalid_password", attempt: newFailedAttempts },
      });
      return res.status(401).json({
        success: false,
        captchaRequired: newFailedAttempts >= CAPTCHA_ATTEMPTS_THRESHOLD,
        message: "Invalid email or password",
      });
    }

    // Successful password check — clear any prior failed-attempt tracking
    if (user.failedLoginAttempts > 0 || user.lockedUntil) {
      await db
        .update(users)
        .set({ failedLoginAttempts: 0, lockedUntil: null, updatedAt: new Date() })
        .where(eq(users.id, user.id));
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error("JWT_SECRET is not defined in environment variables");
      return res.status(500).json({
        success: false,
        message: "Server configuration error",
      });
    }

    // Password is correct — if MFA is enabled, stop short of issuing a session
    // token and require a valid TOTP/backup code first.
    if (user.mfaEnabled) {
      const mfaToken = issueMfaPendingToken(user);
      await logActivity({ userId: user.id, action: ACTIONS.LOGIN_MFA_REQUIRED, req });
      return res.status(200).json({
        success: true,
        mfaRequired: true,
        mfaToken,
        message: "Enter your authenticator code to finish signing in",
      });
    }

    const token = issueSessionToken(user, req.headers["user-agent"]);

    // Remove password, otp, and otpExpiresAt from response
    const { password: _, otp: __, otpExpiresAt: ___, mfaSecret: ____, mfaTempSecret: _____, mfaBackupCodes: ______, ...userResponse } = user;

    await logActivity({ userId: user.id, action: ACTIONS.LOGIN_SUCCESS, req });

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: userResponse,
      token,
      passwordExpired: isPasswordExpired(user.passwordChangedAt),
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error during login",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Forgot password: send OTP to registered email (any user)
 */
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    console.log(`[ForgotPassword] Request for ${email}`);

    const [user] = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, email.toLowerCase()))
      .limit(1);

    if (!user) {
      await logActivity({
        action: ACTIONS.PASSWORD_RESET_REQUESTED,
        status: "failure",
        req,
        metadata: { email: email.toLowerCase(), reason: "user_not_found" },
      });
      return res.status(404).json({
        success: false,
        message: "No account found with this email address",
      });
    }

    const emailLower = email.toLowerCase();
    const otp = await createOTP(emailLower);

    void sendPasswordResetOTPEmail(emailLower, otp).then(
      () => console.log(`[ForgotPassword] OTP sent to ${email}`),
      (emailError) =>
        console.error(`[ForgotPassword] Email FAILED for ${email}:`, emailError.message)
    );

    await logActivity({ userId: user.id, action: ACTIONS.PASSWORD_RESET_REQUESTED, req });

    res.status(200).json({
      success: true,
      message: "OTP has been sent to your email. Use it to reset your password.",
    });
  } catch (error) {
    console.error("[ForgotPassword] Error:", error.message);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Verify OTP for forgot password (does not clear OTP; used before reset step)
 */
const verifyOTPForReset = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const isValid = await validateOTP(email.toLowerCase(), otp);

    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    res.status(200).json({
      success: true,
      message: "OTP verified successfully. You can now set a new password.",
    });
  } catch (error) {
    console.error("Verify OTP for reset error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Reset password: verify OTP (clears it), then update password
 */
const resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const emailLower = email.toLowerCase();

    const isValid = await verifyOTP(emailLower, otp);

    if (!isValid) {
      await logActivity({
        action: ACTIONS.PASSWORD_RESET_FAILED,
        status: "failure",
        req,
        metadata: { email: emailLower, reason: "invalid_otp" },
      });
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP. Please request a new one.",
      });
    }

    const [user] = await db
      .select({ id: users.id, password: users.password })
      .from(users)
      .where(eq(users.email, emailLower))
      .limit(1);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Password reuse prevention: reject resetting to the same password already in place
    const isSameAsCurrent = await bcrypt.compare(newPassword, user.password);
    if (isSameAsCurrent) {
      await logActivity({
        userId: user.id,
        action: ACTIONS.PASSWORD_RESET_FAILED,
        status: "failure",
        req,
        metadata: { reason: "password_reuse" },
      });
      return res.status(400).json({
        success: false,
        message: "New password must be different from your current password.",
      });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    await db
      .update(users)
      .set({
        password: hashedPassword,
        passwordChangedAt: new Date(),
        // A password reset should kill any session issued under the old password —
        // bumping tokenVersion invalidates every previously issued JWT at once.
        tokenVersion: sql`${users.tokenVersion} + 1`,
        updatedAt: new Date(),
      })
      .where(eq(users.email, emailLower));

    await logActivity({ userId: user.id, action: ACTIONS.PASSWORD_RESET_COMPLETED, req });

    res.status(200).json({
      success: true,
      message: "Password has been reset successfully. You can now sign in with your new password.",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * GET /auth/me – return current user from token (fresh from DB, includes isProfileVerified).
 */
const getMe = async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;
    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Access token required",
      });
    }

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const { password: _, otp: __, otpExpiresAt: ___, mfaSecret: ____, mfaTempSecret: _____, mfaBackupCodes: ______, ...userResponse } = user;

    res.status(200).json({
      success: true,
      user: userResponse,
      passwordExpired: isPasswordExpired(user.passwordChangedAt),
    });
  } catch (error) {
    console.error("Get me error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * POST /auth/login/mfa – complete login after password step by verifying a
 * TOTP or backup code against the short-lived mfaToken issued by login().
 */
const loginVerifyMfa = async (req, res) => {
  try {
    const { mfaToken, code } = req.body;

    if (!mfaToken || !code) {
      return res.status(400).json({
        success: false,
        message: "mfaToken and code are required",
      });
    }

    const jwtSecret = process.env.JWT_SECRET;
    let decoded;
    try {
      decoded = jwt.verify(mfaToken, jwtSecret);
    } catch {
      return res.status(401).json({
        success: false,
        message: "MFA session expired. Please log in again.",
      });
    }

    if (!decoded.mfaPending) {
      return res.status(401).json({
        success: false,
        message: "Invalid MFA session",
      });
    }

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, decoded.id))
      .limit(1);

    if (!user || !user.mfaEnabled) {
      return res.status(401).json({
        success: false,
        message: "Invalid MFA session",
      });
    }

    const isValid = await verifyLoginCode(user.id, code);
    if (!isValid) {
      await logActivity({
        userId: user.id,
        action: ACTIONS.MFA_LOGIN_VERIFY_FAILED,
        status: "failure",
        req,
      });
      return res.status(401).json({
        success: false,
        message: "Invalid or expired code",
      });
    }

    const token = issueSessionToken(user, req.headers["user-agent"]);
    const { password: _, otp: __, otpExpiresAt: ___, mfaSecret: ____, mfaTempSecret: _____, mfaBackupCodes: ______, ...userResponse } = user;

    await logActivity({ userId: user.id, action: ACTIONS.LOGIN_SUCCESS, req, metadata: { via: "mfa" } });

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: userResponse,
      token,
      passwordExpired: isPasswordExpired(user.passwordChangedAt),
    });
  } catch (error) {
    console.error("MFA login verification error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * POST /auth/mfa/setup – start enrollment: generate a pending TOTP secret and
 * return a QR code. MFA is not enabled until verifyMfaSetup confirms a code.
 */
const setupMfa = async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;

    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    if (user.mfaEnabled) {
      return res.status(400).json({
        success: false,
        message: "MFA is already enabled. Disable it first to re-enroll.",
      });
    }

    const { secret, qrCodeDataUrl } = await generateEnrollmentSecret(userId, user.email);

    await logActivity({ userId, action: ACTIONS.MFA_SETUP_STARTED, req });

    res.status(200).json({
      success: true,
      message: "Scan the QR code with your authenticator app, then confirm with a code",
      secret,
      qrCodeDataUrl,
    });
  } catch (error) {
    console.error("MFA setup error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * POST /auth/mfa/setup/verify – confirm enrollment with a code from the app.
 * On success, enables MFA and returns one-time backup codes (shown once).
 */
const verifyMfaSetup = async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ success: false, message: "Code is required" });
    }

    const result = await verifyAndEnableMfa(userId, code);
    if (!result.success) {
      await logActivity({ userId, action: ACTIONS.MFA_SETUP_FAILED, status: "failure", req });
      return res.status(400).json({ success: false, message: result.message });
    }

    await logActivity({ userId, action: ACTIONS.MFA_ENABLED, req });

    res.status(200).json({
      success: true,
      message: "MFA enabled successfully. Save these backup codes somewhere safe — they won't be shown again.",
      backupCodes: result.backupCodes,
    });
  } catch (error) {
    console.error("MFA setup verification error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * POST /auth/mfa/disable – turn MFA off. Requires the current password (and,
 * if still available, a valid code) so a hijacked session token alone can't
 * strip a second factor off the account.
 */
const disableMfaController = async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        success: false,
        message: "Current password is required to disable MFA",
      });
    }

    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await logActivity({ userId, action: ACTIONS.MFA_DISABLE_FAILED, status: "failure", req });
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    await disableMfa(userId);

    await logActivity({ userId, action: ACTIONS.MFA_DISABLED, req });

    res.status(200).json({ success: true, message: "MFA has been disabled" });
  } catch (error) {
    console.error("MFA disable error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * POST /auth/logout – server-side session invalidation. Bumps tokenVersion so
 * the token just used (and any other copies of it) fails verification on its
 * very next use, instead of staying valid until its exp claim naturally expires.
 */
const logoutController = async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;

    await db
      .update(users)
      .set({ tokenVersion: sql`${users.tokenVersion} + 1`, updatedAt: new Date() })
      .where(eq(users.id, userId));

    await logActivity({ userId, action: ACTIONS.LOGOUT, req });

    res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

export {
  disableMfaController,
  forgotPassword,
  getMe,
  login,
  loginVerifyMfa,
  logoutController,
  register,
  resendOTP,
  resetPassword,
  setupMfa,
  verifyEmail,
  verifyMfaSetup,
  verifyOTPForReset
};

