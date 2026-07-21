import express from "express";
import {
  disableMfaController,
  forgotPassword,
  getMe,
  login,
  loginVerifyMfa,
  register,
  resendOTP,
  resetPassword,
  setupMfa,
  verifyEmail,
  verifyMfaSetup,
  verifyOTPForReset,
} from "../controller/authController.js";
import {
  createUserDetailsController,
  getUserDetailsController,
  updateUserDetailsController,
  verifyLicenseController
} from "../controller/userDetailsController.js";
import { authenticateToken } from "../middleware/auth.js";
import {
  validateForgotPassword,
  validateLogin,
  validateMfaDisable,
  validateMfaLoginVerify,
  validateMfaSetupVerify,
  validateOTPVerification,
  validateRegistration,
  validateResetPassword,
} from "../middleware/validation.js";

const router = express.Router();

// ==================== Authentication Routes ====================

// Register new user
router.post("/auth/register", validateRegistration, register);

// Verify email with OTP
router.post("/auth/verify-email", validateOTPVerification, verifyEmail);

// Resend OTP
router.post("/auth/resend-otp", resendOTP);

// Login user
router.post("/auth/login", validateLogin, login);

// Forgot password: send OTP to registered email
router.post("/auth/forgot-password", validateForgotPassword, forgotPassword);

// Verify OTP (for forgot password; does not clear OTP)
router.post("/auth/verify-otp", validateOTPVerification, verifyOTPForReset);

// Reset password: verify OTP (clears it) and set new password
router.post("/auth/reset-password", validateResetPassword, resetPassword);

// Get current user (auth required; returns fresh user including isProfileVerified)
router.get("/auth/me", authenticateToken, getMe);

// ==================== MFA (TOTP) Routes ====================

// Complete login after password step by verifying a TOTP/backup code (public — gated by short-lived mfaToken)
router.post("/auth/login/mfa", validateMfaLoginVerify, loginVerifyMfa);

// Start MFA enrollment: generate secret + QR code (auth required)
router.post("/auth/mfa/setup", authenticateToken, setupMfa);

// Confirm MFA enrollment with a code from the authenticator app (auth required)
router.post("/auth/mfa/setup/verify", authenticateToken, validateMfaSetupVerify, verifyMfaSetup);

// Disable MFA — requires current password (auth required)
router.post("/auth/mfa/disable", authenticateToken, validateMfaDisable, disableMfaController);

// ==================== User Details Routes ====================

// All user details routes require authentication
router.use("/user-details", authenticateToken);

// Get user details by user ID
router.get("/user-details/:userId", getUserDetailsController);

// Create user details
router.post("/user-details", createUserDetailsController);

// Update user details
router.put("/user-details/:userId", updateUserDetailsController);

// Verify license (Admin only)
router.patch("/user-details/:userId/verify-license", verifyLicenseController);

export default router;
