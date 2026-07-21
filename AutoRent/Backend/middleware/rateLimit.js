import rateLimit from "express-rate-limit";

const jsonLimitHandler = (req, res) => {
  res.status(429).json({
    success: false,
    message: "Too many requests. Please wait a while before trying again.",
  });
};

/** Login attempts: generous enough for real users mistyping, tight enough to slow credential stuffing. */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: jsonLimitHandler,
});

/** Registration: prevents mass fake-account creation from a single IP. */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  handler: jsonLimitHandler,
});

/** Forgot-password / reset-password: also bounds the email-sending cost of the flow. */
const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: jsonLimitHandler,
});

/** Email OTP verify + resend (registration flow). */
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: jsonLimitHandler,
});

/** MFA code verification (login step + enrollment confirm): 6-digit codes are guessable if unbounded. */
const mfaVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: jsonLimitHandler,
});

export {
  forgotPasswordLimiter,
  loginLimiter,
  mfaVerifyLimiter,
  otpLimiter,
  registerLimiter,
};
