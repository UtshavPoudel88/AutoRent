import {
  faEnvelope,
  faEye,
  faEyeSlash,
  faKey,
  faLock,
  faTimes,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import ReCaptcha from "./ReCaptcha.jsx";
import { authAPI, setAuthToken } from "../utils/api.js";
import { validateLoginForm, validateOtp } from "../utils/formValidation.js";

/** If no site key is configured, the widget doesn't render — don't block submit waiting for a token that'll never come. */
const CAPTCHA_CONFIGURED = !!import.meta.env.VITE_RECAPTCHA_SITE_KEY;

const LoginModal = ({
  isOpen,
  onClose,
  onSwitchToSignUp,
  onSwitchToForgotPassword,
  onLoginSuccess,
}) => {
  const [step, setStep] = useState("login"); // 'login' | 'verify' | 'mfa'
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [captchaRequired, setCaptchaRequired] = useState(false);
  const [captchaToken, setCaptchaToken] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  if (!isOpen) return null;

  const completeLogin = (response) => {
    if (response.token) {
      setAuthToken(response.token);
    }
    if (response.user) {
      localStorage.setItem(
        "user",
        JSON.stringify({ ...response.user, passwordExpired: !!response.passwordExpired })
      );
    }
    if (onLoginSuccess) {
      onLoginSuccess(response);
    } else {
      onClose();
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    const clientErr = validateLoginForm({ email, password });
    if (clientErr) {
      setError(clientErr);
      return;
    }
    if (captchaRequired && CAPTCHA_CONFIGURED && !captchaToken) {
      setError("Please complete the CAPTCHA to continue");
      return;
    }
    setIsLoading(true);

    try {
      const response = await authAPI.login(email, password, captchaToken || undefined);
      if (response.mfaRequired) {
        setMfaToken(response.mfaToken);
        setStep("mfa");
      } else {
        completeLogin(response);
      }
    } catch (err) {
      if (err.data?.captchaRequired) {
        setCaptchaRequired(true);
        setCaptchaToken("");
      }
      const message = err.message || "Invalid email or password. Please try again.";
      if (/verify your email/i.test(message)) {
        setError("");
        setStep("verify");
        // Send a fresh OTP right away since any prior one has likely expired
        try {
          await authAPI.resendOTP(email);
          setSuccess("We've sent a verification code to your email");
          setTimeout(() => setSuccess(""), 5000);
        } catch {
          // Ignore — user can still tap "Resend OTP" manually
        }
      } else {
        setError(message);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyMfa = async (e) => {
    e.preventDefault();
    setError("");

    const trimmed = mfaCode.trim();
    if (!/^\d{6}$/.test(trimmed) && !/^[a-f0-9]{10}$/i.test(trimmed)) {
      setError("Enter your 6-digit authenticator code or a backup code.");
      return;
    }

    setIsLoading(true);
    try {
      const response = await authAPI.loginVerifyMfa(mfaToken, trimmed);
      completeLogin(response);
    } catch (err) {
      setError(err.message || "Invalid or expired code. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyEmail = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const otpErr = validateOtp(otp, 6);
    if (otpErr) {
      setError(otpErr);
      return;
    }

    setIsLoading(true);

    try {
      await authAPI.verifyEmail(email, otp);
      // Email is now verified — log the user in with the credentials they already entered
      const response = await authAPI.login(email, password);
      completeLogin(response);
    } catch (err) {
      setError(err.message || "Invalid or expired OTP. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendOTP = async () => {
    setError("");
    setSuccess("");
    setIsLoading(true);

    try {
      const response = await authAPI.resendOTP(email);
      if (response.success) {
        setSuccess("OTP has been resent to your email");
        setTimeout(() => setSuccess(""), 5000);
      }
    } catch (err) {
      setError(err.message || "Failed to resend OTP. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    setStep("login");
    setOtp("");
    setMfaToken("");
    setMfaCode("");
    setCaptchaRequired(false);
    setCaptchaToken("");
    setError("");
    setSuccess("");
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={handleClose}
        aria-hidden="true"
      />

      {/* Modal */}
      <div className="relative z-10 w-full max-w-md rounded-2xl border border-white/10 bg-gradient-to-br from-black/95 to-black/90 p-8 shadow-2xl backdrop-blur-xl">
        {/* Close button */}
        <button
          type="button"
          onClick={handleClose}
          className="absolute right-4 top-4 rounded-lg p-2 text-white/60 transition hover:bg-white/5 hover:text-white"
          aria-label="Close"
        >
          <FontAwesomeIcon icon={faTimes} className="h-5 w-5" />
        </button>

        {/* Header */}
        <div className="mb-8 text-center">
          <h2 className="text-3xl font-extrabold text-white">
            {step === "login"
              ? "Welcome Back"
              : step === "mfa"
                ? "Two-Factor Verification"
                : "Verify Your Email"}
          </h2>
          <p className="mt-2 text-sm text-white/60">
            {step === "login"
              ? "Sign in to your AutoRent account"
              : step === "mfa"
                ? "Enter the code from your authenticator app (or a backup code)"
                : "Enter the 6-digit code sent to your email to finish signing in"}
          </p>
        </div>

        {/* Success message */}
        {success && (
          <div className="mb-5 rounded-xl bg-green-500/10 border border-green-500/20 p-3 text-sm text-green-400">
            {success}
          </div>
        )}

        {/* Login Form */}
        {step === "login" && (
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Error message */}
            {error && (
              <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-400">
                {error}
              </div>
            )}

            {/* Email field */}
            <div>
              <label
                htmlFor="login-email"
                className="mb-2 block text-sm font-medium text-white/80"
              >
                Email Address
              </label>
              <div className="relative">
                <FontAwesomeIcon
                  icon={faEnvelope}
                  className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-white/40"
                />
                <input
                  id="login-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="you@example.com"
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-12 pr-4 text-white placeholder:text-white/40 focus:border-orange-500/50 focus:bg-white/10 focus:outline-none focus:ring-2 focus:ring-orange-500/20 transition"
                />
              </div>
            </div>

            {/* Password field */}
            <div>
              <label
                htmlFor="login-password"
                className="mb-2 block text-sm font-medium text-white/80"
              >
                Password
              </label>
              <div className="relative">
                <FontAwesomeIcon
                  icon={faLock}
                  className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-white/40"
                />
                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="Enter your password"
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-12 pr-12 text-white placeholder:text-white/40 focus:border-orange-500/50 focus:bg-white/10 focus:outline-none focus:ring-2 focus:ring-orange-500/20 transition"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-white/40 transition hover:text-white/60"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  <FontAwesomeIcon
                    icon={showPassword ? faEyeSlash : faEye}
                    className="h-5 w-5"
                  />
                </button>
              </div>
            </div>

            {/* Forgot password link */}
            <div className="flex items-center justify-end">
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onSwitchToForgotPassword();
                }}
                className="text-sm font-medium text-orange-400 transition hover:text-orange-300"
              >
                Forgot Password?
              </button>
            </div>

            {/* CAPTCHA — only shown after repeated failed attempts */}
            {captchaRequired && (
              <ReCaptcha onVerify={(token) => setCaptchaToken(token || "")} />
            )}

            {/* Submit button */}
            <button
              type="submit"
              disabled={isLoading || (captchaRequired && CAPTCHA_CONFIGURED && !captchaToken)}
              className="w-full cursor-pointer rounded-xl bg-orange-500 py-3 text-base font-bold text-black shadow-[0_8px_30px_rgba(249,115,22,0.35)] transition-all duration-300 hover:scale-105 hover:bg-orange-400 focus:outline-none focus:ring-2 focus:ring-orange-300 focus:ring-offset-2 focus:ring-offset-black disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              {isLoading ? "Signing in..." : "Sign In"}
            </button>
          </form>
        )}

        {/* OTP Verification Form */}
        {step === "verify" && (
          <form onSubmit={handleVerifyEmail} className="space-y-5">
            {/* Error message */}
            {error && (
              <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-400">
                {error}
              </div>
            )}

            <div>
              <label
                htmlFor="login-otp"
                className="mb-2 block text-sm font-medium text-white/80"
              >
                6-Digit OTP Code
              </label>
              <div className="relative">
                <FontAwesomeIcon
                  icon={faKey}
                  className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-white/40"
                />
                <input
                  id="login-otp"
                  type="text"
                  value={otp}
                  onChange={(e) => {
                    const value = e.target.value.replace(/\D/g, "").slice(0, 6);
                    setOtp(value);
                  }}
                  required
                  placeholder="000000"
                  maxLength={6}
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-12 pr-4 text-center text-2xl font-bold tracking-widest text-white placeholder:text-white/20 focus:border-orange-500/50 focus:bg-white/10 focus:outline-none focus:ring-2 focus:ring-orange-500/20 transition"
                />
              </div>
              <p className="mt-2 text-xs text-white/50">
                Didn't receive the code?{" "}
                <button
                  type="button"
                  onClick={handleResendOTP}
                  disabled={isLoading}
                  className="font-medium text-orange-400 hover:text-orange-300 disabled:opacity-50"
                >
                  Resend OTP
                </button>
              </p>
            </div>

            <button
              type="submit"
              disabled={isLoading || otp.length !== 6}
              className="w-full cursor-pointer rounded-xl bg-orange-500 py-3 text-base font-bold text-black shadow-[0_8px_30px_rgba(249,115,22,0.35)] transition-all duration-300 hover:scale-105 hover:bg-orange-400 focus:outline-none focus:ring-2 focus:ring-orange-300 focus:ring-offset-2 focus:ring-offset-black disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              {isLoading ? "Verifying..." : "Verify Email"}
            </button>

            <button
              type="button"
              onClick={() => {
                setStep("login");
                setOtp("");
                setError("");
              }}
              className="w-full text-center text-sm font-medium text-white/60 hover:text-white/80"
            >
              Back to Sign In
            </button>
          </form>
        )}

        {/* MFA Verification Form */}
        {step === "mfa" && (
          <form onSubmit={handleVerifyMfa} className="space-y-5">
            {error && (
              <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-400">
                {error}
              </div>
            )}

            <div>
              <label
                htmlFor="login-mfa-code"
                className="mb-2 block text-sm font-medium text-white/80"
              >
                Authenticator Code
              </label>
              <div className="relative">
                <FontAwesomeIcon
                  icon={faKey}
                  className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-white/40"
                />
                <input
                  id="login-mfa-code"
                  type="text"
                  value={mfaCode}
                  onChange={(e) =>
                    setMfaCode(e.target.value.replace(/[^a-zA-Z0-9]/g, "").slice(0, 10))
                  }
                  required
                  autoComplete="one-time-code"
                  placeholder="000000"
                  maxLength={10}
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-12 pr-4 text-center text-2xl font-bold tracking-widest text-white placeholder:text-white/20 focus:border-orange-500/50 focus:bg-white/10 focus:outline-none focus:ring-2 focus:ring-orange-500/20 transition"
                />
              </div>
              <p className="mt-2 text-xs text-white/50">
                Lost your device? Use one of your 10-character backup codes instead.
              </p>
            </div>

            <button
              type="submit"
              disabled={isLoading || mfaCode.length < 6}
              className="w-full cursor-pointer rounded-xl bg-orange-500 py-3 text-base font-bold text-black shadow-[0_8px_30px_rgba(249,115,22,0.35)] transition-all duration-300 hover:scale-105 hover:bg-orange-400 focus:outline-none focus:ring-2 focus:ring-orange-300 focus:ring-offset-2 focus:ring-offset-black disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              {isLoading ? "Verifying..." : "Verify"}
            </button>

            <button
              type="button"
              onClick={() => {
                setStep("login");
                setMfaCode("");
                setMfaToken("");
                setError("");
              }}
              className="w-full text-center text-sm font-medium text-white/60 hover:text-white/80"
            >
              Back to Sign In
            </button>
          </form>
        )}

        {/* Switch to Sign Up */}
        {step === "login" && (
          <div className="mt-6 text-center text-sm text-white/60">
            Don't have an account?{" "}
            <button
              type="button"
              onClick={() => {
                onClose();
                onSwitchToSignUp();
              }}
              className="font-semibold text-orange-400 transition hover:text-orange-300"
            >
              Sign Up
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default LoginModal;
