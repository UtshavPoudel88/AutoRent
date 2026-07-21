const VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

/**
 * Verifies a Google reCAPTCHA v2 token server-side.
 * If RECAPTCHA_SECRET_KEY is not configured, CAPTCHA enforcement is disabled
 * (logs a warning once) so the app keeps working before keys are provisioned —
 * set the key in production to actually enforce it.
 */
const isCaptchaConfigured = () => !!process.env.RECAPTCHA_SECRET_KEY;

let warnedOnce = false;

const verifyCaptcha = async (token) => {
  if (!isCaptchaConfigured()) {
    if (!warnedOnce) {
      console.warn(
        "[Captcha] RECAPTCHA_SECRET_KEY not set — CAPTCHA checks are disabled. Set it in .env to enforce."
      );
      warnedOnce = true;
    }
    return true;
  }

  if (!token || typeof token !== "string") return false;

  try {
    const params = new URLSearchParams({
      secret: process.env.RECAPTCHA_SECRET_KEY,
      response: token,
    });
    const res = await fetch(VERIFY_URL, { method: "POST", body: params });
    const data = await res.json();
    return data.success === true;
  } catch (err) {
    console.error("[Captcha] Verification request failed:", err.message);
    return false;
  }
};

export { isCaptchaConfigured, verifyCaptcha };
