import zxcvbn from "zxcvbn";

const MIN_LENGTH = 8;
/** zxcvbn score is 0-4 (0/1 = weak-guessable, 2 = fair, 3-4 = strong). Reject anything below this. */
const MIN_ZXCVBN_SCORE = 2;
/** Passwords older than this are flagged as expired, prompting a change (not blocking login). */
const PASSWORD_EXPIRY_DAYS = 90;

const hasUpper = (s) => /[A-Z]/.test(s);
const hasLower = (s) => /[a-z]/.test(s);
const hasNumber = (s) => /\d/.test(s);
const hasSymbol = (s) => /[^A-Za-z0-9]/.test(s);

/**
 * Full password policy check: length, character classes, and zxcvbn strength
 * (which also catches common/breached-pattern passwords via its frequency
 * dictionaries — "password123", "qwerty", names, keyboard patterns, etc.).
 * @param {string} password
 * @param {string[]} [userInputs] - Context values (email, name) to penalize if reused in the password.
 * @returns {{ valid: boolean, errors: string[], score: number }}
 */
const validatePasswordPolicy = (password, userInputs = []) => {
  if (!password || typeof password !== "string") {
    return { valid: false, errors: ["Password is required"], score: 0 };
  }

  const errors = [];
  if (password.length < MIN_LENGTH) {
    errors.push(`Password must be at least ${MIN_LENGTH} characters long`);
  }
  if (!hasUpper(password)) errors.push("Password must include at least one uppercase letter");
  if (!hasLower(password)) errors.push("Password must include at least one lowercase letter");
  if (!hasNumber(password)) errors.push("Password must include at least one number");
  if (!hasSymbol(password)) errors.push("Password must include at least one symbol (e.g. !@#$%^&*)");

  const result = zxcvbn(password, userInputs.filter(Boolean));
  if (result.score < MIN_ZXCVBN_SCORE) {
    const suggestion = result.feedback?.warning || result.feedback?.suggestions?.[0];
    errors.push(
      suggestion
        ? `Password is too weak or common: ${suggestion}`
        : "Password is too weak or common. Choose something less predictable."
    );
  }

  return { valid: errors.length === 0, errors, score: result.score };
};

/** True once passwordChangedAt is older than PASSWORD_EXPIRY_DAYS. */
const isPasswordExpired = (passwordChangedAt) => {
  if (!passwordChangedAt) return false;
  const changedAt =
    passwordChangedAt instanceof Date ? passwordChangedAt : new Date(passwordChangedAt);
  if (Number.isNaN(changedAt.getTime())) return false;
  const ageMs = Date.now() - changedAt.getTime();
  return ageMs > PASSWORD_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
};

export {
  isPasswordExpired,
  MIN_LENGTH,
  MIN_ZXCVBN_SCORE,
  PASSWORD_EXPIRY_DAYS,
  validatePasswordPolicy,
};
