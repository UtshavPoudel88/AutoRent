import { useEffect, useState } from "react";

let zxcvbnPromise = null;
/** zxcvbn is ~800KB — load it lazily only once a user starts typing a password. */
const loadZxcvbn = () => {
  if (!zxcvbnPromise) {
    zxcvbnPromise = import("zxcvbn").then((mod) => mod.default ?? mod);
  }
  return zxcvbnPromise;
};

const LEVELS = [
  { label: "Weak", barClass: "bg-red-500", textClass: "text-red-400" },
  { label: "Weak", barClass: "bg-red-500", textClass: "text-red-400" },
  { label: "Medium", barClass: "bg-amber-500", textClass: "text-amber-400" },
  { label: "Strong", barClass: "bg-emerald-500", textClass: "text-emerald-400" },
  { label: "Strong", barClass: "bg-emerald-500", textClass: "text-emerald-400" },
];

/**
 * Live password strength indicator (weak/medium/strong) backed by zxcvbn,
 * the same scoring approach the backend uses to reject common/guessable passwords.
 * @param {string} password
 * @param {string[]} [userInputs] - Context values (email, name) zxcvbn penalizes if reused.
 */
const PasswordStrengthMeter = ({ password, userInputs = [] }) => {
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!password) {
      setResult(null);
      return undefined;
    }
    let cancelled = false;
    loadZxcvbn().then((zxcvbn) => {
      if (!cancelled) {
        setResult(zxcvbn(password, userInputs.filter(Boolean)));
      }
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [password]);

  if (!password) return null;

  const score = result?.score ?? 0;
  const level = LEVELS[score];
  const warning = result?.feedback?.warning;

  return (
    <div className="mt-2">
      <div className="flex gap-1">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className={`h-1.5 flex-1 rounded-full transition-colors ${
              i <= score ? level.barClass : "bg-white/10"
            }`}
          />
        ))}
      </div>
      <div className="mt-1 flex items-center justify-between">
        <span className={`text-xs font-semibold ${level.textClass}`}>{level.label}</span>
        {warning && <span className="text-xs text-white/40">{warning}</span>}
      </div>
    </div>
  );
};

export default PasswordStrengthMeter;
