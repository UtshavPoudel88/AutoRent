import { faKey, faLock, faShieldHalved } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { mfaAPI } from "../utils/api.js";

/**
 * Self-contained MFA (TOTP) enrollment / disable panel.
 * variant="dark" for the black/orange renter theme; default "light" for the
 * white/slate owner + admin dashboards.
 */
const MfaSettings = ({ user, variant = "light" }) => {
  const dark = variant === "dark";
  const [phase, setPhase] = useState("idle"); // idle | confirming | backupCodes | disabling
  const [mfaEnabled, setMfaEnabled] = useState(!!user.mfaEnabled);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState([]);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const cardClass = dark
    ? "rounded-2xl border border-white/10 bg-white/[0.04] p-8 text-white"
    : "dash-panel rounded-2xl border border-slate-100 bg-white p-5 sm:p-8 text-slate-900";
  const mutedClass = dark ? "text-white/60" : "text-slate-500";
  const inputClass = dark
    ? "w-full rounded-xl border border-white/10 bg-white/5 py-3 px-4 text-white placeholder:text-white/40 focus:border-orange-500/50 focus:outline-none focus:ring-2 focus:ring-orange-500/20"
    : "w-full rounded-xl border border-slate-200 bg-white py-3 px-4 text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-2 focus:ring-indigo-100";
  const primaryBtnClass = dark
    ? "rounded-xl bg-orange-500 px-5 py-2.5 text-sm font-bold text-black transition hover:bg-orange-400 disabled:opacity-50"
    : "rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-bold text-white transition hover:bg-indigo-500 disabled:opacity-50";
  const dangerBtnClass = dark
    ? "rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-2.5 text-sm font-bold text-red-400 transition hover:bg-red-500/20 disabled:opacity-50"
    : "rounded-xl border border-red-200 bg-red-50 px-5 py-2.5 text-sm font-bold text-red-600 transition hover:bg-red-100 disabled:opacity-50";
  const ghostBtnClass = dark
    ? "text-sm font-medium text-white/60 hover:text-white/80"
    : "text-sm font-medium text-slate-500 hover:text-slate-700";

  const reset = () => {
    setPhase("idle");
    setQrCodeDataUrl("");
    setSecret("");
    setCode("");
    setBackupCodes([]);
    setPassword("");
    setError("");
  };

  const startEnrollment = async () => {
    setError("");
    setIsLoading(true);
    try {
      const res = await mfaAPI.setup();
      setQrCodeDataUrl(res.qrCodeDataUrl);
      setSecret(res.secret);
      setPhase("confirming");
    } catch (err) {
      setError(err.message || "Failed to start MFA setup");
    } finally {
      setIsLoading(false);
    }
  };

  const confirmEnrollment = async (e) => {
    e.preventDefault();
    if (!/^\d{6}$/.test(code.trim())) {
      setError("Enter the 6-digit code from your authenticator app");
      return;
    }
    setError("");
    setIsLoading(true);
    try {
      const res = await mfaAPI.verifySetup(code.trim());
      setBackupCodes(res.backupCodes || []);
      setPhase("backupCodes");
      setMfaEnabled(true);
    } catch (err) {
      setError(err.message || "Invalid code. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisable = async (e) => {
    e.preventDefault();
    if (!password) {
      setError("Enter your current password");
      return;
    }
    setError("");
    setIsLoading(true);
    try {
      await mfaAPI.disable(password);
      setMfaEnabled(false);
      reset();
    } catch (err) {
      setError(err.message || "Failed to disable MFA");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={cardClass}>
      <div className="mb-4 flex items-center gap-3">
        <FontAwesomeIcon icon={faShieldHalved} className="h-5 w-5 text-amber-400" />
        <h3 className="text-xl font-bold">Two-Factor Authentication</h3>
      </div>

      {error && (
        <div className="mb-4 rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {phase === "idle" && (
        <>
          <p className={`mb-4 text-sm ${mutedClass}`}>
            {mfaEnabled
              ? "MFA is enabled. You'll be asked for a code from your authenticator app every time you sign in."
              : "Add an extra layer of security by requiring a code from an authenticator app (Google Authenticator, Authy, 1Password, etc.) at login."}
          </p>
          {mfaEnabled ? (
            <button
              type="button"
              onClick={() => setPhase("disabling")}
              className={dangerBtnClass}
            >
              Disable MFA
            </button>
          ) : (
            <button
              type="button"
              onClick={startEnrollment}
              disabled={isLoading}
              className={primaryBtnClass}
            >
              {isLoading ? "Starting..." : "Enable MFA"}
            </button>
          )}
        </>
      )}

      {phase === "confirming" && (
        <form onSubmit={confirmEnrollment} className="space-y-4">
          <p className={`text-sm ${mutedClass}`}>
            Scan this QR code with your authenticator app, then enter the 6-digit code it shows.
          </p>
          {qrCodeDataUrl && (
            <img
              src={qrCodeDataUrl}
              alt="MFA QR code"
              className="mx-auto h-48 w-48 rounded-xl border border-white/10 bg-white p-2"
            />
          )}
          <p className={`text-center text-xs ${mutedClass}`}>
            Can't scan? Enter this code manually:{" "}
            <span className="font-mono font-semibold">{secret}</span>
          </p>
          <div className="relative">
            <FontAwesomeIcon
              icon={faKey}
              className={`absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 ${mutedClass}`}
            />
            <input
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              className={`${inputClass} pl-11 text-center text-xl font-bold tracking-widest`}
              autoComplete="one-time-code"
            />
          </div>
          <div className="flex gap-3">
            <button
              type="submit"
              disabled={isLoading || code.length !== 6}
              className={primaryBtnClass}
            >
              {isLoading ? "Verifying..." : "Confirm & Enable"}
            </button>
            <button type="button" onClick={reset} className={ghostBtnClass}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {phase === "backupCodes" && (
        <div className="space-y-4">
          <p className="text-sm font-semibold text-emerald-400">
            MFA is now enabled. Save these backup codes somewhere safe — each can be used once
            if you lose access to your authenticator app. They won't be shown again.
          </p>
          <div
            className={`grid grid-cols-2 gap-2 rounded-xl p-4 font-mono text-sm ${
              dark ? "bg-white/5 border border-white/10" : "bg-slate-50 border border-slate-200"
            }`}
          >
            {backupCodes.map((c) => (
              <div key={c}>{c}</div>
            ))}
          </div>
          <button type="button" onClick={reset} className={primaryBtnClass}>
            Done
          </button>
        </div>
      )}

      {phase === "disabling" && (
        <form onSubmit={handleDisable} className="space-y-4">
          <p className={`text-sm ${mutedClass}`}>
            Enter your current password to disable two-factor authentication.
          </p>
          <div className="relative">
            <FontAwesomeIcon
              icon={faLock}
              className={`absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 ${mutedClass}`}
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Current password"
              className={`${inputClass} pl-11`}
            />
          </div>
          <div className="flex gap-3">
            <button type="submit" disabled={isLoading} className={dangerBtnClass}>
              {isLoading ? "Disabling..." : "Confirm Disable"}
            </button>
            <button type="button" onClick={reset} className={ghostBtnClass}>
              Cancel
            </button>
          </div>
        </form>
      )}
    </div>
  );
};

export default MfaSettings;
