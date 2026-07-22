import { faTriangleExclamation } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { getAuthToken } from "../utils/api.js";

const computeInitialVisibility = () => {
  const dismissed = sessionStorage.getItem("passwordExpiredBannerDismissed") === "true";
  if (dismissed || !getAuthToken()) return false;
  try {
    const user = JSON.parse(localStorage.getItem("user") || "null");
    return !!user?.passwordExpired;
  } catch {
    return false;
  }
};

/**
 * Prompts a password change once the account's password is older than the
 * server's expiry window (see passwordChangedAt / PASSWORD_EXPIRY_DAYS).
 * Dismissible per browser session — reappears next login if still expired.
 */
const PasswordExpiredBanner = ({ onOpenForgotPassword }) => {
  const [visible, setVisible] = useState(computeInitialVisibility);

  if (!visible) return null;

  const dismiss = () => {
    sessionStorage.setItem("passwordExpiredBannerDismissed", "true");
    setVisible(false);
  };

  return (
    <div className="relative z-40 flex flex-wrap items-center justify-center gap-3 bg-amber-500/90 px-4 py-2.5 text-center text-sm font-medium text-black">
      <FontAwesomeIcon icon={faTriangleExclamation} className="h-4 w-4" />
      <span>Your password is over 90 days old. For your account's security, please change it.</span>
      <button
        type="button"
        onClick={() => {
          dismiss();
          onOpenForgotPassword?.();
        }}
        className="rounded-lg bg-black/80 px-3 py-1 text-xs font-bold text-white transition hover:bg-black"
      >
        Change password
      </button>
      <button
        type="button"
        onClick={dismiss}
        className="text-xs font-semibold text-black/70 underline hover:text-black"
      >
        Dismiss
      </button>
    </div>
  );
};

export default PasswordExpiredBanner;
