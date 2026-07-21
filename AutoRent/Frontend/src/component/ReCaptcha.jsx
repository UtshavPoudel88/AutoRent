import { useEffect, useRef } from "react";

const SITE_KEY = import.meta.env.VITE_RECAPTCHA_SITE_KEY;
const SCRIPT_ID = "recaptcha-script";

let scriptLoadingPromise = null;
const loadRecaptchaScript = () => {
  if (window.grecaptcha?.render) return Promise.resolve();
  if (scriptLoadingPromise) return scriptLoadingPromise;

  scriptLoadingPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.id = SCRIPT_ID;
    script.src = "https://www.google.com/recaptcha/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.onload = resolve;
    script.onerror = reject;
    document.head.appendChild(script);
  });
  return scriptLoadingPromise;
};

/**
 * Google reCAPTCHA v2 checkbox widget. Renders nothing if VITE_RECAPTCHA_SITE_KEY
 * isn't configured — matches the backend, which skips CAPTCHA enforcement when
 * RECAPTCHA_SECRET_KEY isn't set.
 */
const ReCaptcha = ({ onVerify }) => {
  const containerRef = useRef(null);
  const widgetIdRef = useRef(null);

  useEffect(() => {
    if (!SITE_KEY) return undefined;
    let cancelled = false;

    loadRecaptchaScript().then(() => {
      if (cancelled || !containerRef.current || widgetIdRef.current !== null) return;
      widgetIdRef.current = window.grecaptcha.render(containerRef.current, {
        sitekey: SITE_KEY,
        callback: (token) => onVerify?.(token),
        "expired-callback": () => onVerify?.(null),
        "error-callback": () => onVerify?.(null),
      });
    });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!SITE_KEY) return null;

  return <div ref={containerRef} className="flex justify-center" />;
};

export default ReCaptcha;
