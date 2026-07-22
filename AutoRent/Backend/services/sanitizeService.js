import DOMPurify from "isomorphic-dompurify";

/**
 * Strips all HTML/script content from a value, keeping only its text.
 * Applied to free-text user input (names, review comments, contact messages,
 * vehicle descriptions, addresses, notes) at write time. React already escapes
 * on render — this is defense in depth for the other consumers of this data:
 * outbound HTML emails, PDF invoices, admin exports, and any future client.
 */
const sanitizePlainText = (input) => {
  if (input == null) return input;
  const str = String(input);
  return DOMPurify.sanitize(str, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }).trim();
};

export { sanitizePlainText };
