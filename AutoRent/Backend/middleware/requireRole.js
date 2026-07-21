/**
 * Server-side role gate. Must run after authenticateToken, which sets req.user
 * from a verified JWT — so role here can't be spoofed via the client, the
 * request body, or a tampered token (jwt.verify already rejects those).
 *
 * Usage: router.get("/admin/x", authenticateToken, requireRole("admin"), handler)
 * or blanket-guard a whole router: router.use(requireRole("admin"))
 */
const requireRole = (...allowedRoles) => (req, res, next) => {
  if (!req.user?.role || !allowedRoles.includes(req.user.role)) {
    return res.status(403).json({
      success: false,
      message: `Access denied. Requires role: ${allowedRoles.join(" or ")}`,
    });
  }
  next();
};

export { requireRole };
