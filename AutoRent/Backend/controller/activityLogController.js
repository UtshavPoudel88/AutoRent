import { getActivityLogs, getSuspiciousActivity } from "../services/activityLogService.js";

/**
 * GET /admin/activity-log
 * Filterable audit trail for security review / incident response (admin only).
 * Query: userId, action, status ("success"|"failure"), from, to (ISO), limit, offset
 */
const getActivityLogController = async (req, res) => {
  try {
    const { userId, action, status, from, to, limit, offset } = req.query;

    if (status && status !== "success" && status !== "failure") {
      return res.status(400).json({
        success: false,
        message: "status must be 'success' or 'failure'",
      });
    }

    const result = await getActivityLogs({ userId, action, status, from, to, limit, offset });

    res.status(200).json({
      success: true,
      data: result.rows,
      pagination: { total: result.total, limit: result.limit, offset: result.offset },
    });
  } catch (error) {
    console.error("Get activity log error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * GET /admin/activity-log/alerts
 * Suspicious-pattern summary: repeated failed logins and recent lockouts in the
 * last hour (admin only). Pairs with the brute-force protection in authController.js.
 */
const getActivityAlertsController = async (req, res) => {
  try {
    const data = await getSuspiciousActivity();
    res.status(200).json({ success: true, data });
  } catch (error) {
    console.error("Get activity alerts error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

export { getActivityAlertsController, getActivityLogController };
