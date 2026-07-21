import express from "express";
import {
  cancelBookingController,
  createBookingController,
  ensureVerifiedRenter,
  getBookingByIdController,
  getBookingsController,
  getOwnerEarningsReportController,
  getOwnerStatsController,
} from "../controller/bookingController.js";
import { authenticateToken } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";
import { validateCreateBooking } from "../middleware/validators/bookingCreateValidation.js";

const router = express.Router();

router.use(authenticateToken);

router.get("/bookings/stats", requireRole("owner"), getOwnerStatsController);
router.get("/bookings/stats/earnings", requireRole("owner"), getOwnerEarningsReportController);
router.get("/bookings", getBookingsController);
router.get("/bookings/:id", getBookingByIdController);
router.post("/bookings", ensureVerifiedRenter, validateCreateBooking, createBookingController);
router.patch("/bookings/:id/cancel", cancelBookingController);

export default router;
