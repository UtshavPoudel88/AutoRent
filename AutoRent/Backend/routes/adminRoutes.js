import express from "express";
import { getAdminBookingsController } from "../controller/adminBookingController.js";
import {
    deleteUserController,
    getAllUsersController,
    getPendingProfileVerificationController,
    verifyProfileController,
} from "../controller/adminProfileController.js";
import { authenticateToken } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";

const router = express.Router();

// All admin routes require authentication AND the admin role
router.use(authenticateToken);
router.use(requireRole("admin"));

router.get("/admin/bookings", getAdminBookingsController);

// User management (admin only)
router.get("/admin/users", getAllUsersController);
router.get("/admin/users/pending-verification", getPendingProfileVerificationController);
router.patch("/admin/users/:userId/verify-profile", verifyProfileController);
router.delete("/admin/users/:userId", deleteUserController);

export default router;
