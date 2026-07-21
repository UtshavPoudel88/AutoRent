import express from "express";
import {
  getAdminActivityFeedController,
  getAdminReportStatsController,
  getAdminStatsController,
  getAllVehiclesController,
  getVehicleByIdAdminController,
  updateVehicleVerifyController,
} from "../controller/adminVehicleController.js";
import {
  addVehicleController,
  addVehicleImagesController,
  deleteVehicleController,
  getMyVehiclesController,
  getPublicVehiclesController,
  getPublicVehicleByIdController,
  getVehicleByIdController,
  updateVehicleController,
} from "../controller/vehicleController.js";
import { authenticateToken } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";
import { validateAddVehicle, validateAddVehicleImages, validateUpdateVehicle } from "../middleware/validation.js";

const router = express.Router();

// —— Public (renter) routes (no auth) ——
router.get("/vehicles/browse", getPublicVehiclesController);
router.get("/vehicles/browse/:id", getPublicVehicleByIdController);

// —— Owner vehicle routes (auth + owner role required) ——
router.post("/vehicles", authenticateToken, requireRole("owner"), validateAddVehicle, addVehicleController);
router.get("/vehicles", authenticateToken, requireRole("owner"), getMyVehiclesController);
router.get("/vehicles/:id", authenticateToken, requireRole("owner"), getVehicleByIdController);
router.patch("/vehicles/:id", authenticateToken, requireRole("owner"), validateUpdateVehicle, updateVehicleController);
router.delete("/vehicles/:id", authenticateToken, requireRole("owner"), deleteVehicleController);
router.post("/vehicles/:id/images", authenticateToken, requireRole("owner"), validateAddVehicleImages, addVehicleImagesController);

// —— Admin routes (auth + admin role required) ——
router.get("/admin/stats", authenticateToken, requireRole("admin"), getAdminStatsController);
router.get("/admin/vehicles", authenticateToken, requireRole("admin"), getAllVehiclesController);
router.get("/admin/vehicles/:id", authenticateToken, requireRole("admin"), getVehicleByIdAdminController);
router.patch("/admin/vehicles/:id/verify", authenticateToken, requireRole("admin"), updateVehicleVerifyController);
router.get("/admin/reports", authenticateToken, requireRole("admin"), getAdminReportStatsController);
router.get("/admin/activity", authenticateToken, requireRole("admin"), getAdminActivityFeedController);

export default router;
