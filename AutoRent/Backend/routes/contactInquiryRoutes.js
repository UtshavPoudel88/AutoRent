import express from "express";
import {
  createContactInquiryController,
  deleteContactInquiryController,
  listContactInquiriesController,
} from "../controller/contactInquiryController.js";
import { authenticateToken } from "../middleware/auth.js";
import { requireRole } from "../middleware/requireRole.js";
import { validateContactInquiry } from "../middleware/validators/contactInquiryValidation.js";

const router = express.Router();

router.post("/contact-inquiries", validateContactInquiry, createContactInquiryController);
router.get("/admin/contact-inquiries", authenticateToken, requireRole("admin"), listContactInquiriesController);
router.delete("/admin/contact-inquiries/:id", authenticateToken, requireRole("admin"), deleteContactInquiryController);

export default router;
