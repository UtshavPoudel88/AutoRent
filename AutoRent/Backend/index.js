import cors from "cors";
import "dotenv/config";
import express from "express";
import helmet from "helmet";
import http from "http";
import { Server } from "socket.io";
import { client } from "./db/index.js";
import { verifySessionToken } from "./middleware/auth.js";
import adminRoutes from "./routes/adminRoutes.js";
import authRoutes from "./routes/authRoutes.js";
import bookingRequestRoutes from "./routes/bookingRequestRoutes.js";
import bookingRoutes from "./routes/bookingRoutes.js";
import contactInquiryRoutes from "./routes/contactInquiryRoutes.js";
import favoriteRoutes from "./routes/favoriteRoutes.js";
import garageRoutes from "./routes/garageRoutes.js";
import khaltiRoutes from "./routes/khaltiRoutes.js";
import notificationRoutes from "./routes/notificationRoutes.js";
import stripeRoutes from "./routes/stripeRoutes.js";
import uploadRoutes from "./routes/uploadRoutes.js";
import vehicleReviewRoutes from "./routes/vehicleReviewRoutes.js";
import vehicleRoutes from "./routes/vehicleRoutes.js";
import { startBookingScheduler } from "./services/bookingScheduler.js";
import { verifyMailConnection } from "./services/emailService.js";
import { setNotificationSocket } from "./services/notificationService.js";

const app = express();
const PORT = process.env.PORT || 5000;

// Behind a reverse proxy (Render, etc.) — needed so express-rate-limit and
// req.ip see the real client IP from X-Forwarded-For instead of the proxy's.
app.set("trust proxy", 1);

/**
 * Allowed frontend origin(s) — sourced from FRONTEND_URL (comma-separated for
 * multiple deploys, e.g. Render: FRONTEND_URL=https://app1.vercel.app,https://app2.vercel.app).
 * The localhost entries only matter in dev; they're harmless in prod since a
 * request has to actually originate from one of these origins to match.
 * Never falls back to "*" — an unset FRONTEND_URL just means only localhost works.
 */
function getAllowedOrigins() {
  const fromEnv = (process.env.FRONTEND_URL || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const devDefaults = ["http://localhost:5173", "http://127.0.0.1:5173"];
  return [...new Set([...fromEnv, ...devDefaults])];
}

const allowedOrigins = getAllowedOrigins();

function corsOriginCallback(origin, callback) {
  // No Origin header = same-origin request or a non-browser client (curl, mobile
  // app, server-to-server) — CORS is a browser-only mechanism, so this can't be
  // used to bypass auth; every route is still gated by the JWT bearer check.
  if (!origin) return callback(null, true);
  if (allowedOrigins.includes(origin)) return callback(null, true);
  console.warn(`[CORS] Blocked request from disallowed origin: ${origin}`);
  callback(null, false);
}

app.use(
  helmet({
    contentSecurityPolicy: false, // this process serves JSON + Socket.IO, not the HTML the CSP needs to protect — see Frontend/vercel.json and index.html for the CSP that actually governs the app
    crossOriginResourcePolicy: { policy: "cross-origin" }, // API is intentionally called from a different origin (the Vercel-hosted frontend)
  })
);

// CORS — locked to FRONTEND_URL, not "*". credentials:true so the browser will
// forward the Authorization header on cross-origin fetches from the allowed origin.
app.use(
  cors({
    origin: corsOriginCallback,
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use("/api", authRoutes);
app.use("/api", favoriteRoutes);
app.use("/api", notificationRoutes);
app.use("/api", uploadRoutes);
app.use("/api", vehicleRoutes);
app.use("/api", garageRoutes);
app.use("/api", bookingRoutes);
app.use("/api", bookingRequestRoutes);
app.use("/api", khaltiRoutes);
app.use("/api", stripeRoutes);
app.use("/api", vehicleReviewRoutes);
app.use("/api", contactInquiryRoutes);
app.use("/api", adminRoutes);

// Health check
app.get("/", (req, res) => {
  res.json({ message: "AutoRent Backend API is running" });
});

// Create HTTP server + Socket.IO
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

setNotificationSocket(io);

// Socket authentication — same verification as HTTP requests (signature, expiry,
// tokenVersion revocation check, UA binding). See middleware/auth.js.
io.use(async (socket, next) => {
  try {
    const token =
      socket.handshake.auth?.token ||
      (socket.handshake.headers.authorization || "").split(" ")[1];

    if (!token) {
      return next(new Error("Authentication error"));
    }

    const decoded = await verifySessionToken(token, socket.handshake.headers["user-agent"]);
    socket.user = {
      userId: decoded.userId || decoded.id,
      email: decoded.email,
      role: decoded.role,
    };
    next();
  } catch (err) {
    next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.user?.userId;
  if (userId) {
    socket.join(`user:${userId}`);
  }
});

// Start server
server.listen(PORT, async () => {
  console.log(`Server is running on http://localhost:${PORT}`);

  try {
    await client`SELECT 1`;
    console.log("Database: connected");
  } catch (err) {
    console.error("Database: not connected -", err?.message || err);
  }

  try {
    await verifyMailConnection();
    console.log("SMTP: ready");
  } catch (err) {
    console.error("SMTP: not ready -", err?.message || err);
  }

  startBookingScheduler();
});
