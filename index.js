require("dotenv").config();

// index.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");

const { issueToken } = require("./controllers/authController");
const admin = require("./controllers/adminController");
const protectedController = require("./controllers/protectedController");

const app = express();

app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE"] }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use((req, res, next) => {
  const match = req.url.match(/^\/api\/[^/]+(\/.*)$/);

  if (match) {
    req.url = "/api" + match[1];
  }

  next();
});

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// OAuth Mock
app.post("/oauth/token", issueToken);

// Admin / Monitoring
app.post("/admin/reset", admin.reset);
app.get("/admin/metrics", admin.metrics);
app.post("/admin/config", admin.config);
app.get("/admin/tokens", admin.tokens);

// Session endpoints
app.post("/api/session", protectedController.createSession);
app.put("/api/session/:SessionId", protectedController.updateSession);
app.delete("/api/session/:SessionId", protectedController.cancelSession);

// Instructor endpoints
app.post("/api/instructor", protectedController.addInstructor);
//app.put("/api/instructor", protectedController.updateInstructor);

// Attendance and launch endpoints
app.get("/api/session/:SessionId/attendees", protectedController.getAttendance);
app.get("/api/session/:SessionId/extendedoptions", protectedController.getExtendedOptions);
app.get(
  "/api/session/:SessionId/user/:base64EncodedEmail/url",
  protectedController.launchSession
);

// Dev server only (Vercel imports the app instead)
if (process.env.VERCEL !== "1") {
  const port = process.env.PORT || 8000;
  app.listen(port, () => console.log(`Mock OAuth server running on ${port}`));
}

module.exports = app;

// test-MPC branch
