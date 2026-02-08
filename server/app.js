const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { generalLimiter } = require("./middleware/rateLimit.middleware");

const app = express();

// Security middleware
app.use(helmet()); // Secure headers
app.use(morgan("combined")); // Request logging

// Rate limiting
app.use("/api/", generalLimiter); // Apply to all API routes

// CORS
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  }),
);

// Body parsing
app.use(express.json());
app.use(cookieParser());

// Health check (no rate limit)
app.get("/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date() });
});

// Routes
app.use("/api/auth", require("./routes/auth.routes"));
app.use("/api/user", require("./routes/user.routes"));
app.use("/api/admin", require("./routes/admin.routes"));

module.exports = app;
