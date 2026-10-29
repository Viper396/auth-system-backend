const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const config = require("./config/env");
const { generalLimiter } = require("./middleware/rateLimit.middleware");

const app = express();

// Trust reverse proxy (e.g. Nginx, Cloudflare, load balancers) when configured or in production
if (config.TRUST_PROXY) {
  app.set("trust proxy", 1);
}

// Security headers
app.use(helmet());

// Request logging (Apache combined format, does not log request bodies or authorization headers)
app.use(morgan("combined"));

// Rate limiting applied to API routes
app.use("/api/", generalLimiter);

// Hardened CORS configuration with explicit trusted origins
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g. mobile apps, curl, server-to-server)
    if (!origin) {
      return callback(null, true);
    }
    const normalizedOrigin = origin.replace(/\/+$/, "");
    if (config.TRUSTED_ORIGINS.includes(normalizedOrigin)) {
      return callback(null, true);
    }
    // Block disallowed origin safely without throwing uncaught errors
    return callback(null, false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 86400, // Cache preflight for 24 hours
};

app.use(cors(corsOptions));

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
