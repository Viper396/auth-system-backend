const rateLimit = require("express-rate-limit");

/**
 * Standardized rate-limit JSON error response generator.
 * Does not leak internal server details or headers.
 */
const createJsonMessage = (message) => ({
  message,
});

// General API rate limiter (100 req / 15 min)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: createJsonMessage("Too many requests from this IP, please try again later."),
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict limiter for login attempts (5 failed attempts per 15 min per IP)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: createJsonMessage(
    "Too many login attempts from this IP, please try again later.",
  ),
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

// Strict limiter for account registrations (5 signups per hour per IP)
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: createJsonMessage(
    "Too many accounts created from this IP, please try again later.",
  ),
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict limiter for requesting password reset emails (3 requests per hour per IP)
const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: createJsonMessage(
    "Too many password reset requests from this IP, please try again later.",
  ),
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict limiter for token verification & password submissions (5 attempts per 15 min per IP)
const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: createJsonMessage(
    "Too many password reset attempts, please try again later.",
  ),
  standardHeaders: true,
  legacyHeaders: false,
});

// Moderate limiter for refresh token endpoint (30 requests per 15 min per IP)
const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: createJsonMessage(
    "Too many refresh requests, please try again later.",
  ),
  standardHeaders: true,
  legacyHeaders: false,
});

// Backwards-compatible alias
const authLimiter = loginLimiter;

module.exports = {
  generalLimiter,
  loginLimiter,
  signupLimiter,
  forgotPasswordLimiter,
  resetPasswordLimiter,
  refreshLimiter,
  authLimiter,
};
