const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../.env"), quiet: true });

const INSECURE_SECRETS = new Set([
  "your_access_token_secret_key_here",
  "your_refresh_token_secret_key_here",
  "your_jwt_access_token_secret_min_32_chars",
  "your_jwt_refresh_token_secret_min_32_chars",
  "secret",
  "secret123",
  "changeme",
  "password",
  "jwt_secret",
]);

/**
 * Parses duration string (e.g. "15m", "1h", "7d", "30d", "900") into seconds.
 * Returns null if the format is invalid.
 *
 * @param {string|number} val
 * @returns {number|null}
 */
function parseDurationToSeconds(val) {
  if (typeof val === "number" && Number.isFinite(val)) return val;
  if (!val || typeof val !== "string") return null;
  const trimmed = val.trim();
  if (/^\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10);
  }
  const match = trimmed.match(/^(\d+)\s*([smhd])$/i);
  if (!match) return null;
  const count = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  switch (unit) {
    case "s":
      return count;
    case "m":
      return count * 60;
    case "h":
      return count * 3600;
    case "d":
      return count * 86400;
    default:
      return null;
  }
}

/**
 * Validates and normalizes application configuration.
 * Never prints secret values in error messages.
 *
 * @param {NodeJS.ProcessEnv} env - Environment variables to validate
 * @returns {Readonly<object>} Validated configuration object
 */
function validateConfig(env = process.env) {
  const errors = [];

  // 1. Environment mode
  const nodeEnv = (env.NODE_ENV || "development").trim().toLowerCase();
  const validEnvs = ["development", "production", "test"];
  if (!validEnvs.includes(nodeEnv)) {
    errors.push(
      `Invalid NODE_ENV: "${nodeEnv}". Must be one of: ${validEnvs.join(", ")}.`,
    );
  }

  // 2. Port validation
  let port = 5000;
  if (env.PORT) {
    const parsedPort = parseInt(env.PORT, 10);
    if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      errors.push(
        `Invalid PORT: "${env.PORT}". Must be an integer between 1 and 65535.`,
      );
    } else {
      port = parsedPort;
    }
  }

  // 3. JWT Access Secret (canonical: JWT_ACCESS_SECRET, legacy fallback: ACCESS_TOKEN_SECRET)
  const jwtAccessSecret =
    env.JWT_ACCESS_SECRET || env.ACCESS_TOKEN_SECRET || "";
  if (!jwtAccessSecret || !jwtAccessSecret.trim()) {
    errors.push(
      "Missing required configuration: JWT_ACCESS_SECRET is required.",
    );
  } else if (nodeEnv === "production") {
    if (jwtAccessSecret.length < 32) {
      errors.push(
        "Insecure JWT_ACCESS_SECRET: Must be at least 32 characters in production.",
      );
    }
    if (INSECURE_SECRETS.has(jwtAccessSecret.toLowerCase())) {
      errors.push(
        "Insecure JWT_ACCESS_SECRET: Detected known placeholder secret in production.",
      );
    }
  }

  // 4. JWT Refresh Secret (canonical: JWT_REFRESH_SECRET, legacy fallback: REFRESH_TOKEN_SECRET)
  const jwtRefreshSecret =
    env.JWT_REFRESH_SECRET || env.REFRESH_TOKEN_SECRET || "";
  if (!jwtRefreshSecret || !jwtRefreshSecret.trim()) {
    errors.push(
      "Missing required configuration: JWT_REFRESH_SECRET is required.",
    );
  } else if (nodeEnv === "production") {
    if (jwtRefreshSecret.length < 32) {
      errors.push(
        "Insecure JWT_REFRESH_SECRET: Must be at least 32 characters in production.",
      );
    }
    if (INSECURE_SECRETS.has(jwtRefreshSecret.toLowerCase())) {
      errors.push(
        "Insecure JWT_REFRESH_SECRET: Detected known placeholder secret in production.",
      );
    }
  }

  // 4b. Ensure Access and Refresh secrets are strictly distinct
  if (
    jwtAccessSecret &&
    jwtRefreshSecret &&
    jwtAccessSecret === jwtRefreshSecret
  ) {
    errors.push(
      "Insecure JWT configuration: JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be distinct secrets.",
    );
  }

  // 4c. JWT Token Lifetimes (Configurable within safe bounds)
  // Access token safe bounds: 1 minute (60s) to 1 hour (3600s)
  const rawAccessExpiry = (env.JWT_ACCESS_EXPIRES_IN || "15m").trim();
  const accessExpirySeconds = parseDurationToSeconds(rawAccessExpiry);
  if (
    accessExpirySeconds === null ||
    accessExpirySeconds < 60 ||
    accessExpirySeconds > 3600
  ) {
    errors.push(
      `Invalid JWT_ACCESS_EXPIRES_IN: "${rawAccessExpiry}". Must be between 1 minute and 1 hour (e.g., "15m", "30m", "1h").`,
    );
  }

  // Refresh token safe bounds: 1 hour (3600s) to 30 days (2592000s)
  const rawRefreshExpiry = (env.JWT_REFRESH_EXPIRES_IN || "7d").trim();
  const refreshExpirySeconds = parseDurationToSeconds(rawRefreshExpiry);
  if (
    refreshExpirySeconds === null ||
    refreshExpirySeconds < 3600 ||
    refreshExpirySeconds > 2592000
  ) {
    errors.push(
      `Invalid JWT_REFRESH_EXPIRES_IN: "${rawRefreshExpiry}". Must be between 1 hour and 30 days (e.g., "7d", "14d", "30d").`,
    );
  }

  // 4d. Optional Claims: Issuer and Audience
  const jwtIssuer =
    env.JWT_ISSUER && env.JWT_ISSUER.trim() ? env.JWT_ISSUER.trim() : undefined;
  const jwtAudience =
    env.JWT_AUDIENCE && env.JWT_AUDIENCE.trim()
      ? env.JWT_AUDIENCE.trim()
      : undefined;

  // 5. MongoDB URI (required in development and production)
  const mongoUri = env.MONGO_URI || "";
  if (nodeEnv !== "test" && (!mongoUri || !mongoUri.trim())) {
    errors.push("Missing required configuration: MONGO_URI is required.");
  }

  // 6. Frontend URL & Trusted Origins
  let rawFrontendUrl = env.FRONTEND_URL;
  if (!rawFrontendUrl || !rawFrontendUrl.trim()) {
    rawFrontendUrl =
      nodeEnv === "production" ? "" : "http://localhost:5173";
  }

  const trustedOrigins = rawFrontendUrl
    ? rawFrontendUrl
        .split(",")
        .map((origin) => origin.trim().replace(/\/+$/, ""))
        .filter(Boolean)
    : [];

  // In production, require at least one explicit trusted origin
  if (nodeEnv === "production" && trustedOrigins.length === 0) {
    errors.push(
      "Missing required configuration: FRONTEND_URL must specify at least one trusted origin in production.",
    );
  }

  // 7. Cookie settings
  let cookieSameSite = (env.COOKIE_SAME_SITE || "lax").trim().toLowerCase();
  const validSameSiteValues = ["lax", "strict", "none"];
  if (!validSameSiteValues.includes(cookieSameSite)) {
    errors.push(
      `Invalid COOKIE_SAME_SITE: "${env.COOKIE_SAME_SITE}". Must be one of: ${validSameSiteValues.join(", ")}.`,
    );
    cookieSameSite = "lax";
  }

  // Determine cookie secure flag
  let cookieSecure = false;
  if (env.COOKIE_SECURE !== undefined) {
    cookieSecure = env.COOKIE_SECURE === "true" || env.COOKIE_SECURE === "1";
  } else {
    // Default to secure in production or if SameSite=None is used
    cookieSecure = nodeEnv === "production" || cookieSameSite === "none";
  }

  // Fail clearly at startup if required configuration is missing or invalid
  if (errors.length > 0) {
    throw new Error(
      `Configuration Validation Failed:\n  - ${errors.join("\n  - ")}\nPlease review your environment variables or .env file.`,
    );
  }

  // Safe configuration object
  return Object.freeze({
    PORT: port,
    NODE_ENV: nodeEnv,
    MONGO_URI: mongoUri,
    JWT_ACCESS_SECRET: jwtAccessSecret,
    JWT_REFRESH_SECRET: jwtRefreshSecret,
    JWT_ACCESS_EXPIRES_IN: rawAccessExpiry,
    JWT_ACCESS_EXPIRES_IN_SECONDS: accessExpirySeconds || 900,
    JWT_REFRESH_EXPIRES_IN: rawRefreshExpiry,
    JWT_REFRESH_EXPIRES_IN_SECONDS: refreshExpirySeconds || 604800,
    JWT_ISSUER: jwtIssuer,
    JWT_AUDIENCE: jwtAudience,
    FRONTEND_URL: trustedOrigins[0] || "http://localhost:5173",
    TRUSTED_ORIGINS: Object.freeze(trustedOrigins),
    COOKIE_SAME_SITE: cookieSameSite,
    COOKIE_SECURE: cookieSecure,
    COOKIE_DOMAIN: env.COOKIE_DOMAIN ? env.COOKIE_DOMAIN.trim() : undefined,
    EMAIL_HOST: env.EMAIL_HOST || "",
    EMAIL_PORT: env.EMAIL_PORT ? parseInt(env.EMAIL_PORT, 10) : 587,
    EMAIL_USER: env.EMAIL_USER || "",
    EMAIL_PASSWORD: env.EMAIL_PASSWORD || "",
    EMAIL_FROM: env.EMAIL_FROM || "noreply@example.com",
    APP_NAME: env.APP_NAME || "AuthSystem",
    RESET_TOKEN_EXPIRE_MINUTES: env.RESET_TOKEN_EXPIRE_MINUTES
      ? parseInt(env.RESET_TOKEN_EXPIRE_MINUTES, 10)
      : 15,
    ACCOUNT_LOCKOUT_MINUTES: env.ACCOUNT_LOCKOUT_MINUTES
      ? Math.max(1, Math.min(120, parseInt(env.ACCOUNT_LOCKOUT_MINUTES, 10) || 15))
      : 15,
    TRUST_PROXY:
      env.TRUST_PROXY === "true" ||
      env.TRUST_PROXY === "1" ||
      nodeEnv === "production",
  });
}

// Automatically validate process.env when required by application
const runtimeConfig = validateConfig(process.env);

module.exports = {
  ...runtimeConfig,
  validateConfig,
  parseDurationToSeconds,
};
