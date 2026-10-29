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
  });
}

// Automatically validate process.env when required by application
const runtimeConfig = validateConfig(process.env);

module.exports = {
  ...runtimeConfig,
  validateConfig,
};
