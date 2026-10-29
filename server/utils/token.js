const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const config = require("../config/env");

const JWT_ALGORITHM = "HS256";

/**
 * Computes SHA-256 hash of a raw token string for safe database persistence.
 *
 * @param {string} token
 * @returns {string|null}
 */
const hashToken = (token) => {
  if (!token || typeof token !== "string" || !token.trim()) {
    return null;
  }
  return crypto.createHash("sha256").update(token.trim()).digest("hex");
};

/**
 * Resolves optional sessionId and customConfig arguments for token generation.
 * Supports:
 * - (userId)
 * - (userId, customConfig)
 * - (userId, sessionId)
 * - (userId, sessionId, customConfig)
 */
const resolveTokenArgs = (arg2, arg3) => {
  let sessionId = null;
  let customConfig = config;

  if (arg2) {
    if (
      typeof arg2 === "object" &&
      (arg2.JWT_ACCESS_SECRET || arg2.JWT_REFRESH_SECRET || arg2.JWT_ACCESS_EXPIRES_IN)
    ) {
      customConfig = arg2;
    } else {
      sessionId = arg2.toString();
      if (arg3 && typeof arg3 === "object") {
        customConfig = arg3;
      }
    }
  }

  return { sessionId, customConfig };
};

/**
 * Generates a signed, short-lived access token.
 * Payload includes userId, optional sessionId, explicit token type, and unique jti.
 * Does NOT contain passwords, sensitive personal data, or secrets.
 *
 * @param {string|object} userId - User ID
 * @param {string|object} [arg2] - Session ID or customConfig override
 * @param {object} [arg3] - Optional configuration override when arg2 is sessionId
 * @returns {string} Signed JWT access token
 */
const generateAccessToken = (userId, arg2, arg3) => {
  if (!userId) {
    throw new Error("userId is required to generate access token");
  }

  const { sessionId, customConfig } = resolveTokenArgs(arg2, arg3);

  const payload = {
    userId: userId.toString(),
    type: "access",
    jti: crypto.randomBytes(16).toString("hex"),
  };

  if (sessionId) {
    payload.sessionId = sessionId;
  }

  const options = {
    algorithm: JWT_ALGORITHM,
    expiresIn: customConfig.JWT_ACCESS_EXPIRES_IN || "15m",
  };

  if (customConfig.JWT_ISSUER) {
    options.issuer = customConfig.JWT_ISSUER;
  }

  if (customConfig.JWT_AUDIENCE) {
    options.audience = customConfig.JWT_AUDIENCE;
  }

  return jwt.sign(payload, customConfig.JWT_ACCESS_SECRET, options);
};

/**
 * Generates a signed, long-lived refresh token.
 * Payload includes userId, optional sessionId, explicit token type, and unique jti.
 * Does NOT contain passwords, sensitive personal data, or secrets.
 *
 * @param {string|object} userId - User ID
 * @param {string|object} [arg2] - Session ID or customConfig override
 * @param {object} [arg3] - Optional configuration override when arg2 is sessionId
 * @returns {string} Signed JWT refresh token
 */
const generateRefreshToken = (userId, arg2, arg3) => {
  if (!userId) {
    throw new Error("userId is required to generate refresh token");
  }

  const { sessionId, customConfig } = resolveTokenArgs(arg2, arg3);

  const payload = {
    userId: userId.toString(),
    type: "refresh",
    jti: crypto.randomBytes(16).toString("hex"),
  };

  if (sessionId) {
    payload.sessionId = sessionId;
  }

  const options = {
    algorithm: JWT_ALGORITHM,
    expiresIn: customConfig.JWT_REFRESH_EXPIRES_IN || "7d",
  };

  if (customConfig.JWT_ISSUER) {
    options.issuer = customConfig.JWT_ISSUER;
  }

  if (customConfig.JWT_AUDIENCE) {
    options.audience = customConfig.JWT_AUDIENCE;
  }

  return jwt.sign(payload, customConfig.JWT_REFRESH_SECRET, options);
};

/**
 * Verifies an access token with explicit algorithm pinning, signature verification,
 * expiration check, claim validation (issuer/audience when configured), and token type enforcement.
 *
 * @param {string} token - Access token to verify
 * @param {object} [customConfig] - Optional configuration override for testing
 * @returns {object|null} Decoded token payload if valid, null otherwise
 */
const verifyAccessToken = (token, customConfig = config) => {
  if (!token || typeof token !== "string" || !token.trim()) {
    return null;
  }

  try {
    const options = {
      algorithms: [JWT_ALGORITHM],
    };

    if (customConfig.JWT_ISSUER) {
      options.issuer = customConfig.JWT_ISSUER;
    }

    if (customConfig.JWT_AUDIENCE) {
      options.audience = customConfig.JWT_AUDIENCE;
    }

    const decoded = jwt.verify(
      token.trim(),
      customConfig.JWT_ACCESS_SECRET,
      options,
    );

    // Enforce explicit token type and presence of userId
    if (!decoded || decoded.type !== "access" || !decoded.userId) {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
};

/**
 * Verifies a refresh token with explicit algorithm pinning, signature verification,
 * expiration check, claim validation (issuer/audience when configured), and token type enforcement.
 *
 * @param {string} token - Refresh token to verify
 * @param {object} [customConfig] - Optional configuration override for testing
 * @returns {object|null} Decoded token payload if valid, null otherwise
 */
const verifyRefreshToken = (token, customConfig = config) => {
  if (!token || typeof token !== "string" || !token.trim()) {
    return null;
  }

  try {
    const options = {
      algorithms: [JWT_ALGORITHM],
    };

    if (customConfig.JWT_ISSUER) {
      options.issuer = customConfig.JWT_ISSUER;
    }

    if (customConfig.JWT_AUDIENCE) {
      options.audience = customConfig.JWT_AUDIENCE;
    }

    const decoded = jwt.verify(
      token.trim(),
      customConfig.JWT_REFRESH_SECRET,
      options,
    );

    // Enforce explicit token type and presence of userId
    if (!decoded || decoded.type !== "refresh" || !decoded.userId) {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
};

module.exports = {
  JWT_ALGORITHM,
  hashToken,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
};
