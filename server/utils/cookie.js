const config = require("../config/env");

const REFRESH_TOKEN_COOKIE_NAME = "refreshToken";

/**
 * Returns options for setting the refresh token cookie.
 * Scoped to /api/auth with HttpOnly and deployment-appropriate Secure & SameSite attributes.
 *
 * @param {object} [customConfig] - Optional configuration override for testing
 * @returns {import("express").CookieOptions}
 */
const getRefreshTokenCookieOptions = (customConfig = config) => {
  const isProduction = customConfig.NODE_ENV === "production";
  const sameSite = (customConfig.COOKIE_SAME_SITE || "lax").toLowerCase();

  // Browsers strictly reject SameSite=None cookies unless Secure is true
  const secure =
    customConfig.COOKIE_SECURE === true ||
    isProduction ||
    sameSite === "none";

  const options = {
    httpOnly: true,
    secure,
    sameSite,
    path: "/api/auth",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  };

  if (customConfig.COOKIE_DOMAIN) {
    options.domain = customConfig.COOKIE_DOMAIN;
  }

  return options;
};

/**
 * Returns options for clearing the refresh token cookie.
 * Must match path, domain, sameSite, and secure attributes of the original cookie.
 *
 * @param {object} [customConfig] - Optional configuration override for testing
 * @returns {import("express").CookieOptions}
 */
const getClearRefreshTokenCookieOptions = (customConfig = config) => {
  const setOptions = getRefreshTokenCookieOptions(customConfig);
  const clearOptions = {
    httpOnly: setOptions.httpOnly,
    secure: setOptions.secure,
    sameSite: setOptions.sameSite,
    path: setOptions.path,
  };

  if (setOptions.domain) {
    clearOptions.domain = setOptions.domain;
  }

  return clearOptions;
};

module.exports = {
  REFRESH_TOKEN_COOKIE_NAME,
  getRefreshTokenCookieOptions,
  getClearRefreshTokenCookieOptions,
};
