const { verifyAccessToken } = require("../utils/token");
const User = require("../models/user.model");

/**
 * Authentication middleware that verifies the incoming Bearer access token.
 * Derives user identity and role strictly from server-side database records,
 * ignoring any client-supplied request bodies or headers.
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers?.authorization;

    if (
      !authHeader ||
      typeof authHeader !== "string" ||
      !authHeader.startsWith("Bearer ")
    ) {
      return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1]?.trim();
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    // Verify access token (pinned algorithm, valid signature, unexpired, correct type)
    const decoded = verifyAccessToken(token);
    if (!decoded) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    // Retrieve user from database; exclude credentials
    const user = await User.findById(decoded.userId).select(
      "-password -refreshToken",
    );
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // Attach server-verified user identity and role
    req.user = user;
    next();
  } catch (error) {
    console.error(
      "Auth middleware error:",
      error.message || "Authentication failed",
    );
    res.status(401).json({ message: "Authentication failed" });
  }
};

module.exports = authenticate;
