const { verifyAccessToken } = require("../utils/token");
const User = require("../models/user.model");

const authenticate = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    // Verify token
    const decoded = verifyAccessToken(token);
    if (!decoded) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    // Get user from database
    const user = await User.findById(decoded.userId).select(
      "-password -refreshToken",
    );
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // Attach user to request object
    req.user = user;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(401).json({ message: "Authentication failed" });
  }
};

module.exports = authenticate;
