// Check if user has required role
const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Authentication required" });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: "Access denied. Insufficient permissions.",
        requiredRole: allowedRoles,
        yourRole: req.user.role,
      });
    }

    next();
  };
};

module.exports = authorize;
