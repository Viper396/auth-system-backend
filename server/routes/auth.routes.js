const express = require("express");
const {
  loginLimiter,
  signupLimiter,
  refreshLimiter,
  forgotPasswordLimiter,
  resetPasswordLimiter,
} = require("../middleware/rateLimit.middleware");
const {
  signupValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  validate,
} = require("../middleware/validation.middleware");
const authenticate = require("../middleware/auth.middleware");
const {
  signup,
  login,
  refresh,
  logout,
  logoutAll,
  forgotPassword,
  verifyResetToken,
  resetPassword,
} = require("../controllers/auth.controller");

const router = express.Router();

router.post("/signup", signupLimiter, signupValidation, validate, signup);
router.post("/login", loginLimiter, loginValidation, validate, login);
router.post("/refresh", refreshLimiter, refresh);
router.post("/logout", logout);
router.post("/logout-all", authenticate, logoutAll);

// Password reset routes
router.post(
  "/forgot-password",
  forgotPasswordLimiter,
  forgotPasswordValidation,
  validate,
  forgotPassword,
);
router.get("/reset-password/:token", resetPasswordLimiter, verifyResetToken);
router.post(
  "/reset-password/:token",
  resetPasswordLimiter,
  resetPasswordValidation,
  validate,
  resetPassword,
);

module.exports = router;
