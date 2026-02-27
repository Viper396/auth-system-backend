const express = require("express");
const {
  authLimiter,
  resetPasswordLimiter,
} = require("../middleware/rateLimit.middleware");
const {
  signupValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  validate,
} = require("../middleware/validation.middleware");
const {
  signup,
  login,
  refresh,
  logout,
  forgotPassword,
  verifyResetToken,
  resetPassword,
} = require("../controllers/auth.controller");

const router = express.Router();

router.post("/signup", authLimiter, signupValidation, validate, signup);
router.post("/login", authLimiter, loginValidation, validate, login);
router.post("/refresh", refresh);
router.post("/logout", logout);

// Password reset routes
router.post(
  "/forgot-password",
  resetPasswordLimiter,
  forgotPasswordValidation,
  validate,
  forgotPassword,
);
router.get("/reset-password/:token", verifyResetToken);
router.post(
  "/reset-password/:token",
  resetPasswordValidation,
  validate,
  resetPassword,
);

module.exports = router;
