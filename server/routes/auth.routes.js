const express = require("express");
const { authLimiter } = require("../middleware/rateLimit.middleware");
const {
  signupValidation,
  loginValidation,
  validate,
} = require("../middleware/validation.middleware");
const {
  signup,
  login,
  refresh,
  logout,
} = require("../controllers/auth.controller");

const router = express.Router();

router.post("/signup", authLimiter, signupValidation, validate, signup);
router.post("/login", authLimiter, loginValidation, validate, login);
router.post("/refresh", refresh);
router.post("/logout", logout);

module.exports = router;
