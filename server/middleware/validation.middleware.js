const { body, validationResult } = require("express-validator");

const signupValidation = [
  body("email").isEmail().withMessage("Must be a valid email").normalizeEmail(),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters")
    .matches(/\d/)
    .withMessage("Password must contain at least one number"),
];

const loginValidation = [
  body("email").isEmail().withMessage("Must be a valid email").normalizeEmail(),
  body("password").notEmpty().withMessage("Password is required"),
];

const updateProfileValidation = [
  body("email")
    .optional()
    .isEmail()
    .withMessage("Must be a valid email")
    .normalizeEmail(),
];

// NEW: Password reset validations
const forgotPasswordValidation = [
  body("email").isEmail().withMessage("Must be a valid email").normalizeEmail(),
];

const resetPasswordValidation = [
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters")
    .matches(/\d/)
    .withMessage("Password must contain at least one number"),
];

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: "Validation failed",
      errors: errors.array().map((err) => ({
        field: err.path,
        message: err.msg,
      })),
    });
  }
  next();
};

module.exports = {
  signupValidation,
  loginValidation,
  updateProfileValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  validate,
};
