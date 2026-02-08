const express = require("express");
const authenticate = require("../middleware/auth.middleware");
const {
  updateProfileValidation,
  validate,
} = require("../middleware/validation.middleware");
const { getProfile, updateProfile } = require("../controllers/user.controller");

const router = express.Router();

router.use(authenticate);

router.get("/profile", getProfile);
router.put("/profile", updateProfileValidation, validate, updateProfile);

module.exports = router;
