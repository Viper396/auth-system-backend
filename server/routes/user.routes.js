const express = require("express");
const authenticate = require("../middleware/auth.middleware");
const { getProfile, updateProfile } = require("../controllers/user.controller");

const router = express.Router();

// All routes here require authentication
router.use(authenticate);

router.get("/profile", getProfile);
router.put("/profile", updateProfile);

module.exports = router;
