const express = require("express");
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/role.middleware");
const {
  getAllUsers,
  getUserById,
  deleteUser,
  updateUserRole,
} = require("../controllers/admin.controller");

const router = express.Router();

// All admin routes require authentication AND admin role
router.use(authenticate);
router.use(authorize("admin"));

router.get("/users", getAllUsers);
router.get("/users/:id", getUserById);
router.delete("/users/:id", deleteUser);
router.put("/users/:id/role", updateUserRole);

module.exports = router;
