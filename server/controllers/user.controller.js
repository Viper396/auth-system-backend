const User = require("../models/user.model");

// @desc    Get current user profile
// @route   GET /api/user/profile
exports.getProfile = async (req, res) => {
  try {
    // req.user is set by auth middleware
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        role: req.user.role,
        createdAt: req.user.createdAt,
      },
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// @desc    Update user profile
// @route   PUT /api/user/profile
exports.updateProfile = async (req, res) => {
  try {
    const { email } = req.body;

    if (email) {
      // Check if email already exists
      const existingUser = await User.findOne({
        email,
        _id: { $ne: req.user._id },
      });
      if (existingUser) {
        return res.status(400).json({ message: "Email already in use" });
      }
      req.user.email = email;
    }

    await req.user.save();

    res.json({
      message: "Profile updated successfully",
      user: {
        id: req.user._id,
        email: req.user.email,
        role: req.user.role,
      },
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ message: "Server error" });
  }
};
