const User = require("../models/user.model");
const crypto = require("crypto");
const config = require("../config/env");
const { sendPasswordResetEmail } = require("../utils/email");
const {
  REFRESH_TOKEN_COOKIE_NAME,
  getRefreshTokenCookieOptions,
  getClearRefreshTokenCookieOptions,
} = require("../utils/cookie");
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require("../utils/token");

exports.signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const user = await User.create({ email, password });

    res.status(201).json({
      message: "User created successfully",
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Check if account is locked
    if (user.isLocked) {
      const lockTimeLeft = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60); // minutes
      return res.status(423).json({
        message: `Account locked due to too many failed login attempts. Try again in ${lockTimeLeft} minutes.`,
      });
    }

    // Verify password
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      // Increment failed attempts
      await user.incLoginAttempts();

      // Check if this failed attempt locked the account
      const updatedUser = await User.findById(user._id);
      if (updatedUser.isLocked) {
        return res.status(423).json({
          message:
            "Account locked due to too many failed login attempts. Try again in 2 hours.",
        });
      }

      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Successful login - reset attempts
    await user.resetLoginAttempts();

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Store refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Send refresh token as hardened httpOnly cookie
    res.cookie(
      REFRESH_TOKEN_COOKIE_NAME,
      refreshToken,
      getRefreshTokenCookieOptions(),
    );

    res.json({
      message: "Login successful",
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

exports.refresh = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token provided" });
    }

    const decoded = verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    // Generate new tokens
    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    // Update stored refresh token
    user.refreshToken = newRefreshToken;
    await user.save();

    // Send new refresh token
    res.cookie(
      REFRESH_TOKEN_COOKIE_NAME,
      newRefreshToken,
      getRefreshTokenCookieOptions(),
    );

    res.json({
      accessToken: newAccessToken,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if (refreshToken) {
      await User.findOneAndUpdate({ refreshToken }, { refreshToken: null });
    }

    res.clearCookie(
      REFRESH_TOKEN_COOKIE_NAME,
      getClearRefreshTokenCookieOptions(),
    );

    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// @desc    Request password reset
// @route   POST /api/auth/forgot-password
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });

    // SECURITY: Don't reveal if email exists or not (Generic response & timing mitigation)
    if (!user) {
      await new Promise((resolve) => setTimeout(resolve, 80));
      return res.json({
        message: "If that email exists, a password reset link has been sent.",
      });
    }

    // Generate cryptographically secure random reset token (stored as SHA-256 hash)
    const resetToken = user.createPasswordResetToken(
      config.RESET_TOKEN_EXPIRE_MINUTES || 15,
    );
    await user.save();

    const resetUrl = `${config.FRONTEND_URL}/reset-password/${resetToken}`;

    // Dispatch email
    try {
      await sendPasswordResetEmail(user.email, resetUrl);

      // Return ONLY generic response; NEVER expose raw resetToken or resetUrl
      return res.json({
        message: "If that email exists, a password reset link has been sent.",
      });
    } catch (emailError) {
      // Rollback generated token on email delivery failure to prevent unsendable active tokens
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      console.error(
        "Password reset email delivery failed:",
        emailError.message || "Email send failure",
      );
      return res.status(500).json({
        message: "Failed to send reset email. Please try again later.",
      });
    }
  } catch (error) {
    console.error("Forgot password error:", error.message || "Server error");
    return res.status(500).json({ message: "Server error" });
  }
};

// @desc    Verify reset token
// @route   GET /api/auth/reset-password/:token
exports.verifyResetToken = async (req, res) => {
  try {
    const { token } = req.params;

    if (!token || typeof token !== "string") {
      return res.status(400).json({
        valid: false,
        message: "Invalid or expired reset token",
      });
    }

    // Hash the token from URL to match database hash
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // Find user with active, unexpired token
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        valid: false,
        message: "Invalid or expired reset token",
      });
    }

    return res.json({
      valid: true,
      message: "Token is valid",
    });
  } catch (error) {
    console.error("Verify reset token error:", error.message || "Server error");
    return res.status(500).json({ message: "Server error" });
  }
};

// @desc    Reset password
// @route   POST /api/auth/reset-password/:token
exports.resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!token || typeof token !== "string") {
      return res.status(400).json({
        message: "Invalid or expired reset token",
      });
    }

    if (!password) {
      return res.status(400).json({ message: "Password is required" });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters",
      });
    }

    // Hash the token from URL
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // ATOMIC SINGLE-USE CONDITIONAL UPDATE:
    // Concurrently competing requests with the same token cannot both match.
    // The first request atomically sets resetPasswordToken to null.
    const user = await User.findOneAndUpdate(
      {
        resetPasswordToken: hashedToken,
        resetPasswordExpires: { $gt: Date.now() },
      },
      {
        $set: {
          resetPasswordToken: null,
          resetPasswordExpires: null,
          refreshToken: null,
          loginAttempts: 0,
        },
        $unset: {
          lockUntil: 1,
        },
      },
      { new: true },
    );

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired reset token",
      });
    }

    // Set new password (triggers Mongoose pre-save bcrypt hook)
    user.password = password;
    await user.save();

    // Revoke refresh token cookie from calling client if present
    res.clearCookie(
      REFRESH_TOKEN_COOKIE_NAME,
      getClearRefreshTokenCookieOptions(),
    );

    return res.json({
      message:
        "Password reset successful. You can now login with your new password.",
    });
  } catch (error) {
    console.error("Reset password error:", error.message || "Server error");
    return res.status(500).json({ message: "Server error" });
  }
};
