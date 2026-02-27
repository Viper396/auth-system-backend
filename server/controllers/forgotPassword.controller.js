const { sendPasswordResetEmail } = require("../utils/email");

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({
        message: "If that email exists, a password reset link has been sent.",
      });
    }

    const resetToken = user.createPasswordResetToken();
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    // Send email
    try {
      await sendPasswordResetEmail(user.email, resetUrl);

      res.json({
        message: "If that email exists, a password reset link has been sent.",
      });
    } catch (emailError) {
      // If email fails, clear the reset token
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      console.error("Email send failed:", emailError);
      res.status(500).json({ message: "Failed to send reset email" });
    }
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Server error" });
  }
};
