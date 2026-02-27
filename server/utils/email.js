const nodemailer = require("nodemailer");

// Create transporter (configure with your email service)
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST, // e.g., smtp.gmail.com
  port: process.env.EMAIL_PORT, // e.g., 587
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Send password reset email
const sendPasswordResetEmail = async (email, resetUrl) => {
  const mailOptions = {
    from: `"${process.env.APP_NAME}" <${process.env.EMAIL_FROM}>`,
    to: email,
    subject: "Password Reset Request",
    html: `
      <h1>Password Reset</h1>
      <p>You requested a password reset.</p>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Password reset email sent to:", email);
  } catch (error) {
    console.error("Email send error:", error);
    throw new Error("Failed to send email");
  }
};

module.exports = {
  sendPasswordResetEmail,
};
