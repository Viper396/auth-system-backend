const nodemailer = require("nodemailer");
const config = require("../config/env");

// Create transporter (configure with your email service)
let transporter = nodemailer.createTransport({
  host: config.EMAIL_HOST,
  port: config.EMAIL_PORT,
  secure: config.EMAIL_PORT === 465,
  auth: {
    user: config.EMAIL_USER,
    pass: config.EMAIL_PASSWORD,
  },
});

/**
 * Allows injecting a mock/stub transporter for testing purposes.
 * @param {object} newTransporter - Custom nodemailer transporter
 */
const setTransporter = (newTransporter) => {
  transporter = newTransporter;
};

/**
 * Resets the transporter back to standard nodemailer configuration.
 */
const resetTransporter = () => {
  transporter = nodemailer.createTransport({
    host: config.EMAIL_HOST,
    port: config.EMAIL_PORT,
    secure: config.EMAIL_PORT === 465,
    auth: {
      user: config.EMAIL_USER,
      pass: config.EMAIL_PASSWORD,
    },
  });
};

// Send password reset email
const sendPasswordResetEmail = async (email, resetUrl) => {
  const mailOptions = {
    from: `"${config.APP_NAME}" <${config.EMAIL_FROM}>`,
    to: email,
    subject: "Password Reset Request",
    html: `
      <h1>Password Reset</h1>
      <p>You requested a password reset.</p>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>This link will expire in ${config.RESET_TOKEN_EXPIRE_MINUTES || 15} minutes.</p>
      <p>If you didn't request this, please ignore this email.</p>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Password reset email sent to:", email);
  } catch (error) {
    console.error("Email send error:", error.message || "Failed to send email");
    throw new Error("Failed to send email");
  }
};

module.exports = {
  sendPasswordResetEmail,
  setTransporter,
  resetTransporter,
};
