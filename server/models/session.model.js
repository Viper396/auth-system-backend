const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    // SHA-256 hash of active refresh token (never stored in plaintext)
    currentHash: {
      type: String,
      required: true,
      index: true,
    },
    // SHA-256 hash of immediately preceding token (for concurrency grace window)
    previousHash: {
      type: String,
      default: null,
      index: true,
    },
    // Timestamp until which previousHash is accepted for concurrent in-flight requests
    rotationGraceUntil: {
      type: Date,
      default: null,
    },
    // Session expiration timestamp (native MongoDB TTL index automatically removes expired sessions)
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 },
    },
    userAgent: {
      type: String,
      default: null,
    },
    ipAddress: {
      type: String,
      default: null,
    },
  },
  { timestamps: true },
);

module.exports = mongoose.model("Session", sessionSchema);
