const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const User = require("../models/user.model");
const Session = require("../models/session.model");
const emailUtil = require("../utils/email");
const authController = require("../controllers/auth.controller");
const config = require("../config/env");

describe("Password Reset - Token Generation & Hashing (Model)", () => {
  test("generates 256-bit CSPRNG token and stores only SHA-256 hash", () => {
    const user = new User({
      email: "test@example.com",
      password: "password123",
    });

    const rawToken = user.createPasswordResetToken(15);

    // Raw token must be 64-character hex string (32 bytes entropy)
    assert.equal(typeof rawToken, "string");
    assert.equal(rawToken.length, 64);
    assert.match(rawToken, /^[0-9a-f]{64}$/);

    // Stored token must NOT equal the raw token
    assert.notEqual(user.resetPasswordToken, rawToken);

    // Stored token must equal the SHA-256 hash of the raw token
    const expectedHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");
    assert.equal(user.resetPasswordToken, expectedHash);

    // Expiry must be approximately 15 minutes from now
    const expectedExpiry = Date.now() + 15 * 60 * 1000;
    assert.ok(Math.abs(user.resetPasswordExpires.getTime() - expectedExpiry) < 5000);
  });
});

describe("Password Reset - Controller Flow & Security", () => {
  let originalFindOne;
  let originalFindOneAndUpdate;
  let originalDeleteMany;
  let sentEmails = [];

  beforeEach(() => {
    originalFindOne = User.findOne;
    originalFindOneAndUpdate = User.findOneAndUpdate;
    originalDeleteMany = Session.deleteMany;
    Session.deleteMany = async () => ({ deletedCount: 1 });
    sentEmails = [];

    // Intercept email sending to avoid real network calls
    emailUtil.setTransporter({
      sendMail: async (options) => {
        sentEmails.push(options);
        return { messageId: "mock-id-123" };
      },
    });
  });

  afterEach(() => {
    User.findOne = originalFindOne;
    User.findOneAndUpdate = originalFindOneAndUpdate;
    Session.deleteMany = originalDeleteMany;
    emailUtil.resetTransporter();
  });

  // Helper to create mock Express response
  function createMockResponse() {
    return {
      statusCode: 200,
      body: null,
      cookiesCleared: [],
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(data) {
        this.body = data;
        return this;
      },
      clearCookie(name, options) {
        this.cookiesCleared.push({ name, options });
        return this;
      },
    };
  }

  test("forgotPassword returns generic 200 for unknown email (anti-enumeration)", async () => {
    User.findOne = async () => null;

    const req = { body: { email: "nonexistent@example.com" } };
    const res = createMockResponse();

    await authController.forgotPassword(req, res);

    assert.equal(res.statusCode, 200);
    assert.equal(
      res.body.message,
      "If that email exists, a password reset link has been sent.",
    );
    assert.equal(res.body.resetToken, undefined);
    assert.equal(res.body.resetUrl, undefined);
    assert.equal(sentEmails.length, 0);
  });

  test("forgotPassword generates token, sends email, and NEVER exposes raw token in API response", async () => {
    const mockUser = new User({
      email: "victim@example.com",
      password: "hashedPassword123",
    });
    mockUser.save = async () => mockUser;
    User.findOne = async ({ email }) => (email === mockUser.email ? mockUser : null);

    const req = { body: { email: "victim@example.com" } };
    const res = createMockResponse();

    await authController.forgotPassword(req, res);

    // Response must be generic 200
    assert.equal(res.statusCode, 200);
    assert.equal(
      res.body.message,
      "If that email exists, a password reset link has been sent.",
    );

    // CRITICAL: Ensure raw token and URL are NEVER returned in response
    assert.equal(res.body.resetToken, undefined);
    assert.equal(res.body.resetUrl, undefined);

    // Email was dispatched
    assert.equal(sentEmails.length, 1);
    assert.equal(sentEmails[0].to, "victim@example.com");
    assert.match(sentEmails[0].html, new RegExp(`${config.FRONTEND_URL}/reset-password/`));

    // Stored token is a valid 64-char SHA-256 hash
    assert.equal(mockUser.resetPasswordToken.length, 64);
  });

  test("forgotPassword rolls back token and returns 500 when email delivery fails", async () => {
    const mockUser = new User({
      email: "user@example.com",
      password: "hashedPassword123",
    });
    let saveCount = 0;
    mockUser.save = async () => {
      saveCount++;
      return mockUser;
    };
    User.findOne = async () => mockUser;

    // Simulate SMTP failure
    emailUtil.setTransporter({
      sendMail: async () => {
        throw new Error("SMTP connection timeout");
      },
    });

    const req = { body: { email: "user@example.com" } };
    const res = createMockResponse();

    await authController.forgotPassword(req, res);

    assert.equal(res.statusCode, 500);
    assert.equal(
      res.body.message,
      "Failed to send reset email. Please try again later.",
    );

    // Token must be rolled back to null in DB
    assert.equal(mockUser.resetPasswordToken, null);
    assert.equal(mockUser.resetPasswordExpires, null);
    assert.ok(saveCount >= 2, "User should be saved on rollback");
  });

  test("verifyResetToken accepts valid, unexpired token", async () => {
    const validRawToken = "a".repeat(64);
    const expectedHash = crypto.createHash("sha256").update(validRawToken).digest("hex");

    User.findOne = async (query) => {
      if (query.resetPasswordToken === expectedHash && query.resetPasswordExpires.$gt) {
        return { email: "user@example.com" };
      }
      return null;
    };

    const req = { params: { token: validRawToken } };
    const res = createMockResponse();

    await authController.verifyResetToken(req, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.valid, true);
    assert.equal(res.body.message, "Token is valid");
  });

  test("verifyResetToken rejects expired or invalid token", async () => {
    User.findOne = async () => null;

    const req = { params: { token: "invalid_or_expired_token_123" } };
    const res = createMockResponse();

    await authController.verifyResetToken(req, res);

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.valid, false);
    assert.equal(res.body.message, "Invalid or expired reset token");
  });

  test("resetPassword atomically updates password, revokes sessions, and clears cookie", async () => {
    const rawToken = "b".repeat(64);
    const expectedHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    const mockUser = new User({
      email: "user@example.com",
      password: "oldPassword123",
      resetPasswordToken: expectedHash,
      resetPasswordExpires: new Date(Date.now() + 600000),
      refreshToken: "active_refresh_token_xyz",
    });

    mockUser.save = async function () {
      return this;
    };

    User.findOneAndUpdate = async (query, update) => {
      if (query.resetPasswordToken === expectedHash) {
        mockUser.resetPasswordToken = update.$set.resetPasswordToken;
        mockUser.resetPasswordExpires = update.$set.resetPasswordExpires;
        mockUser.refreshToken = update.$set.refreshToken;
        return mockUser;
      }
      return null;
    };

    const req = {
      params: { token: rawToken },
      body: { password: "BrandNewPassword1" },
    };
    const res = createMockResponse();

    await authController.resetPassword(req, res);

    assert.equal(res.statusCode, 200);
    assert.match(res.body.message, /Password reset successful/);

    // Password was updated
    assert.equal(mockUser.password, "BrandNewPassword1");

    // Single-use: resetPasswordToken and expires were set to null
    assert.equal(mockUser.resetPasswordToken, null);
    assert.equal(mockUser.resetPasswordExpires, null);

    // Session revocation: refreshToken was set to null
    assert.equal(mockUser.refreshToken, null);

    // Cookie was cleared
    assert.equal(res.cookiesCleared.length, 1);
    assert.equal(res.cookiesCleared[0].name, "refreshToken");
  });

  test("resetPassword rejects reused or invalid token", async () => {
    // findOneAndUpdate returns null when token was already invalidated
    User.findOneAndUpdate = async () => null;

    const req = {
      params: { token: "already_used_token_abc" },
      body: { password: "NewPassword123" },
    };
    const res = createMockResponse();

    await authController.resetPassword(req, res);

    assert.equal(res.statusCode, 400);
    assert.equal(res.body.message, "Invalid or expired reset token");
  });

  test("concurrent reset attempts with the same token guarantee atomic single-use", async () => {
    const rawToken = "c".repeat(64);
    const expectedHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    let tokenActive = true;
    const mockUser = new User({
      email: "racer@example.com",
      password: "initialPassword123",
      resetPasswordToken: expectedHash,
      resetPasswordExpires: new Date(Date.now() + 600000),
    });
    mockUser.save = async function () {
      return this;
    };

    // Simulate MongoDB's atomic findOneAndUpdate document write-lock
    User.findOneAndUpdate = async (query) => {
      if (query.resetPasswordToken === expectedHash && tokenActive) {
        // First concurrent caller atomically claims the token
        tokenActive = false;
        return mockUser;
      }
      // Second caller finds query.resetPasswordToken is no longer matched
      return null;
    };

    const reqA = { params: { token: rawToken }, body: { password: "WinnerPassword1" } };
    const resA = createMockResponse();

    const reqB = { params: { token: rawToken }, body: { password: "LoserPassword2" } };
    const resB = createMockResponse();

    // Fire both requests simultaneously
    await Promise.all([
      authController.resetPassword(reqA, resA),
      authController.resetPassword(reqB, resB),
    ]);

    // Exactly one request must succeed (200), and the other must fail (400)
    const statuses = [resA.statusCode, resB.statusCode].sort();
    assert.deepEqual(statuses, [200, 400]);

    const winner = resA.statusCode === 200 ? resA : resB;
    const loser = resA.statusCode === 400 ? resA : resB;

    assert.match(winner.body.message, /Password reset successful/);
    assert.equal(loser.body.message, "Invalid or expired reset token");
  });
});
