const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("../models/user.model");
const Session = require("../models/session.model");
const authController = require("../controllers/auth.controller");
const { REFRESH_TOKEN_COOKIE_NAME } = require("../utils/cookie");

const createMockRes = () => {
  return {
    statusCode: 200,
    jsonData: null,
    cookiesSet: {},
    cookiesCleared: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.jsonData = data;
      return this;
    },
    cookie(name, val, options) {
      this.cookiesSet[name] = { val, options };
    },
    clearCookie(name, options) {
      this.cookiesCleared[name] = options;
    },
  };
};

describe("Registration Flow & Password Hashing", () => {
  let originalFindOne;
  let originalCreate;

  beforeEach(() => {
    originalFindOne = User.findOne;
    originalCreate = User.create;
  });

  afterEach(() => {
    User.findOne = originalFindOne;
    User.create = originalCreate;
  });

  test("registers a new user successfully and returns user without password", async () => {
    User.findOne = async () => null;

    let createdUserDoc = null;
    User.create = async (payload) => {
      createdUserDoc = {
        _id: new mongoose.Types.ObjectId(),
        email: payload.email,
        role: "user",
      };
      return createdUserDoc;
    };

    const req = {
      body: {
        email: "newuser@example.com",
        password: "password123",
      },
    };
    const res = createMockRes();

    await authController.signup(req, res);

    assert.equal(res.statusCode, 201);
    assert.equal(res.jsonData.message, "User created successfully");
    assert.ok(res.jsonData.user.id);
    assert.equal(res.jsonData.user.email, "newuser@example.com");
    assert.equal(res.jsonData.user.role, "user");
    // Password must NEVER be returned in response
    assert.equal(res.jsonData.user.password, undefined);
  });

  test("rejects registration when email or password is missing", async () => {
    const res1 = createMockRes();
    await authController.signup({ body: { email: "" } }, res1);
    assert.equal(res1.statusCode, 400);
    assert.equal(res1.jsonData.message, "Email and password required");

    const res2 = createMockRes();
    await authController.signup({ body: { password: "password123" } }, res2);
    assert.equal(res2.statusCode, 400);
    assert.equal(res2.jsonData.message, "Email and password required");
  });

  test("rejects registration when password is less than 6 characters", async () => {
    const req = {
      body: {
        email: "shortpass@example.com",
        password: "123",
      },
    };
    const res = createMockRes();

    await authController.signup(req, res);

    assert.equal(res.statusCode, 400);
    assert.equal(res.jsonData.message, "Password must be at least 6 characters");
  });

  test("rejects registration when email already exists (duplicate account)", async () => {
    User.findOne = async () => ({
      _id: new mongoose.Types.ObjectId(),
      email: "existing@example.com",
    });

    const req = {
      body: {
        email: "existing@example.com",
        password: "password123",
      },
    };
    const res = createMockRes();

    await authController.signup(req, res);

    assert.equal(res.statusCode, 400);
    assert.equal(res.jsonData.message, "User already exists");
  });

  test("handles database errors during registration gracefully", async () => {
    User.findOne = async () => {
      throw new Error("Database connection dropped");
    };

    const req = {
      body: { email: "fail@example.com", password: "password123" },
    };
    const res = createMockRes();

    await authController.signup(req, res);

    assert.equal(res.statusCode, 500);
    assert.equal(res.jsonData.message, "Server error");
    assert.equal(res.jsonData.stack, undefined);
  });
});

describe("User Model Password Hashing & Schema Constraints", () => {
  test("bcrypt pre-save hook securely hashes password with salt", async () => {
    const rawPassword = "plainSecretPassword123";
    const user = new User({
      email: "hash_test@example.com",
      password: rawPassword,
    });

    // Run the pre-save middleware manually to test model hook without DB
    await user.schema.s.hooks.execPre("save", user);

    // Password must be hashed (starts with $2a$ or $2b$)
    assert.notEqual(user.password, rawPassword);
    assert.match(user.password, /^\$2[ab]\$\d+\$/);

    // comparePassword must successfully verify the hash
    const match = await user.comparePassword(rawPassword);
    assert.equal(match, true);

    const wrongMatch = await user.comparePassword("wrongSecretPassword");
    assert.equal(wrongMatch, false);
  });

  test("email field enforces trimming and lowercase normalization in schema", () => {
    const user = new User({
      email: "   TEST.User+tag@EXAMPLE.COM   ",
      password: "password123",
    });

    assert.equal(user.email, "test.user+tag@example.com");
  });

  test("isLocked virtual correctly computes lockout state", () => {
    const futureLock = new User({
      email: "locked@example.com",
      password: "password123",
      lockUntil: new Date(Date.now() + 60000), // 1 min in future
    });
    assert.equal(futureLock.isLocked, true);

    const expiredLock = new User({
      email: "unlocked@example.com",
      password: "password123",
      lockUntil: new Date(Date.now() - 60000), // 1 min in past
    });
    assert.equal(expiredLock.isLocked, false);

    const nullLock = new User({
      email: "clean@example.com",
      password: "password123",
      lockUntil: null,
    });
    assert.equal(nullLock.isLocked, false);
  });

  test("incLoginAttempts resets attempts count when previous lockout expired", async () => {
    const user = new User({
      email: "reset_attempts@example.com",
      password: "password123",
      loginAttempts: 5,
      lockUntil: new Date(Date.now() - 10000), // Expired lockout
    });

    let updatePayload = null;
    user.updateOne = async (updates) => {
      updatePayload = updates;
      return updates;
    };

    await user.incLoginAttempts();

    assert.deepEqual(updatePayload, {
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 },
    });
  });
});

describe("Login Flow: Successful and Unsuccessful", () => {
  let originalFindOne;
  let originalFindById;
  let originalSessionSave;

  beforeEach(() => {
    originalFindOne = User.findOne;
    originalFindById = User.findById;
    originalSessionSave = Session.prototype.save;
    Session.prototype.save = async function () {
      return this;
    };
  });

  afterEach(() => {
    User.findOne = originalFindOne;
    User.findById = originalFindById;
    Session.prototype.save = originalSessionSave;
  });

  test("successful login returns 200, JWT access token, user info, and sets refresh cookie", async () => {
    const userId = new mongoose.Types.ObjectId();
    let resetAttemptsCalled = false;

    const mockUser = new User({
      _id: userId,
      email: "login_ok@example.com",
      password: "password123",
      role: "user",
      loginAttempts: 2,
    });
    mockUser.resetLoginAttempts = async () => {
      resetAttemptsCalled = true;
    };
    mockUser.comparePassword = async (candidate) => candidate === "password123";

    User.findOne = async () => mockUser;

    const req = {
      body: {
        email: "login_ok@example.com",
        password: "password123",
      },
      headers: { "user-agent": "TestBrowser" },
      ip: "127.0.0.1",
    };
    const res = createMockRes();

    await authController.login(req, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.jsonData.message, "Login successful");
    assert.ok(res.jsonData.accessToken);
    assert.equal(res.jsonData.user.id.toString(), userId.toString());
    assert.equal(res.jsonData.user.email, "login_ok@example.com");
    assert.equal(res.jsonData.user.role, "user");
    assert.equal(resetAttemptsCalled, true);
    assert.ok(res.cookiesSet[REFRESH_TOKEN_COOKIE_NAME]);
    assert.equal(res.cookiesSet[REFRESH_TOKEN_COOKIE_NAME].options.httpOnly, true);
  });

  test("rejects login when email or password is missing", async () => {
    const res1 = createMockRes();
    await authController.login({ body: { email: "" } }, res1);
    assert.equal(res1.statusCode, 400);
    assert.equal(res1.jsonData.message, "Email and password required");

    const res2 = createMockRes();
    await authController.login({ body: { password: "pass" } }, res2);
    assert.equal(res2.statusCode, 400);
    assert.equal(res2.jsonData.message, "Email and password required");
  });

  test("rejects login with 401 when email does not exist without disclosing user absence", async () => {
    User.findOne = async () => null;

    const req = {
      body: {
        email: "nonexistent@example.com",
        password: "password123",
      },
    };
    const res = createMockRes();

    await authController.login(req, res);

    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "Invalid credentials");
  });

  test("rejects login with 401 on wrong password and increments failed attempts", async () => {
    const userId = new mongoose.Types.ObjectId();
    let incAttemptsCalled = false;

    const mockUser = new User({
      _id: userId,
      email: "wrong_pass@example.com",
      password: "correctpassword",
      role: "user",
      loginAttempts: 1,
    });
    mockUser.incLoginAttempts = async () => {
      incAttemptsCalled = true;
    };
    mockUser.comparePassword = async () => false; // Wrong password!

    User.findOne = async () => mockUser;
    User.findById = async () => mockUser;

    const req = {
      body: {
        email: "wrong_pass@example.com",
        password: "badpassword",
      },
    };
    const res = createMockRes();

    await authController.login(req, res);

    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "Invalid credentials");
    assert.equal(incAttemptsCalled, true);
  });

  test("rejects login with 423 when account is already locked", async () => {
    const mockUser = new User({
      _id: new mongoose.Types.ObjectId(),
      email: "already_locked@example.com",
      password: "password123",
      loginAttempts: 5,
      lockUntil: new Date(Date.now() + 15 * 60 * 1000),
    });

    User.findOne = async () => mockUser;

    const req = {
      body: {
        email: "already_locked@example.com",
        password: "password123",
      },
    };
    const res = createMockRes();

    await authController.login(req, res);

    assert.equal(res.statusCode, 423);
    assert.match(res.jsonData.message, /Account locked/);
  });

  test("handles database errors during login gracefully without leaking details", async () => {
    User.findOne = async () => {
      throw new Error("Mongo network error");
    };

    const req = {
      body: { email: "err@example.com", password: "password123" },
    };
    const res = createMockRes();

    await authController.login(req, res);

    assert.equal(res.statusCode, 500);
    assert.equal(res.jsonData.message, "Server error");
  });
});
