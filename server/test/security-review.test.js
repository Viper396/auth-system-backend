const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const mongoose = require("mongoose");
const User = require("../models/user.model");
const authenticate = require("../middleware/auth.middleware");
const authorize = require("../middleware/role.middleware");
const authController = require("../controllers/auth.controller");
const userController = require("../controllers/user.controller");
const adminController = require("../controllers/admin.controller");
const { generateAccessToken } = require("../utils/token");
const { resetPasswordLimiter } = require("../middleware/rateLimit.middleware");

const createMockRes = () => {
  return {
    statusCode: 200,
    jsonData: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.jsonData = data;
      return this;
    },
  };
};

describe("Authentication & RBAC Server-Side Enforcement", () => {
  let originalFindById;

  beforeEach(() => {
    originalFindById = User.findById;
  });

  afterEach(() => {
    User.findById = originalFindById;
  });

  test("rejects unauthenticated requests to protected endpoints with 401", async () => {
    const req = { headers: {} };
    const res = createMockRes();
    let nextCalled = false;

    await authenticate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "No token provided");
    assert.equal(res.jsonData.stack, undefined);
  });

  test("denies ordinary authenticated users access to admin routes with 403 Forbidden", async () => {
    const regularUserId = new mongoose.Types.ObjectId().toString();
    const token = generateAccessToken(regularUserId);

    User.findById = () => ({
      select: () =>
        Promise.resolve({
          _id: regularUserId,
          email: "regular@example.com",
          role: "user", // Normal user role
        }),
    });

    const req = {
      headers: { authorization: `Bearer ${token}` },
    };
    const resAuth = createMockRes();
    let authNextCalled = false;

    await authenticate(req, resAuth, () => {
      authNextCalled = true;
    });

    assert.equal(authNextCalled, true);
    assert.equal(req.user.role, "user");

    // Pass through authorize("admin")
    const resAdmin = createMockRes();
    let adminNextCalled = false;
    const adminMiddleware = authorize("admin");

    adminMiddleware(req, resAdmin, () => {
      adminNextCalled = true;
    });

    assert.equal(adminNextCalled, false);
    assert.equal(resAdmin.statusCode, 403);
    assert.match(resAdmin.jsonData.message, /Access denied/);
    assert.equal(resAdmin.jsonData.yourRole, "user");
  });

  test("allows admin user access to admin routes", async () => {
    const adminUserId = new mongoose.Types.ObjectId().toString();
    const req = {
      user: {
        _id: adminUserId,
        email: "admin@example.com",
        role: "admin",
      },
    };
    const res = createMockRes();
    let adminNextCalled = false;

    const adminMiddleware = authorize("admin");
    adminMiddleware(req, res, () => {
      adminNextCalled = true;
    });

    assert.equal(adminNextCalled, true);
    assert.equal(res.statusCode, 200);
  });
});

describe("Privilege Escalation Prevention", () => {
  let originalUserCreate;
  let createdUserPayload = null;

  beforeEach(() => {
    originalUserCreate = User.create;
    createdUserPayload = null;
    User.create = async (payload) => {
      createdUserPayload = payload;
      return {
        _id: new mongoose.Types.ObjectId(),
        email: payload.email,
        role: "user", // Default schema role
      };
    };
  });

  afterEach(() => {
    User.create = originalUserCreate;
  });

  test("registration ignores client-supplied role: 'admin' and sets default 'user'", async () => {
    User.findOne = async () => null; // No existing user

    const req = {
      body: {
        email: "hacker@example.com",
        password: "password123",
        role: "admin", // Malicious attempt to self-elevate
      },
    };
    const res = createMockRes();

    await authController.signup(req, res);

    assert.equal(res.statusCode, 201);
    // User.create should ONLY receive { email, password }, never role
    assert.equal(createdUserPayload.role, undefined);
    assert.equal(res.jsonData.user.role, "user");
  });

  test("profile update ignores client-supplied role and prevents self-elevation", async () => {
    let saved = false;
    const mockUser = {
      _id: new mongoose.Types.ObjectId(),
      email: "victim@example.com",
      role: "user",
      save: async function () {
        saved = true;
      },
    };

    User.findOne = async () => null; // Email not taken

    const req = {
      user: mockUser,
      body: {
        email: "newemail@example.com",
        role: "admin", // Malicious attempt to elevate role via profile update
      },
    };
    const res = createMockRes();

    await userController.updateProfile(req, res);

    assert.equal(res.statusCode, 200);
    assert.equal(saved, true);
    // Email updated
    assert.equal(mockUser.email, "newemail@example.com");
    // Role remains strictly 'user'
    assert.equal(mockUser.role, "user");
    assert.equal(res.jsonData.user.role, "user");
  });
});

describe("Account Lockout & DoS Mitigation", () => {
  let originalFindById;

  beforeEach(() => {
    originalFindById = User.findById;
  });

  afterEach(() => {
    User.findById = originalFindById;
  });

  test("account locks out after max failed attempts and returns HTTP 423 with time left", async () => {
    const lockTime = 15 * 60 * 1000;
    const lockedUser = new User({
      email: "brute@example.com",
      password: "password123",
      loginAttempts: 5,
      lockUntil: new Date(Date.now() + lockTime),
    });

    User.findOne = async () => lockedUser;

    const req = {
      body: { email: "brute@example.com", password: "wrongpassword" },
    };
    const res = createMockRes();

    await authController.login(req, res);

    assert.equal(res.statusCode, 423);
    assert.match(res.jsonData.message, /Account locked due to too many failed login attempts/);
    assert.match(res.jsonData.message, /Try again in/);
  });

  test("password reset resets failed attempts and unlocks account", async () => {
    const user = new User({
      email: "locked@example.com",
      password: "oldpassword123",
      loginAttempts: 5,
      lockUntil: new Date(Date.now() + 15 * 60 * 1000),
      resetPasswordToken: "some_hash",
      resetPasswordExpires: new Date(Date.now() + 15 * 60 * 1000),
    });

    assert.equal(user.isLocked, true);

    // resetLoginAttempts resets attempts and unsets lockUntil
    let updateParams = null;
    user.updateOne = async (updates) => {
      updateParams = updates;
      user.loginAttempts = updates.$set?.loginAttempts ?? user.loginAttempts;
      if (updates.$unset?.lockUntil) user.lockUntil = null;
    };

    await user.resetLoginAttempts();

    assert.equal(user.loginAttempts, 0);
    assert.equal(user.isLocked, false);
    assert.deepEqual(updateParams, {
      $set: { loginAttempts: 0 },
      $unset: { lockUntil: 1 },
    });
  });

  test("email normalization ensures case variations map to the same account", () => {
    const user1 = new User({ email: "  User.Name@Example.COM  ", password: "password123" });
    assert.equal(user1.email, "user.name@example.com");

    const user2 = new User({ email: "USER@DOMAIN.COM", password: "password123" });
    assert.equal(user2.email, "user@domain.com");
  });
});

describe("Administrative Boundary & Self-Action Guards", () => {
  let originalFindById;
  let originalFindByIdAndDelete;

  beforeEach(() => {
    originalFindById = User.findById;
    originalFindByIdAndDelete = User.findByIdAndDelete;
  });

  afterEach(() => {
    User.findById = originalFindById;
    User.findByIdAndDelete = originalFindByIdAndDelete;
  });

  test("prevents administrator from deleting their own account", async () => {
    const adminId = new mongoose.Types.ObjectId().toString();

    User.findById = async (id) => ({
      _id: id,
      email: "admin@example.com",
      role: "admin",
    });

    const req = {
      params: { id: adminId },
      user: { _id: adminId }, // Calling admin is target user
    };
    const res = createMockRes();

    await adminController.deleteUser(req, res);

    assert.equal(res.statusCode, 400);
    assert.equal(res.jsonData.message, "Cannot delete your own account");
  });

  test("prevents administrator from demoting themselves to user", async () => {
    const adminId = new mongoose.Types.ObjectId().toString();

    User.findById = async (id) => ({
      _id: id,
      email: "admin@example.com",
      role: "admin",
    });

    const req = {
      params: { id: adminId },
      user: { _id: adminId },
      body: { role: "user" }, // Attempting self-demotion
    };
    const res = createMockRes();

    await adminController.updateUserRole(req, res);

    assert.equal(res.statusCode, 400);
    assert.equal(res.jsonData.message, "Cannot demote yourself");
  });

  test("rejects invalid role values with 400", async () => {
    const targetUserId = new mongoose.Types.ObjectId().toString();
    const adminId = new mongoose.Types.ObjectId().toString();

    const req = {
      params: { id: targetUserId },
      user: { _id: adminId },
      body: { role: "superadmin" }, // Invalid role
    };
    const res = createMockRes();

    await adminController.updateUserRole(req, res);

    assert.equal(res.statusCode, 400);
    assert.match(res.jsonData.message, /Invalid role/);
  });
});

describe("Rate Limiter Response Hygiene & 429 Status", () => {
  test("rate limiter responds with 429 and clean JSON message without stack traces", async () => {
    let statusCode = null;
    let responseBody = null;

    const createTestRes = () => {
      const res = {
        setHeader: () => {},
        getHeader: () => {},
        status: (code) => {
          statusCode = code;
          return res;
        },
        send: (body) => {
          responseBody = body;
          return res;
        },
      };
      return res;
    };

    // Exhaust 5 allowed attempts on resetPasswordLimiter
    for (let i = 0; i < 5; i++) {
      const req = {
        ip: "192.0.2.1",
        headers: {},
        app: { get: () => false },
      };
      await new Promise((resolve) =>
        resetPasswordLimiter(req, createTestRes(), resolve),
      );
    }

    // 6th attempt should trigger 429
    let nextCalled = false;
    const req6 = {
      ip: "192.0.2.1",
      headers: {},
      app: { get: () => false },
    };
    await new Promise((resolve) => {
      resetPasswordLimiter(req6, createTestRes(), () => {
        nextCalled = true;
        resolve();
      });
      setTimeout(resolve, 50);
    });

    assert.equal(nextCalled, false);
    assert.equal(statusCode, 429);
    assert.ok(responseBody);
    assert.match(responseBody.message, /Too many password reset attempts/);
    assert.equal(responseBody.stack, undefined);
  });
});
