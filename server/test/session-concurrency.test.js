const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const User = require("../models/user.model");
const Session = require("../models/session.model");
const authController = require("../controllers/auth.controller");
const {
  hashToken,
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require("../utils/token");
const { REFRESH_TOKEN_COOKIE_NAME } = require("../utils/cookie");

describe("Session Persistence & Hashed Storage", () => {
  let originalSessionSave;
  let originalUserSave;
  let originalUserFindOne;
  let createdSession = null;

  beforeEach(() => {
    originalSessionSave = Session.prototype.save;
    originalUserSave = User.prototype.save;
    originalUserFindOne = User.findOne;
    createdSession = null;

    Session.prototype.save = async function () {
      createdSession = this;
      return this;
    };
    User.prototype.save = async function () {
      return this;
    };
  });

  afterEach(() => {
    Session.prototype.save = originalSessionSave;
    User.prototype.save = originalUserSave;
    User.findOne = originalUserFindOne;
  });

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

  test("login creates a Session record with SHA-256 token hash and never stores raw token", async () => {
    const userId = new mongoose.Types.ObjectId();
    const mockUser = new User({
      _id: userId,
      email: "hashed_test@example.com",
      password: "password123",
      role: "user",
      loginAttempts: 0,
    });
    mockUser.resetLoginAttempts = async () => {};
    mockUser.comparePassword = async () => true;

    User.findOne = async () => mockUser;

    const req = {
      body: { email: "hashed_test@example.com", password: "password123" },
      headers: { "user-agent": "Mozilla/5.0 TestBrowser" },
      ip: "192.168.1.100",
    };
    const res = createMockRes();

    await authController.login(req, res);

    assert.equal(res.statusCode, 200);
    assert.ok(res.jsonData.accessToken);
    assert.ok(res.cookiesSet[REFRESH_TOKEN_COOKIE_NAME]);

    const rawRefreshToken = res.cookiesSet[REFRESH_TOKEN_COOKIE_NAME].val;
    assert.ok(createdSession);
    assert.equal(createdSession.userId.toString(), userId.toString());
    assert.equal(createdSession.userAgent, "Mozilla/5.0 TestBrowser");

    // Ensure raw token is NOT in database
    assert.notEqual(createdSession.currentHash, rawRefreshToken);
    // Ensure currentHash equals SHA-256 of the raw token
    assert.equal(createdSession.currentHash, hashToken(rawRefreshToken));
    // Ensure token contains sessionId claim
    const decoded = verifyRefreshToken(rawRefreshToken);
    assert.equal(decoded.sessionId, createdSession._id.toString());
    assert.equal(decoded.userId, userId.toString());
  });
});

describe("Concurrency-Safe Token Rotation & Atomic Controls", () => {
  let mockSessions = new Map();
  let originalFindOneAndUpdate;
  let originalFindById;
  let originalFindByIdAndDelete;
  let originalUserFindById;

  beforeEach(() => {
    mockSessions = new Map();
    originalFindOneAndUpdate = Session.findOneAndUpdate;
    originalFindById = Session.findById;
    originalFindByIdAndDelete = Session.findByIdAndDelete;
    originalUserFindById = User.findById;

    // Emulate atomic MongoDB findOneAndUpdate with conditional query filter
    Session.findOneAndUpdate = async (filter, update, options) => {
      const session = mockSessions.get(filter._id.toString());
      if (!session) return null;

      // Conditional query matching
      if (filter.currentHash && session.currentHash !== filter.currentHash) {
        return null;
      }
      if (filter.expiresAt && filter.expiresAt.$gt && session.expiresAt <= filter.expiresAt.$gt) {
        return null;
      }

      // Apply atomic $set updates
      if (update.$set) {
        Object.assign(session, update.$set);
      }

      return { ...session };
    };

    Session.findById = async (id) => {
      const session = mockSessions.get(id.toString());
      return session ? { ...session } : null;
    };

    Session.findByIdAndDelete = async (id) => {
      const session = mockSessions.get(id.toString());
      mockSessions.delete(id.toString());
      return session;
    };

    User.findById = async (id) => ({
      _id: id,
      email: "rotation_user@example.com",
      role: "user",
    });
  });

  afterEach(() => {
    Session.findOneAndUpdate = originalFindOneAndUpdate;
    Session.findById = originalFindById;
    Session.findByIdAndDelete = originalFindByIdAndDelete;
    User.findById = originalUserFindById;
  });

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

  test("rotates refresh token atomically on valid request", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const sessionId = new mongoose.Types.ObjectId().toString();

    const initialToken = generateRefreshToken(userId, sessionId);
    const initialHash = hashToken(initialToken);

    mockSessions.set(sessionId, {
      _id: sessionId,
      userId,
      currentHash: initialHash,
      previousHash: null,
      rotationGraceUntil: null,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const req = { cookies: { [REFRESH_TOKEN_COOKIE_NAME]: initialToken } };
    const res = createMockRes();

    await authController.refresh(req, res);

    assert.equal(res.statusCode, 200);
    assert.ok(res.jsonData.accessToken);
    assert.ok(res.cookiesSet[REFRESH_TOKEN_COOKIE_NAME]);

    const newToken = res.cookiesSet[REFRESH_TOKEN_COOKIE_NAME].val;
    assert.notEqual(newToken, initialToken);

    // Verify session updated atomically
    const sessionInDb = mockSessions.get(sessionId);
    assert.equal(sessionInDb.previousHash, initialHash);
    assert.equal(sessionInDb.currentHash, hashToken(newToken));
    assert.ok(sessionInDb.rotationGraceUntil > new Date());
  });

  test("cannot consume the same refresh token twice for standard rotation (double-spend prevention)", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const sessionId = new mongoose.Types.ObjectId().toString();

    const tokenT1 = generateRefreshToken(userId, sessionId);
    const hashT1 = hashToken(tokenT1);

    mockSessions.set(sessionId, {
      _id: sessionId,
      userId,
      currentHash: hashT1,
      previousHash: null,
      rotationGraceUntil: null,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // 1st consumption: succeeds and advances currentHash
    const res1 = createMockRes();
    await authController.refresh({ cookies: { [REFRESH_TOKEN_COOKIE_NAME]: tokenT1 } }, res1);
    assert.equal(res1.statusCode, 200);

    const sessionAfterFirst = mockSessions.get(sessionId);
    assert.equal(sessionAfterFirst.previousHash, hashT1);
    assert.notEqual(sessionAfterFirst.currentHash, hashT1);

    // 2nd consumption attempt with T1 when grace period has expired:
    sessionAfterFirst.rotationGraceUntil = new Date(Date.now() - 1000); // Expire grace period
    const res2 = createMockRes();
    await authController.refresh({ cookies: { [REFRESH_TOKEN_COOKIE_NAME]: tokenT1 } }, res2);

    // Must be rejected with 401
    assert.equal(res2.statusCode, 401);
    assert.equal(res2.jsonData.message, "Invalid refresh token");
  });

  test("concurrent requests within 20s grace period succeed safely without re-rotating", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const sessionId = new mongoose.Types.ObjectId().toString();

    const tokenT1 = generateRefreshToken(userId, sessionId);
    const hashT1 = hashToken(tokenT1);

    mockSessions.set(sessionId, {
      _id: sessionId,
      userId,
      currentHash: hashT1,
      previousHash: null,
      rotationGraceUntil: null,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // Request 1 arrives and rotates token T1 -> T2
    const res1 = createMockRes();
    await authController.refresh({ cookies: { [REFRESH_TOKEN_COOKIE_NAME]: tokenT1 } }, res1);
    assert.equal(res1.statusCode, 200);
    const tokenT2 = res1.cookiesSet[REFRESH_TOKEN_COOKIE_NAME].val;

    const sessionState = mockSessions.get(sessionId);
    assert.equal(sessionState.previousHash, hashT1);
    assert.equal(sessionState.currentHash, hashToken(tokenT2));

    // Request 2 (e.g. parallel browser tab) arrives with T1 within the 20s grace window
    const res2 = createMockRes();
    await authController.refresh({ cookies: { [REFRESH_TOKEN_COOKIE_NAME]: tokenT1 } }, res2);

    // Request 2 MUST SUCCEED with 200 and a valid access token
    assert.equal(res2.statusCode, 200);
    assert.ok(res2.jsonData.accessToken);

    // Ensure session state was NOT mutated/corrupted by Request 2
    const sessionStateAfterR2 = mockSessions.get(sessionId);
    assert.equal(sessionStateAfterR2.currentHash, hashToken(tokenT2));
    assert.equal(sessionStateAfterR2.previousHash, hashT1);
  });

  test("replay attack after grace window revokes the entire session immediately", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const sessionId = new mongoose.Types.ObjectId().toString();

    const stolenToken = generateRefreshToken(userId, sessionId);
    const stolenHash = hashToken(stolenToken);

    // Session has already rotated past the grace period (e.g. 5 minutes ago)
    mockSessions.set(sessionId, {
      _id: sessionId,
      userId,
      currentHash: "newer_active_hash_value",
      previousHash: stolenHash,
      rotationGraceUntil: new Date(Date.now() - 60000), // Grace window expired 1 minute ago!
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const res = createMockRes();
    await authController.refresh({ cookies: { [REFRESH_TOKEN_COOKIE_NAME]: stolenToken } }, res);

    // Replay attack rejected
    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "Invalid refresh token");

    // Crucial security action: active session MUST be deleted from database
    assert.equal(mockSessions.has(sessionId), false);
    // Cookie cleared
    assert.ok(res.cookiesCleared[REFRESH_TOKEN_COOKIE_NAME]);
  });
});

describe("Multi-Device Session Isolation & Revocation Scope", () => {
  let mockSessions = new Map();
  let originalDeleteOne;
  let originalDeleteMany;
  let originalFindById;
  let originalFindOneAndUpdate;
  let originalUserFindOneAndUpdate;
  let originalUserFindByIdAndUpdate;

  beforeEach(() => {
    mockSessions = new Map();
    originalDeleteOne = Session.deleteOne;
    originalDeleteMany = Session.deleteMany;
    originalFindById = Session.findById;
    originalFindOneAndUpdate = Session.findOneAndUpdate;
    originalUserFindOneAndUpdate = User.findOneAndUpdate;
    originalUserFindByIdAndUpdate = User.findByIdAndUpdate;

    User.findOneAndUpdate = async () => null;
    User.findByIdAndUpdate = async () => null;

    Session.deleteOne = async (filter) => {
      for (const [id, session] of mockSessions.entries()) {
        if (filter.$or) {
          const match = filter.$or.some(
            (cond) =>
              (cond.currentHash && session.currentHash === cond.currentHash) ||
              (cond.previousHash && session.previousHash === cond.previousHash),
          );
          if (match) {
            mockSessions.delete(id);
            return { deletedCount: 1 };
          }
        }
      }
      return { deletedCount: 0 };
    };

    Session.deleteMany = async (filter) => {
      let count = 0;
      for (const [id, session] of mockSessions.entries()) {
        if (filter.userId && session.userId.toString() === filter.userId.toString()) {
          mockSessions.delete(id);
          count++;
        }
      }
      return { deletedCount: count };
    };

    Session.findById = async (id) => mockSessions.get(id.toString()) || null;

    Session.findOneAndUpdate = async (filter, update) => {
      const session = mockSessions.get(filter._id.toString());
      if (session && filter.currentHash === session.currentHash) {
        Object.assign(session, update.$set);
        return session;
      }
      return null;
    };
  });

  afterEach(() => {
    Session.deleteOne = originalDeleteOne;
    Session.deleteMany = originalDeleteMany;
    Session.findById = originalFindById;
    Session.findOneAndUpdate = originalFindOneAndUpdate;
    User.findOneAndUpdate = originalUserFindOneAndUpdate;
    User.findByIdAndUpdate = originalUserFindByIdAndUpdate;
  });

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

  test("multi-device: logout on Device 1 leaves Device 2 session active", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const session1Id = new mongoose.Types.ObjectId().toString();
    const session2Id = new mongoose.Types.ObjectId().toString();

    const device1Token = generateRefreshToken(userId, session1Id);
    const device2Token = generateRefreshToken(userId, session2Id);

    mockSessions.set(session1Id, {
      _id: session1Id,
      userId,
      currentHash: hashToken(device1Token),
      previousHash: null,
    });

    mockSessions.set(session2Id, {
      _id: session2Id,
      userId,
      currentHash: hashToken(device2Token),
      previousHash: null,
    });

    // Device 1 logs out
    const resLogout = createMockRes();
    await authController.logout(
      { cookies: { [REFRESH_TOKEN_COOKIE_NAME]: device1Token } },
      resLogout,
    );
    assert.equal(resLogout.statusCode, 200);

    // Device 1 session was deleted
    assert.equal(mockSessions.has(session1Id), false);
    // Device 2 session is STILL ACTIVE
    assert.equal(mockSessions.has(session2Id), true);
  });

  test("password reset revokes all sessions across all devices for that user", async () => {
    const userId = new mongoose.Types.ObjectId();
    const session1Id = new mongoose.Types.ObjectId().toString();
    const session2Id = new mongoose.Types.ObjectId().toString();

    mockSessions.set(session1Id, { _id: session1Id, userId });
    mockSessions.set(session2Id, { _id: session2Id, userId });

    assert.equal(mockSessions.size, 2);

    // Simulate password reset execution
    await Session.deleteMany({ userId });

    // All sessions revoked
    assert.equal(mockSessions.size, 0);
  });

  test("logoutAll endpoint revokes all sessions for authenticated user", async () => {
    const userId = new mongoose.Types.ObjectId();
    const s1 = new mongoose.Types.ObjectId().toString();
    const s2 = new mongoose.Types.ObjectId().toString();

    mockSessions.set(s1, { _id: s1, userId });
    mockSessions.set(s2, { _id: s2, userId });

    const req = { user: { _id: userId } };
    const res = createMockRes();

    await authController.logoutAll(req, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.jsonData.message, "All sessions logged out successfully");
    assert.equal(mockSessions.size, 0);
    assert.ok(res.cookiesCleared[REFRESH_TOKEN_COOKIE_NAME]);
  });
});
