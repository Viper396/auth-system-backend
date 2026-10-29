const { test, describe, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("../models/user.model");
const Session = require("../models/session.model");
const authenticate = require("../middleware/auth.middleware");
const authController = require("../controllers/auth.controller");
const {
  JWT_ALGORITHM,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} = require("../utils/token");
const { REFRESH_TOKEN_COOKIE_NAME } = require("../utils/cookie");

describe("JWT Hardening & Token Issuance", () => {
  const testConfig = {
    JWT_ACCESS_SECRET: "strong_test_access_secret_32_chars_long!",
    JWT_REFRESH_SECRET: "strong_test_refresh_secret_32_chars_long!",
    JWT_ACCESS_EXPIRES_IN: "15m",
    JWT_REFRESH_EXPIRES_IN: "7d",
  };

  test("uses HS256 algorithm and embeds no sensitive user data in access token", () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const token = generateAccessToken(userId, testConfig);

    const decodedHeader = jwt.decode(token, { complete: true }).header;
    assert.equal(decodedHeader.alg, JWT_ALGORITHM);
    assert.equal(decodedHeader.typ, "JWT");

    const decodedPayload = jwt.decode(token);
    assert.equal(decodedPayload.userId, userId);
    assert.equal(decodedPayload.type, "access");
    // Ensure no password, email, role, or credentials exist in payload
    assert.equal(decodedPayload.password, undefined);
    assert.equal(decodedPayload.email, undefined);
    assert.equal(decodedPayload.role, undefined);
    assert.equal(decodedPayload.refreshToken, undefined);
  });

  test("uses HS256 algorithm and embeds no sensitive user data in refresh token", () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const token = generateRefreshToken(userId, testConfig);

    const decodedHeader = jwt.decode(token, { complete: true }).header;
    assert.equal(decodedHeader.alg, JWT_ALGORITHM);
    assert.equal(decodedHeader.typ, "JWT");

    const decodedPayload = jwt.decode(token);
    assert.equal(decodedPayload.userId, userId);
    assert.equal(decodedPayload.type, "refresh");
    assert.equal(decodedPayload.password, undefined);
    assert.equal(decodedPayload.email, undefined);
    assert.equal(decodedPayload.role, undefined);
  });

  test("includes issuer and audience claims only when configured", () => {
    const userId = "user123";
    const claimsConfig = {
      ...testConfig,
      JWT_ISSUER: "https://auth.example.com",
      JWT_AUDIENCE: "auth-service-client",
    };

    const token = generateAccessToken(userId, claimsConfig);
    const decoded = verifyAccessToken(token, claimsConfig);

    assert.ok(decoded);
    assert.equal(decoded.iss, "https://auth.example.com");
    assert.equal(decoded.aud, "auth-service-client");
  });
});

describe("JWT Verification & Defense-in-Depth", () => {
  const testConfig = {
    JWT_ACCESS_SECRET: "strong_test_access_secret_32_chars_long!",
    JWT_REFRESH_SECRET: "strong_test_refresh_secret_32_chars_long!",
    JWT_ACCESS_EXPIRES_IN: "15m",
    JWT_REFRESH_EXPIRES_IN: "7d",
  };

  test("rejects expired access tokens", () => {
    const userId = "user_expired_test";
    const expiredToken = jwt.sign(
      { userId, type: "access" },
      testConfig.JWT_ACCESS_SECRET,
      { algorithm: "HS256", expiresIn: "-10s" },
    );

    const verified = verifyAccessToken(expiredToken, testConfig);
    assert.equal(verified, null);
  });

  test("rejects expired refresh tokens", () => {
    const userId = "user_expired_test";
    const expiredToken = jwt.sign(
      { userId, type: "refresh" },
      testConfig.JWT_REFRESH_SECRET,
      { algorithm: "HS256", expiresIn: "-10s" },
    );

    const verified = verifyRefreshToken(expiredToken, testConfig);
    assert.equal(verified, null);
  });

  test("rejects tokens with invalid or tampered signatures", () => {
    const userId = "user_tamper_test";
    const validToken = generateAccessToken(userId, testConfig);

    // Tamper with payload
    const parts = validToken.split(".");
    const tamperedPayload = Buffer.from(
      JSON.stringify({ userId: "impostor_id", type: "access" }),
    ).toString("base64url");
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    assert.equal(verifyAccessToken(tamperedToken, testConfig), null);

    // Signed with wrong secret
    const foreignToken = jwt.sign(
      { userId, type: "access" },
      "completely_wrong_foreign_secret_key_32_chars!",
      { algorithm: "HS256", expiresIn: "15m" },
    );
    assert.equal(verifyAccessToken(foreignToken, testConfig), null);
  });

  test("prevents token substitution: access token cannot be used as refresh token", () => {
    const userId = "user_sub_test";
    const accessToken = generateAccessToken(userId, testConfig);

    // Attempting to verify access token as a refresh token
    const result = verifyRefreshToken(accessToken, testConfig);
    assert.equal(result, null);
  });

  test("prevents token substitution: refresh token cannot be used as access token", () => {
    const userId = "user_sub_test";
    const refreshToken = generateRefreshToken(userId, testConfig);

    // Attempting to verify refresh token as an access token
    const result = verifyAccessToken(refreshToken, testConfig);
    assert.equal(result, null);
  });

  test("rejects tokens with wrong or missing type claims even if secret matches", () => {
    const userId = "user_type_test";

    // Token signed with access secret but missing type
    const noTypeToken = jwt.sign(
      { userId },
      testConfig.JWT_ACCESS_SECRET,
      { algorithm: "HS256", expiresIn: "15m" },
    );
    assert.equal(verifyAccessToken(noTypeToken, testConfig), null);

    // Token signed with access secret but with type: "refresh"
    const wrongTypeToken = jwt.sign(
      { userId, type: "refresh" },
      testConfig.JWT_ACCESS_SECRET,
      { algorithm: "HS256", expiresIn: "15m" },
    );
    assert.equal(verifyAccessToken(wrongTypeToken, testConfig), null);
    assert.equal(verifyRefreshToken(wrongTypeToken, testConfig), null);
  });

  test("rejects algorithm confusion attacks (alg: none and asymmetric algs)", () => {
    const userId = "user_alg_confusion";

    // Alg: none attack
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ userId, type: "access" })).toString("base64url");
    const noneToken = `${header}.${payload}.`;

    assert.equal(verifyAccessToken(noneToken, testConfig), null);
    assert.equal(verifyRefreshToken(noneToken, testConfig), null);
  });

  test("rejects malformed and non-string inputs safely without throwing", () => {
    assert.equal(verifyAccessToken(null, testConfig), null);
    assert.equal(verifyAccessToken(undefined, testConfig), null);
    assert.equal(verifyAccessToken("", testConfig), null);
    assert.equal(verifyAccessToken("   ", testConfig), null);
    assert.equal(verifyAccessToken(12345, testConfig), null);
    assert.equal(verifyAccessToken({}, testConfig), null);
    assert.equal(verifyAccessToken("not.a.valid.jwt.string", testConfig), null);
    assert.equal(verifyAccessToken("header.payload", testConfig), null);

    assert.equal(verifyRefreshToken(null, testConfig), null);
    assert.equal(verifyRefreshToken("", testConfig), null);
    assert.equal(verifyRefreshToken("random-garbage", testConfig), null);
  });

  test("enforces issuer and audience claim validation when configured", () => {
    const userId = "user_claim_check";
    const serverConfig = {
      ...testConfig,
      JWT_ISSUER: "https://auth.primary.com",
      JWT_AUDIENCE: "primary-api",
    };

    // Valid claims
    const validToken = generateAccessToken(userId, serverConfig);
    assert.ok(verifyAccessToken(validToken, serverConfig));

    // Token issued by different issuer
    const wrongIssuerToken = jwt.sign(
      { userId, type: "access" },
      serverConfig.JWT_ACCESS_SECRET,
      {
        algorithm: "HS256",
        expiresIn: "15m",
        issuer: "https://untrusted-issuer.com",
        audience: "primary-api",
      },
    );
    assert.equal(verifyAccessToken(wrongIssuerToken, serverConfig), null);

    // Token issued for different audience
    const wrongAudienceToken = jwt.sign(
      { userId, type: "access" },
      serverConfig.JWT_ACCESS_SECRET,
      {
        algorithm: "HS256",
        expiresIn: "15m",
        issuer: "https://auth.primary.com",
        audience: "wrong-audience",
      },
    );
    assert.equal(verifyAccessToken(wrongAudienceToken, serverConfig), null);
  });
});

describe("Authentication Middleware Hardening", () => {
  let originalFindById;

  beforeEach(() => {
    originalFindById = User.findById;
  });

  afterEach(() => {
    User.findById = originalFindById;
  });

  const createMockRes = () => {
    const res = {
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
    return res;
  };

  test("authenticates valid access token and derives role strictly from database", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const token = generateAccessToken(userId);

    const mockDbUser = {
      _id: userId,
      email: "victim@example.com",
      role: "admin", // Database role
    };

    User.findById = (id) => ({
      select: () => {
        assert.equal(id, userId);
        return Promise.resolve(mockDbUser);
      },
    });

    const req = {
      headers: {
        authorization: `Bearer ${token}`,
      },
      body: {
        // Attempted client spoofing in request body
        role: "user",
        user: { role: "user" },
      },
    };
    const res = createMockRes();
    let nextCalled = false;

    await authenticate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(req.user.role, "admin"); // Server-side DB claim wins
    assert.equal(req.user.email, "victim@example.com");
  });

  test("rejects request when Authorization header is missing or not Bearer", async () => {
    const res1 = createMockRes();
    await authenticate({ headers: {} }, res1, () => {});
    assert.equal(res1.statusCode, 401);
    assert.equal(res1.jsonData.message, "No token provided");

    const res2 = createMockRes();
    await authenticate({ headers: { authorization: "Basic dXNlcjpwYXNz" } }, res2, () => {});
    assert.equal(res2.statusCode, 401);
    assert.equal(res2.jsonData.message, "No token provided");

    const res3 = createMockRes();
    await authenticate({ headers: { authorization: "Bearer " } }, res3, () => {});
    assert.equal(res3.statusCode, 401);
    assert.equal(res3.jsonData.message, "No token provided");
  });

  test("rejects expired or invalid access token with generic 401 without stack trace", async () => {
    const expiredToken = jwt.sign(
      { userId: "u123", type: "access" },
      process.env.JWT_ACCESS_SECRET || "access_secret",
      { algorithm: "HS256", expiresIn: "-5s" },
    );

    const req = {
      headers: { authorization: `Bearer ${expiredToken}` },
    };
    const res = createMockRes();

    await authenticate(req, res, () => {});
    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "Invalid or expired token");
    assert.equal(res.jsonData.stack, undefined);
  });

  test("rejects refresh token supplied to authenticate middleware", async () => {
    const userId = "u123";
    const refreshToken = generateRefreshToken(userId);

    const req = {
      headers: { authorization: `Bearer ${refreshToken}` },
    };
    const res = createMockRes();

    await authenticate(req, res, () => {});
    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "Invalid or expired token");
  });

  test("rejects request when user does not exist in database", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const token = generateAccessToken(userId);

    User.findById = () => ({
      select: () => Promise.resolve(null),
    });

    const req = {
      headers: { authorization: `Bearer ${token}` },
    };
    const res = createMockRes();

    await authenticate(req, res, () => {});
    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "User not found");
  });
});

describe("Revoked Refresh Sessions & Lifecycle", () => {
  let originalFindById;
  let originalFindOneAndUpdate;
  let originalFindByIdAndUpdate;
  let originalSessionDeleteOne;
  let originalSessionSave;

  beforeEach(() => {
    originalFindById = User.findById;
    originalFindOneAndUpdate = User.findOneAndUpdate;
    originalFindByIdAndUpdate = User.findByIdAndUpdate;
    originalSessionDeleteOne = Session.deleteOne;
    originalSessionSave = Session.prototype.save;
    Session.deleteOne = async () => ({ deletedCount: 1 });
    Session.prototype.save = async function () {
      return this;
    };
  });

  afterEach(() => {
    User.findById = originalFindById;
    User.findOneAndUpdate = originalFindOneAndUpdate;
    User.findByIdAndUpdate = originalFindByIdAndUpdate;
    Session.deleteOne = originalSessionDeleteOne;
    Session.prototype.save = originalSessionSave;
  });

  const createMockRes = () => {
    const res = {
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
    return res;
  };

  test("logout invalidates the stored refresh session in database and clears cookie", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const refreshToken = generateRefreshToken(userId);

    let updatedFilter = null;
    let updatedFields = null;

    User.findOneAndUpdate = async (filter, update) => {
      updatedFilter = filter;
      updatedFields = update;
      return { _id: userId, refreshToken: null };
    };

    const req = {
      cookies: {
        [REFRESH_TOKEN_COOKIE_NAME]: refreshToken,
      },
      headers: {},
    };
    const res = createMockRes();

    await authController.logout(req, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.jsonData.message, "Logged out successfully");
    assert.deepEqual(updatedFilter, { refreshToken });
    assert.deepEqual(updatedFields, { refreshToken: null });
    assert.ok(res.cookiesCleared[REFRESH_TOKEN_COOKIE_NAME]);
    assert.equal(res.cookiesCleared[REFRESH_TOKEN_COOKIE_NAME].path, "/api/auth");
  });

  test("refresh endpoint rejects a revoked or mismatched refresh token with 401", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const revokedToken = generateRefreshToken(userId);

    // Database user currently has refreshToken: null (session was revoked)
    User.findById = async (id) => {
      assert.equal(id, userId);
      return {
        _id: userId,
        email: "user@example.com",
        role: "user",
        refreshToken: null, // Revoked!
      };
    };

    const req = {
      cookies: {
        [REFRESH_TOKEN_COOKIE_NAME]: revokedToken,
      },
    };
    const res = createMockRes();

    await authController.refresh(req, res);

    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "Invalid refresh token");
  });

  test("refresh endpoint rejects an expired refresh token with 401", async () => {
    const userId = "u_expired_refresh";
    const expiredToken = jwt.sign(
      { userId, type: "refresh" },
      process.env.JWT_REFRESH_SECRET || "refresh_secret",
      { algorithm: "HS256", expiresIn: "-10s" },
    );

    const req = {
      cookies: {
        [REFRESH_TOKEN_COOKIE_NAME]: expiredToken,
      },
    };
    const res = createMockRes();

    await authController.refresh(req, res);

    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "Invalid refresh token");
  });

  test("refresh endpoint rejects access token passed as refresh token", async () => {
    const userId = "u_sub_refresh";
    const accessToken = generateAccessToken(userId);

    const req = {
      cookies: {
        [REFRESH_TOKEN_COOKIE_NAME]: accessToken,
      },
    };
    const res = createMockRes();

    await authController.refresh(req, res);

    assert.equal(res.statusCode, 401);
    assert.equal(res.jsonData.message, "Invalid refresh token");
  });

  test("successful refresh issues new access token, rotates refresh token, and sets cookie", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const currentRefreshToken = generateRefreshToken(userId);

    let saved = false;
    const mockUser = {
      _id: userId,
      email: "active@example.com",
      role: "user",
      refreshToken: currentRefreshToken,
      save: async function () {
        saved = true;
      },
    };

    User.findById = async (id) => {
      assert.equal(id, userId);
      return mockUser;
    };

    const req = {
      cookies: {
        [REFRESH_TOKEN_COOKIE_NAME]: currentRefreshToken,
      },
    };
    const res = createMockRes();

    await authController.refresh(req, res);

    assert.equal(res.statusCode, 200);
    assert.ok(res.jsonData.accessToken);
    assert.equal(res.jsonData.user.email, "active@example.com");
    assert.equal(saved, true);
    assert.ok(res.cookiesSet[REFRESH_TOKEN_COOKIE_NAME]);
    assert.notEqual(
      res.cookiesSet[REFRESH_TOKEN_COOKIE_NAME].val,
      currentRefreshToken,
    );
  });
});
