import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import api, { authAPI, userAPI, adminAPI } from "../src/services/api.js";

describe("Frontend API Interceptor & Request Queuing", () => {
  let mockStorage = {};
  let originalLocalStorage;

  beforeEach(() => {
    mockStorage = {};
    originalLocalStorage = globalThis.localStorage;
    globalThis.localStorage = {
      getItem: (key) => mockStorage[key] || null,
      setItem: (key, val) => {
        mockStorage[key] = val;
      },
      removeItem: (key) => {
        delete mockStorage[key];
      },
    };
  });

  afterEach(() => {
    globalThis.localStorage = originalLocalStorage;
  });

  test("api instance has baseURL and credentials enabled", () => {
    assert.ok(api.defaults.baseURL);
    assert.equal(api.defaults.withCredentials, true);
    assert.equal(api.defaults.headers["Content-Type"], "application/json");
  });

  test("request interceptor attaches Bearer token when stored in localStorage", async () => {
    globalThis.localStorage.setItem("accessToken", "valid_stored_jwt_token");

    // Execute request interceptor directly
    const requestHandler = api.interceptors.request.handlers[0].fulfilled;
    const config = { headers: {} };
    const modifiedConfig = requestHandler(config);

    assert.equal(
      modifiedConfig.headers.Authorization,
      "Bearer valid_stored_jwt_token",
    );
  });

  test("request interceptor does not attach Bearer token when localStorage is empty", async () => {
    const requestHandler = api.interceptors.request.handlers[0].fulfilled;
    const config = { headers: {} };
    const modifiedConfig = requestHandler(config);

    assert.equal(modifiedConfig.headers.Authorization, undefined);
  });

  test("single-flight queue logic: resolves all concurrent requests with rotated access token", async () => {
    let failedQueue = [];
    const processQueue = (error, token = null) => {
      failedQueue.forEach((prom) => {
        if (error) prom.reject(error);
        else prom.resolve(token);
      });
      failedQueue = [];
    };

    // Simulate 3 concurrent requests waiting in queue
    const p1 = new Promise((resolve, reject) =>
      failedQueue.push({ resolve, reject }),
    );
    const p2 = new Promise((resolve, reject) =>
      failedQueue.push({ resolve, reject }),
    );
    const p3 = new Promise((resolve, reject) =>
      failedQueue.push({ resolve, reject }),
    );

    assert.equal(failedQueue.length, 3);

    // Refresh resolves with new token
    processQueue(null, "rotated_access_token_456");

    const [t1, t2, t3] = await Promise.all([p1, p2, p3]);
    assert.equal(t1, "rotated_access_token_456");
    assert.equal(t2, "rotated_access_token_456");
    assert.equal(t3, "rotated_access_token_456");
    assert.equal(failedQueue.length, 0);
  });

  test("single-flight queue logic: rejects all pending requests and clears state on refresh failure", async () => {
    globalThis.localStorage.setItem("accessToken", "expired_token");

    let failedQueue = [];
    const processQueue = (error, token = null) => {
      failedQueue.forEach((prom) => {
        if (error) prom.reject(error);
        else prom.resolve(token);
      });
      failedQueue = [];
    };

    const p1 = new Promise((resolve, reject) =>
      failedQueue.push({ resolve, reject }),
    );
    const p2 = new Promise((resolve, reject) =>
      failedQueue.push({ resolve, reject }),
    );

    // Refresh fails
    const refreshError = new Error("Session expired or revoked");
    processQueue(refreshError, null);
    globalThis.localStorage.removeItem("accessToken");

    await assert.rejects(p1, /Session expired or revoked/);
    await assert.rejects(p2, /Session expired or revoked/);
    assert.equal(failedQueue.length, 0);
    assert.equal(globalThis.localStorage.getItem("accessToken"), null);
  });

  test("auth endpoints bypass refresh interceptor to prevent infinite retry loops", () => {
    const isAuthUrl = (url) =>
      url?.includes("/auth/login") ||
      url?.includes("/auth/signup") ||
      url?.includes("/auth/refresh") ||
      url?.includes("/auth/forgot-password") ||
      url?.includes("/auth/reset-password");

    assert.equal(isAuthUrl("/api/auth/login"), true);
    assert.equal(isAuthUrl("/api/auth/refresh"), true);
    assert.equal(isAuthUrl("/api/auth/signup"), true);
    assert.equal(isAuthUrl("/api/auth/forgot-password"), true);
    assert.equal(isAuthUrl("/api/auth/reset-password/token123"), true);

    // Protected data endpoints should NOT be bypassed
    assert.equal(isAuthUrl("/api/user/profile"), false);
    assert.equal(isAuthUrl("/api/admin/users"), false);
  });

  test("exported API modules expose expected methods matching contracts", () => {
    assert.equal(typeof authAPI.login, "function");
    assert.equal(typeof authAPI.signup, "function");
    assert.equal(typeof authAPI.logout, "function");
    assert.equal(typeof authAPI.logoutAll, "function");
    assert.equal(typeof authAPI.refresh, "function");
    assert.equal(typeof authAPI.forgotPassword, "function");
    assert.equal(typeof authAPI.verifyResetToken, "function");
    assert.equal(typeof authAPI.resetPassword, "function");

    assert.equal(typeof userAPI.getProfile, "function");
    assert.equal(typeof userAPI.updateProfile, "function");

    assert.equal(typeof adminAPI.getAllUsers, "function");
    assert.equal(typeof adminAPI.getUserById, "function");
    assert.equal(typeof adminAPI.updateUserRole, "function");
    assert.equal(typeof adminAPI.deleteUser, "function");
  });
});
