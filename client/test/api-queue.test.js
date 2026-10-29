import { test, describe } from "node:test";
import assert from "node:assert/strict";
import api from "../src/services/api.js";

describe("Frontend API Interceptor & Request Queuing", () => {
  test("api instance has baseURL and credentials enabled", () => {
    assert.ok(api.defaults.baseURL);
    assert.equal(api.defaults.withCredentials, true);
    assert.equal(api.defaults.headers["Content-Type"], "application/json");
  });

  test("single-flight queue logic: processQueue resolves all queued callers with new token", async () => {
    let queue = [];
    const processQueueMock = (error, token = null) => {
      queue.forEach((prom) => {
        if (error) prom.reject(error);
        else prom.resolve(token);
      });
      queue = [];
    };

    const p1 = new Promise((resolve, reject) => queue.push({ resolve, reject }));
    const p2 = new Promise((resolve, reject) => queue.push({ resolve, reject }));
    const p3 = new Promise((resolve, reject) => queue.push({ resolve, reject }));

    assert.equal(queue.length, 3);

    processQueueMock(null, "new_mock_access_token_123");

    const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
    assert.equal(r1, "new_mock_access_token_123");
    assert.equal(r2, "new_mock_access_token_123");
    assert.equal(r3, "new_mock_access_token_123");
    assert.equal(queue.length, 0);
  });

  test("single-flight queue logic: processQueue rejects all queued callers on refresh failure", async () => {
    let queue = [];
    const processQueueMock = (error, token = null) => {
      queue.forEach((prom) => {
        if (error) prom.reject(error);
        else prom.resolve(token);
      });
      queue = [];
    };

    const p1 = new Promise((resolve, reject) => queue.push({ resolve, reject }));
    const p2 = new Promise((resolve, reject) => queue.push({ resolve, reject }));

    processQueueMock(new Error("Refresh token expired"), null);

    await assert.rejects(p1, /Refresh token expired/);
    await assert.rejects(p2, /Refresh token expired/);
    assert.equal(queue.length, 0);
  });
});
