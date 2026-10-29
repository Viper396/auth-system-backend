const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const app = require("../app");
const config = require("../config/env");
const {
  getRefreshTokenCookieOptions,
  getClearRefreshTokenCookieOptions,
  REFRESH_TOKEN_COOKIE_NAME,
} = require("../utils/cookie");

describe("CORS & Origin Hardening", () => {
  let server;
  let baseUrl;

  before(async () => {
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  test("allows preflight requests from trusted frontend origin with credentials", async () => {
    const res = await fetch(`${baseUrl}/health`, {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "GET",
      },
    });

    assert.equal(res.status, 204);
    assert.equal(res.headers.get("access-control-allow-origin"), "http://localhost:5173");
    assert.equal(res.headers.get("access-control-allow-credentials"), "true");
    assert.match(res.headers.get("access-control-allow-methods"), /GET/);
    assert.match(res.headers.get("access-control-allow-methods"), /POST/);
  });

  test("allows actual requests from trusted origin", async () => {
    const res = await fetch(`${baseUrl}/health`, {
      headers: {
        Origin: "http://localhost:5173",
      },
    });

    assert.equal(res.status, 200);
    assert.equal(res.headers.get("access-control-allow-origin"), "http://localhost:5173");
    assert.equal(res.headers.get("access-control-allow-credentials"), "true");
  });

  test("rejects CORS headers for untrusted origin", async () => {
    const res = await fetch(`${baseUrl}/health`, {
      headers: {
        Origin: "https://evil-untrusted-site.com",
      },
    });

    assert.equal(res.status, 200);
    // Origin is not allowed, so access-control-allow-origin header MUST NOT be present
    assert.equal(res.headers.get("access-control-allow-origin"), null);
  });

  test("allows non-browser requests with no origin header", async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, "OK");
  });

  test("config parses multiple comma-separated trusted origins cleanly", () => {
    const parsed = config.validateConfig({
      NODE_ENV: "development",
      PORT: "5000",
      MONGO_URI: "mongodb://localhost:27017/test_db",
      JWT_ACCESS_SECRET: "development_access_token_secret_32_chars_long",
      JWT_REFRESH_SECRET: "development_refresh_token_secret_32_chars_long",
      FRONTEND_URL: "http://localhost:5173, https://admin.example.com/",
    });

    assert.deepEqual(parsed.TRUSTED_ORIGINS, [
      "http://localhost:5173",
      "https://admin.example.com",
    ]);
  });
});

describe("Cookie Attributes & Deployment Topology", () => {
  test("generates secure development cookie options scoped to /api/auth", () => {
    const devConfig = {
      NODE_ENV: "development",
      COOKIE_SAME_SITE: "lax",
      COOKIE_SECURE: false,
    };
    const options = getRefreshTokenCookieOptions(devConfig);

    assert.equal(options.httpOnly, true);
    assert.equal(options.secure, false);
    assert.equal(options.sameSite, "lax");
    assert.equal(options.path, "/api/auth");
    assert.equal(options.maxAge, 7 * 24 * 60 * 60 * 1000);
    assert.equal(options.domain, undefined);
  });

  test("enforces Secure flag in production topology", () => {
    const prodConfig = {
      NODE_ENV: "production",
      COOKIE_SAME_SITE: "lax",
      COOKIE_SECURE: true,
    };
    const options = getRefreshTokenCookieOptions(prodConfig);

    assert.equal(options.httpOnly, true);
    assert.equal(options.secure, true);
    assert.equal(options.sameSite, "lax");
    assert.equal(options.path, "/api/auth");
  });

  test("automatically requires Secure flag when SameSite=none for cross-site deployments", () => {
    const crossSiteConfig = {
      NODE_ENV: "development",
      COOKIE_SAME_SITE: "none",
      COOKIE_SECURE: false,
    };
    const options = getRefreshTokenCookieOptions(crossSiteConfig);

    assert.equal(options.sameSite, "none");
    assert.equal(options.secure, true); // Required by browser specification for SameSite=None
  });

  test("attaches custom domain attribute when configured for subdomain sharing", () => {
    const domainConfig = {
      NODE_ENV: "production",
      COOKIE_SAME_SITE: "lax",
      COOKIE_SECURE: true,
      COOKIE_DOMAIN: ".example.com",
    };
    const options = getRefreshTokenCookieOptions(domainConfig);

    assert.equal(options.domain, ".example.com");
  });

  test("clear cookie options exactly mirror path, domain, sameSite, and secure attributes", () => {
    const customConfig = {
      NODE_ENV: "production",
      COOKIE_SAME_SITE: "strict",
      COOKIE_SECURE: true,
      COOKIE_DOMAIN: ".example.com",
    };
    const setOptions = getRefreshTokenCookieOptions(customConfig);
    const clearOptions = getClearRefreshTokenCookieOptions(customConfig);

    assert.equal(clearOptions.path, setOptions.path);
    assert.equal(clearOptions.domain, setOptions.domain);
    assert.equal(clearOptions.sameSite, setOptions.sameSite);
    assert.equal(clearOptions.secure, setOptions.secure);
    assert.equal(clearOptions.httpOnly, setOptions.httpOnly);
  });
});
