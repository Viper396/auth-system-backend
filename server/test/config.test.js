const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { validateConfig } = require("../config/env");

describe("Environment Configuration & Validation", () => {
  const baseValidEnv = {
    NODE_ENV: "development",
    PORT: "5000",
    MONGO_URI: "mongodb://localhost:27017/test_db",
    JWT_ACCESS_SECRET: "development_access_token_secret_32_chars_long",
    JWT_REFRESH_SECRET: "development_refresh_token_secret_32_chars_long",
    FRONTEND_URL: "http://localhost:5173",
  };

  test("loads successfully with valid development configuration", () => {
    const config = validateConfig({ ...baseValidEnv });
    assert.equal(config.NODE_ENV, "development");
    assert.equal(config.PORT, 5000);
    assert.equal(config.MONGO_URI, baseValidEnv.MONGO_URI);
    assert.equal(config.JWT_ACCESS_SECRET, baseValidEnv.JWT_ACCESS_SECRET);
    assert.equal(config.JWT_REFRESH_SECRET, baseValidEnv.JWT_REFRESH_SECRET);
    assert.equal(config.FRONTEND_URL, "http://localhost:5173");
  });

  test("loads successfully with valid production configuration", () => {
    const prodEnv = {
      ...baseValidEnv,
      NODE_ENV: "production",
      JWT_ACCESS_SECRET: "strong_production_access_secret_greater_than_32_chars!",
      JWT_REFRESH_SECRET: "strong_production_refresh_secret_greater_than_32_chars!",
      FRONTEND_URL: "https://auth.example.com",
    };
    const config = validateConfig(prodEnv);
    assert.equal(config.NODE_ENV, "production");
    assert.equal(config.FRONTEND_URL, "https://auth.example.com");
  });

  test("fails clearly when JWT_ACCESS_SECRET is missing", () => {
    const invalidEnv = { ...baseValidEnv, JWT_ACCESS_SECRET: "" };
    delete invalidEnv.ACCESS_TOKEN_SECRET;

    assert.throws(
      () => validateConfig(invalidEnv),
      (err) => {
        assert.match(err.message, /JWT_ACCESS_SECRET is required/);
        return true;
      },
    );
  });

  test("fails clearly when JWT_REFRESH_SECRET is missing", () => {
    const invalidEnv = { ...baseValidEnv, JWT_REFRESH_SECRET: "" };
    delete invalidEnv.REFRESH_TOKEN_SECRET;

    assert.throws(
      () => validateConfig(invalidEnv),
      (err) => {
        assert.match(err.message, /JWT_REFRESH_SECRET is required/);
        return true;
      },
    );
  });

  test("fails clearly when MONGO_URI is missing in development and production", () => {
    const noMongoDev = { ...baseValidEnv, MONGO_URI: "" };
    assert.throws(
      () => validateConfig(noMongoDev),
      (err) => {
        assert.match(err.message, /MONGO_URI is required/);
        return true;
      },
    );

    const noMongoProd = {
      ...baseValidEnv,
      NODE_ENV: "production",
      MONGO_URI: "",
      JWT_ACCESS_SECRET: "strong_production_access_secret_greater_than_32_chars!",
      JWT_REFRESH_SECRET: "strong_production_refresh_secret_greater_than_32_chars!",
    };
    assert.throws(
      () => validateConfig(noMongoProd),
      (err) => {
        assert.match(err.message, /MONGO_URI is required/);
        return true;
      },
    );
  });

  test("accepts legacy ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET as fallback", () => {
    const legacyEnv = {
      NODE_ENV: "development",
      PORT: "5000",
      MONGO_URI: "mongodb://localhost:27017/test_db",
      ACCESS_TOKEN_SECRET: "legacy_access_secret_key_value_here",
      REFRESH_TOKEN_SECRET: "legacy_refresh_secret_key_value_here",
    };
    const config = validateConfig(legacyEnv);
    assert.equal(config.JWT_ACCESS_SECRET, "legacy_access_secret_key_value_here");
    assert.equal(config.JWT_REFRESH_SECRET, "legacy_refresh_secret_key_value_here");
  });

  test("rejects known insecure placeholder secrets in production", () => {
    const insecureProd = {
      ...baseValidEnv,
      NODE_ENV: "production",
      JWT_ACCESS_SECRET: "your_access_token_secret_key_here",
      JWT_REFRESH_SECRET: "your_refresh_token_secret_key_here",
    };
    assert.throws(
      () => validateConfig(insecureProd),
      (err) => {
        assert.match(err.message, /Insecure JWT_ACCESS_SECRET/);
        return true;
      },
    );
  });

  test("rejects short secrets (< 32 chars) in production", () => {
    const shortSecretProd = {
      ...baseValidEnv,
      NODE_ENV: "production",
      JWT_ACCESS_SECRET: "too_short_secret",
      JWT_REFRESH_SECRET: "also_too_short",
    };
    assert.throws(
      () => validateConfig(shortSecretProd),
      (err) => {
        assert.match(err.message, /Must be at least 32 characters in production/);
        return true;
      },
    );
  });

  test("rejects invalid PORT numbers", () => {
    assert.throws(
      () => validateConfig({ ...baseValidEnv, PORT: "not-a-number" }),
      (err) => {
        assert.match(err.message, /Invalid PORT/);
        return true;
      },
    );

    assert.throws(
      () => validateConfig({ ...baseValidEnv, PORT: "99999" }),
      (err) => {
        assert.match(err.message, /Invalid PORT/);
        return true;
      },
    );
  });

  test("rejects invalid NODE_ENV value", () => {
    assert.throws(
      () => validateConfig({ ...baseValidEnv, NODE_ENV: "staging_invalid" }),
      (err) => {
        assert.match(err.message, /Invalid NODE_ENV/);
        return true;
      },
    );
  });

  test("never prints actual secret values in error messages", () => {
    const sensitiveSecret = "my_super_secret_value_that_must_never_leak_in_logs";
    const invalidProd = {
      ...baseValidEnv,
      NODE_ENV: "production",
      JWT_ACCESS_SECRET: sensitiveSecret, // short or insecure
      PORT: "invalid_port",
    };

    try {
      validateConfig(invalidProd);
      assert.fail("Should have thrown");
    } catch (err) {
      assert.ok(!err.message.includes(sensitiveSecret), "Secret leaked in error message!");
    }
  });

  test("rejects identical JWT_ACCESS_SECRET and JWT_REFRESH_SECRET", () => {
    const identicalSecretsEnv = {
      ...baseValidEnv,
      JWT_ACCESS_SECRET: "same_secret_key_used_for_both_access_and_refresh!",
      JWT_REFRESH_SECRET: "same_secret_key_used_for_both_access_and_refresh!",
    };

    assert.throws(
      () => validateConfig(identicalSecretsEnv),
      (err) => {
        assert.match(err.message, /must be distinct secrets/);
        return true;
      },
    );
  });

  test("validates JWT_ACCESS_EXPIRES_IN within safe bounds (1m to 1h)", () => {
    // Valid values
    const valid1m = validateConfig({ ...baseValidEnv, JWT_ACCESS_EXPIRES_IN: "1m" });
    assert.equal(valid1m.JWT_ACCESS_EXPIRES_IN_SECONDS, 60);

    const valid30m = validateConfig({ ...baseValidEnv, JWT_ACCESS_EXPIRES_IN: "30m" });
    assert.equal(valid30m.JWT_ACCESS_EXPIRES_IN_SECONDS, 1800);

    const valid1h = validateConfig({ ...baseValidEnv, JWT_ACCESS_EXPIRES_IN: "1h" });
    assert.equal(valid1h.JWT_ACCESS_EXPIRES_IN_SECONDS, 3600);

    // Too short (< 1m)
    assert.throws(
      () => validateConfig({ ...baseValidEnv, JWT_ACCESS_EXPIRES_IN: "30s" }),
      (err) => {
        assert.match(err.message, /Invalid JWT_ACCESS_EXPIRES_IN/);
        return true;
      },
    );

    // Too long (> 1h)
    assert.throws(
      () => validateConfig({ ...baseValidEnv, JWT_ACCESS_EXPIRES_IN: "2h" }),
      (err) => {
        assert.match(err.message, /Invalid JWT_ACCESS_EXPIRES_IN/);
        return true;
      },
    );

    // Invalid format
    assert.throws(
      () => validateConfig({ ...baseValidEnv, JWT_ACCESS_EXPIRES_IN: "unlimited" }),
      (err) => {
        assert.match(err.message, /Invalid JWT_ACCESS_EXPIRES_IN/);
        return true;
      },
    );
  });

  test("validates JWT_REFRESH_EXPIRES_IN within safe bounds (1h to 30d)", () => {
    // Valid values
    const valid1h = validateConfig({ ...baseValidEnv, JWT_REFRESH_EXPIRES_IN: "1h" });
    assert.equal(valid1h.JWT_REFRESH_EXPIRES_IN_SECONDS, 3600);

    const valid7d = validateConfig({ ...baseValidEnv, JWT_REFRESH_EXPIRES_IN: "7d" });
    assert.equal(valid7d.JWT_REFRESH_EXPIRES_IN_SECONDS, 604800);

    const valid30d = validateConfig({ ...baseValidEnv, JWT_REFRESH_EXPIRES_IN: "30d" });
    assert.equal(valid30d.JWT_REFRESH_EXPIRES_IN_SECONDS, 2592000);

    // Too short (< 1h)
    assert.throws(
      () => validateConfig({ ...baseValidEnv, JWT_REFRESH_EXPIRES_IN: "30m" }),
      (err) => {
        assert.match(err.message, /Invalid JWT_REFRESH_EXPIRES_IN/);
        return true;
      },
    );

    // Too long (> 30d)
    assert.throws(
      () => validateConfig({ ...baseValidEnv, JWT_REFRESH_EXPIRES_IN: "60d" }),
      (err) => {
        assert.match(err.message, /Invalid JWT_REFRESH_EXPIRES_IN/);
        return true;
      },
    );
  });

  test("parses optional JWT_ISSUER and JWT_AUDIENCE claims when configured", () => {
    const claimsEnv = {
      ...baseValidEnv,
      JWT_ISSUER: "https://auth.company.com",
      JWT_AUDIENCE: "auth-api",
    };
    const config = validateConfig(claimsEnv);
    assert.equal(config.JWT_ISSUER, "https://auth.company.com");
    assert.equal(config.JWT_AUDIENCE, "auth-api");
  });
});
