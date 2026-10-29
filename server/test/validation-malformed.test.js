const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const {
  signupValidation,
  loginValidation,
  updateProfileValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  validate,
} = require("../middleware/validation.middleware");

// Helper to run express-validator middleware chains on a mock req
const runValidations = async (validations, req) => {
  for (const validation of validations) {
    await validation.run(req);
  }
};

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

describe("Input Validation Middleware & Malformed Requests", () => {
  test("signupValidation accepts valid email and password with number", async () => {
    const req = {
      body: {
        email: "valid.user@example.com",
        password: "securePassword1",
      },
    };
    const res = createMockRes();
    let nextCalled = false;

    await runValidations(signupValidation, req);
    validate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(res.statusCode, 200);
  });

  test("signupValidation rejects invalid email format", async () => {
    const req = {
      body: {
        email: "not-an-email",
        password: "password123",
      },
    };
    const res = createMockRes();
    let nextCalled = false;

    await runValidations(signupValidation, req);
    validate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 400);
    assert.equal(res.jsonData.message, "Validation failed");
    const emailErr = res.jsonData.errors.find((e) => e.field === "email");
    assert.ok(emailErr);
    assert.match(emailErr.message, /Must be a valid email/);
  });

  test("signupValidation rejects password shorter than 6 characters", async () => {
    const req = {
      body: {
        email: "test@example.com",
        password: "123",
      },
    };
    const res = createMockRes();
    let nextCalled = false;

    await runValidations(signupValidation, req);
    validate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 400);
    const passErr = res.jsonData.errors.find((e) => e.field === "password");
    assert.ok(passErr);
    assert.match(passErr.message, /at least 6 characters/);
  });

  test("signupValidation rejects password without numbers", async () => {
    const req = {
      body: {
        email: "test@example.com",
        password: "allletterslongpassword",
      },
    };
    const res = createMockRes();
    let nextCalled = false;

    await runValidations(signupValidation, req);
    validate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 400);
    const passErr = res.jsonData.errors.find((e) =>
      e.message.includes("at least one number"),
    );
    assert.ok(passErr);
  });

  test("loginValidation rejects empty password", async () => {
    const req = {
      body: {
        email: "test@example.com",
        password: "",
      },
    };
    const res = createMockRes();
    let nextCalled = false;

    await runValidations(loginValidation, req);
    validate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 400);
    const passErr = res.jsonData.errors.find((e) => e.field === "password");
    assert.ok(passErr);
    assert.match(passErr.message, /Password is required/);
  });

  test("updateProfileValidation accepts valid email and ignores empty optional email", async () => {
    const req1 = { body: { email: "newemail@example.com" } };
    const res1 = createMockRes();
    let next1 = false;
    await runValidations(updateProfileValidation, req1);
    validate(req1, res1, () => {
      next1 = true;
    });
    assert.equal(next1, true);

    const req2 = { body: {} };
    const res2 = createMockRes();
    let next2 = false;
    await runValidations(updateProfileValidation, req2);
    validate(req2, res2, () => {
      next2 = true;
    });
    assert.equal(next2, true);
  });

  test("forgotPasswordValidation rejects invalid email", async () => {
    const req = { body: { email: "plainaddress" } };
    const res = createMockRes();
    let nextCalled = false;

    await runValidations(forgotPasswordValidation, req);
    validate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 400);
    assert.match(res.jsonData.errors[0].message, /Must be a valid email/);
  });

  test("resetPasswordValidation rejects short or numberless password", async () => {
    const req = { body: { password: "short" } };
    const res = createMockRes();
    let nextCalled = false;

    await runValidations(resetPasswordValidation, req);
    validate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 400);
    assert.ok(res.jsonData.errors.length >= 1);
  });

  test("malformed requests: null or non-object body handles safely without crashing", async () => {
    const req = { body: null };
    const res = createMockRes();
    let nextCalled = false;

    await runValidations(loginValidation, req);
    validate(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 400);
    assert.equal(res.jsonData.message, "Validation failed");
  });
});
