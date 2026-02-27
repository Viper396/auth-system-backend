# Auth System Backend

A secure authentication system I built using Node.js, Express, and MongoDB. It handles everything from user registration to login and profile management using JWT tokens.

## What It Does

This backend handles the complete authentication flow you'd expect in a modern web app:

- User registration with email and password
- Secure login with JWT token generation
- Token refresh mechanism to keep users logged in
- Logout functionality that properly cleans up tokens
- Protected routes that require authentication
- User profile viewing and updating
- Role-based access control (admin/user permissions)
- Password reset flow with secure token generation
- Account lockout after failed login attempts
- Bcrypt password hashing for security
- Input validation to prevent bad data

## Tech Stack

I chose these technologies for their reliability and industry adoption:

- **Node.js & Express.js** - For the server and API
- **MongoDB & Mongoose** - Database and object modeling
- **JWT** - Token-based authentication
- **bcryptjs** - Secure password hashing
- **Helmet** - Security headers for Express
- **express-rate-limit** - Rate limiting to prevent brute force attacks
- **express-validator** - Input validation and sanitization
- **Morgan** - HTTP request logging
- **Nodemailer** - Email sending for password reset

## Getting Started

### What You'll Need

- Node.js (v14+)
- npm or yarn
- MongoDB Atlas account (or local MongoDB)

### Setup Instructions

Clone the repo and install dependencies:

```bash
git clone <repository-url>
cd auth-system-backend/server
npm install
```

Create a `.env` file in the `server/` directory with these variables:

```env
PORT=5000
NODE_ENV=development
MONGO_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/<dbname>
JWT_ACCESS_SECRET=your_access_token_secret_key_here
JWT_REFRESH_SECRET=your_refresh_token_secret_key_here
FRONTEND_URL=http://localhost:3000
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=noreply@yourapp.com
APP_NAME=Your App Name
```

Start the development server:

```bash
npm run dev
```

The server runs on `http://localhost:5000`

## API Reference

### Authentication Endpoints

#### Register a new user

```
POST /api/auth/signup

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Login

```
POST /api/auth/login

{
  "email": "user@example.com",
  "password": "password123"
}
```

Returns access token (15min expiry) and refresh token (7 days expiry).

#### Refresh token

```
POST /api/auth/refresh
```

Automatically reads refresh token from cookies and issues a new access token.

#### Logout

```
POST /api/auth/logout
```

Invalidates the refresh token and logs out the user.

#### Request password reset

```
POST /api/auth/forgot-password

{
  "email": "user@example.com"
}
```

Sends a password reset email with a secure token (expires in 1 hour).

#### Verify reset token

```
GET /api/auth/reset-password/:token
```

Checks if a password reset token is valid before showing reset form.

#### Reset password

```
POST /api/auth/reset-password/:token

{
  "password": "newpassword123"
}
```

Sets a new password using the valid reset token. Token is invalidated after use.

### User Endpoints

These routes require authentication via `Authorization: Bearer <accessToken>` header.

#### Get profile

```
GET /api/user/profile
```

#### Update profile

```
PUT /api/user/profile

{
  "email": "newemail@example.com"
}
```

### Admin Endpoints

These routes require both authentication and admin role.

#### Get all users

```
GET /api/admin/users
```

#### Get user by ID

```
GET /api/admin/users/:id
```

#### Update user role

```
PUT /api/admin/users/:id/role

{
  "role": "admin"
}
```

#### Delete user

```
DELETE /api/admin/users/:id
```

## How Authentication Works

I implemented a dual-token system for better security:

- User registers and their password gets hashed with bcrypt
- On login, the system verifies credentials and issues two tokens
- Access token (15 min) is used for API requests
- Refresh token (7 days) is stored in httpOnly cookies
- When access token expires, refresh endpoint issues a new one
- Middleware validates tokens before granting access to protected routes
- Role-based middleware checks user permissions for admin routes

## Password Reset Flow

The password reset system uses secure, time-limited tokens:

- User requests password reset via email
- System generates a cryptographically secure random token
- Token is hashed using SHA-256 before storing in database
- Email is sent with reset link containing the unhashed token
- Token expires after 1 hour for security
- User clicks link and submits new password
- Token is validated, password is updated, and token is invalidated
- All existing sessions are cleared (user must login again)

## Project Structure

```
server/
├── models/           # Database schemas
├── controllers/      # Business logic
│   ├── auth.controller.js
│   ├── user.controller.js
│   └── admin.controller.js
├── routes/          # API endpoints
│   ├── auth.routes.js
│   ├── user.routes.js
│   └── admin.routes.js
├── middleware/      # Auth verification and rate limiting
│   ├── auth.middleware.js
│   ├── role.middleware.js
│   ├── rateLimit.middleware.js
│   └── validation.middleware.js
├── utils/           # Helper functions
│   ├── db.js
│   ├── token.js
│   └── email.js
├── app.js           # Express setup
└── server.js        # Entry point
```

## Security Features

I've implemented several security best practices:

- Passwords hashed with 10 salt rounds (never stored in plain text)
- Short-lived access tokens minimize exposure
- Refresh token rotation prevents token reuse
- Environment variables keep secrets out of code
- Passwords excluded from all API responses
- Input validation on every endpoint using express-validator
- Comprehensive input sanitization to prevent injection attacks
- Email validation and normalization
- Password strength requirements (minimum 6 characters with at least one number)
- Rate limiting to prevent brute force attacks:
  - Authentication endpoints: 5 attempts per 15 minutes
  - General API: 100 requests per 15 minutes
  - Password reset: 3 attempts per hour
- Security headers implemented with Helmet
- HTTP request logging with Morgan
- Account lockout after repeated failed login attempts (locks for 2 hours after 5 failed attempts)
- Validation middleware applied to signup, login, password reset, and profile update routes
- Password reset tokens hashed before storage using SHA-256
- Reset tokens expire after 1 hour
- One-time use reset tokens (invalidated after password change)
- No user enumeration (same response for existing and non-existing emails)
- All sessions cleared on password reset
- Admin self-protection (cannot delete or demote themselves)
- Proper error messages that don't leak sensitive info

## Error Responses

The API uses standard HTTP status codes:

- `200`/`201` - Success
- `400` - Validation errors
- `401` - Authentication failed
- `403` - Forbidden (insufficient permissions)
- `404` - Resource not found
- `423` - Locked (account locked due to failed attempts)
- `500` - Server error

## Example Usage

Here's how you'd use this from a frontend:

```javascript
// Login
const response = await fetch("http://localhost:5000/api/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include", // Important for cookies
  body: JSON.stringify({
    email: "user@example.com",
    password: "pass123",
  }),
});
const { accessToken } = await response.json();
localStorage.setItem("accessToken", accessToken);

// Make authenticated request
const profile = await fetch("http://localhost:5000/api/user/profile", {
  headers: {
    Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
  },
});

// Password reset flow
// Step 1: Request reset
await fetch("http://localhost:5000/api/auth/forgot-password", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "user@example.com" }),
});

// Step 2: User receives email with token and clicks link
// Step 3: Submit new password
await fetch(`http://localhost:5000/api/auth/reset-password/${token}`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ password: "newpass123" }),
});
```

## What I Learned

Building this project helped me understand JWT authentication flows, token management strategies, secure API design patterns, role-based access control, and production-grade security implementations. I focused on writing clean, maintainable code and following industry best practices for authentication systems.

## License

MIT License - feel free to use this code for your own projects.

For issues or questions, please create an issue in the repository.
