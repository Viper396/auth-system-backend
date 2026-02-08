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
ACCESS_TOKEN_SECRET=your_access_token_secret_key_here
REFRESH_TOKEN_SECRET=your_refresh_token_secret_key_here
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
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
  "password": "password123",
  "name": "John Doe"
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
  "email": "newemail@example.com",
  "name": "Jane Doe"
}
```

## How Authentication Works

I implemented a dual-token system for better security:

- User registers and their password gets hashed with bcrypt
- On login, the system verifies credentials and issues two tokens
- Access token (15 min) is used for API requests
- Refresh token (7 days) is stored in httpOnly cookies
- When access token expires, refresh endpoint issues a new one
- Middleware validates tokens before granting access to protected routes

## Project Structure

```
server/
├── models/           # Database schemas
├── controllers/      # Business logic
├── routes/          # API endpoints
├── middleware/      # Auth verification
├── utils/           # Helper functions (DB, tokens)
├── server.js        # Express setup
└── app.js           # Entry point
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
- Validation middleware applied to signup, login, and profile update routes using express-validator
- Proper error messages that don't leak sensitive info

## Error Responses

The API uses standard HTTP status codes:

- `200`/`201` - Success
- `400` - Validation errors
- `401` - Authentication failed
- `404` - Resource not found
- `500` - Server error

## Example Usage

Here's how you'd use this from a frontend:

```javascript
// Login
const response = await fetch("http://localhost:5000/api/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
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
```

## What I Learned

Building this project helped me understand JWT authentication flows, token management strategies, and secure API design patterns. I focused on writing clean, maintainable code and following industry best practices.

## License

MIT License - feel free to use this code for your own projects.

For issues or questions, please create an issue in the repository.
