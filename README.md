# Auth System Backend

A secure authentication system built with Node.js, Express, and MongoDB. This backend handles user registration, login, and profile management using JWT tokens.

## 🚀 Features

- **User Registration** - Sign up with email and password
- **User Login** - Authenticate users and issue JWT tokens
- **Token Refresh** - Refresh access tokens with token rotation
- **User Logout** - Logout users and invalidate refresh tokens
- **JWT Authentication** - Secure API endpoints with access and refresh tokens
- **User Profile** - Get and update user profile information
- **Password Hashing** - Passwords encrypted with bcrypt
- **Token Management** - Short-lived access tokens and long-lived refresh tokens
- **Input Validation** - Comprehensive validation for all inputs
- **Error Handling** - Detailed error messages for debugging

## 📋 Tech Stack

- **Node.js** - JavaScript runtime
- **Express.js** - Web framework
- **MongoDB** - NoSQL database
- **Mongoose** - MongoDB ODM
- **JWT** - JSON Web Tokens for authentication
- **bcryptjs** - Password hashing

## 📦 Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- MongoDB account (MongoDB Atlas recommended)

## ⚙️ Installation

1. **Clone the repository**

```bash
git clone <repository-url>
cd auth-system-backend-claude
```

2. **Install dependencies**

```bash
cd server
npm install
```

3. **Setup environment variables**
   Create a `.env` file in the `server/` directory:

```env
PORT=5000
NODE_ENV=development
MONGO_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/<dbname>
ACCESS_TOKEN_SECRET=your_access_token_secret_key_here
REFRESH_TOKEN_SECRET=your_refresh_token_secret_key_here
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
```

4. **Start the server**

```bash
npm run dev
```

The server will start on `http://localhost:5000`

## 📚 API Endpoints

### Authentication Routes

#### Register User

```
POST /api/auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "name": "John Doe"
}

Response: 201 Created
{
  "message": "User created successfully",
  "user": {
    "id": "...",
    "email": "user@example.com",
    "role": "user"
  }
}
```

#### Login User

```
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}

Response: 200 OK
{
  "message": "Login successful",
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "...",
    "email": "user@example.com",
    "role": "user"
  }
}
```

#### Refresh Access Token

```
POST /api/auth/refresh
Cookie: refreshToken=<refreshToken>

Response: 200 OK
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "...",
    "email": "user@example.com",
    "role": "user"
  }
}
```

#### Logout User

```
POST /api/auth/logout
Cookie: refreshToken=<refreshToken>

Response: 200 OK
{
  "message": "Logged out successfully"
}
```

### User Routes (Protected)

All user routes require the `Authorization: Bearer <accessToken>` header.

#### Get User Profile

```
GET /api/user/profile
Authorization: Bearer <accessToken>

Response: 200 OK
{
  "user": {
    "id": "...",
    "email": "user@example.com",
    "role": "user",
    "createdAt": "2026-01-23T10:00:00Z"
  }
}
```

#### Update User Profile

```
PUT /api/user/profile
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "email": "newemail@example.com",
  "name": "Jane Doe"
}

Response: 200 OK
{
  "message": "Profile updated successfully",
  "user": { ... }
}
```

## 🔒 Authentication Flow

1. User registers with email and password
2. Password is hashed using bcrypt before storing in database
3. User logs in with email and password
4. System verifies credentials and issues two tokens:
   - **Access Token**: Valid for 15 minutes (used for API requests)
   - **Refresh Token**: Valid for 7 days (used to get new access token)
5. Client includes access token in `Authorization: Bearer <token>` header for protected routes
6. Middleware validates token before allowing access to protected routes

## 📁 Project Structure

```
server/
├── models/
│   └── user.model.js          # User schema and validation
├── controllers/
│   ├── auth.controller.js     # Authentication logic
│   └── user.controller.js     # User profile logic
├── routes/
│   ├── auth.routes.js         # Auth endpoints
│   └── user.routes.js         # User endpoints
├── middleware/
│   └── auth.middleware.js     # JWT verification middleware
├── utils/
│   ├── db.js                  # Database connection
│   └── token.js               # JWT token generation and verification
├── server.js                  # Express app setup
├── app.js                     # Application entry point
├── .env                       # Environment variables (not in git)
└── package.json               # Dependencies
```

## 🛡️ Security Best Practices

- Passwords are hashed with bcrypt (10 salt rounds)
- AcceToken Management

### Refresh Token Flow

When access token expires, use the refresh token to get a new access token:

```
POST /api/auth/refresh
Cookie: refreshToken=<refreshToken>

Response: 200 OK
{
  "accessToken": "new_token_...",
  "user": {
    "id": "...",
    "email": "user@example.com",
    "role": "user"
  }
}
```

**Token Rotation**: A new refresh token is issued with each refresh request, and the old token is invalidated for security.

### Logout Flow

When logging out, the refresh token is cleared and invalidated:

```
POST /api/auth/logout
Cookie: refreshToken=<refreshToken>

Response: 200 OK
{
  "message": "Logged outrver port                   | `5000`              |
| `NODE_ENV`             | Environment mode              | `development`       |
| `MONGO_URI`            | MongoDB connection string     | `mongodb+srv://...` |
| `ACCESS_TOKEN_SECRET`  | Secret key for access tokens  | Random string       |
| `REFRESH_TOKEN_SECRET` | Secret key for refresh tokens | Random string       |
| `ACCESS_TOKEN_EXPIRY`  | Access token expiration time  | `15m`               |
| `REFRESH_TOKEN_EXPIRY` | Refresh token expiration time | `7d`                |

## 🚨 Error Handling

The API returns appropriate HTTP status codes:

- `200` - Success
- `201` - Created
- `400` - Bad Request (validation error)
- `401` - Unauthorized (invalid credentials or token)
- `500` - Server Error

## 🔄 Refresh Token Flow

When access token expires:

```

POST /api/auth/refresh
Authorization: Bearer <refreshToken>

Response: 200 OK
{
"accessToken": "new*token*...",
"message": "Token refreshed successfully"
}

````

## 💡 Usage Example (Frontend)

```javascript
// Login
const response = await fetch("http://localhost:5000/api/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "user@example.com", password: "pass123" }),
});
const data = await response.json();
localStorage.setItem("accessToken", data.accessToken);

// Use token in protected request
const profileResponse = await fetch("http://localhost:5000/api/user/profile", {
  method: "GET",
  headers: { Authorization: `Bearer ${localStorage.getItem("accessToken")}` },
});
const profile = await profileResponse.json();
````

## 📄 License

This project is open source and available under the MIT License.

## 📞 Support

For issues or questions, please create an issue in the repository.
