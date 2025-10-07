# 🛡️ SecureCloud Project - Hybrid RBAC + ABAC System

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/express-%5E4.18.0-blue.svg)](https://expressjs.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green.svg)](https://mongodb.com/)
[![JWT](https://img.shields.io/badge/JWT-Authentication-orange.svg)](https://jwt.io/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A comprehensive **Microsoft Azure-inspired** access management system implementing both **Role-Based Access Control (RBAC)** and **Attribute-Based Access Control (ABAC)** for fine-grained security and authorization.

## 📚 Table of Contents

- [🎯 Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [⚡ Quick Start](#-quick-start)
- [🔧 Installation](#-installation)
- [📖 API Documentation](#-api-documentation)
- [🔐 Authentication & Authorization](#-authentication--authorization)
- [🧪 Testing](#-testing)
- [📁 Project Structure](#-project-structure)
- [🌱 Database Seeding](#-database-seeding)
- [🔄 Environment Variables](#-environment-variables)
- [🛠️ Development](#️-development)
- [📊 Monitoring & Logging](#-monitoring--logging)
- [🤝 Contributing](#-contributing)

## 🎯 Features

### 🔒 **Hybrid Security Model**
- **RBAC (Role-Based Access Control)**: Coarse-grained permissions based on user roles
- **ABAC (Attribute-Based Access Control)**: Fine-grained access control using dynamic attributes
- **Multi-Role Policies**: Single policy can apply to multiple roles
- **Dynamic Conditions**: Location, department, time-based, and resource sensitivity controls

### 🚀 **Core Capabilities**
- ✅ **JWT Authentication** with access & refresh tokens
- ✅ **Password Security** with bcrypt hashing (10 rounds)
- ✅ **MongoDB Integration** with Mongoose ODM
- ✅ **Audit Logging** for all access attempts
- ✅ **RESTful API** with comprehensive endpoints
- ✅ **Input Validation** and error handling
- ✅ **Environment-based Configuration**

### 👥 **User Management**
- Multi-tier role system (SuperAdmin → Admin → Editor → Viewer)
- Department and location-based access controls
- Secure user registration and profile management
- Session management with refresh token rotation

## 🏗️ Architecture

### **Security Flow**
```
📥 Request → 🔐 Auth Middleware → 👤 RBAC Middleware → 🎯 ABAC Middleware → 🎮 Controller
```

### **Components Overview**

```mermaid
graph TB
    A[Client Request] --> B[Auth Middleware]
    B --> C[RBAC Middleware]
    C --> D[ABAC Middleware]
    D --> E[Controller]
    E --> F[Database]
    
    B --> G[JWT Verification]
    C --> H[Role Permission Check]
    D --> I[Policy Condition Evaluation]
    
    subgraph "Database Models"
        F --> J[Users]
        F --> K[Roles]
        F --> L[Policies]
        F --> M[Resources]
        F --> N[AuditLogs]
    end
```

### **Database Schema**

#### **User Model**
```javascript
{
  username: String (unique),
  email: String (unique),
  password: String (hashed),
  role: ObjectId (ref: Role),
  department: String,
  location: String,
  isActive: Boolean,
  refreshToken: String
}
```

#### **Role Model**
```javascript
{
  name: String (unique),
  description: String,
  permissions: [{ action: String, resource: String }],
  isSystemRole: Boolean
}
```

#### **Policy Model**
```javascript
{
  role: [ObjectId] (ref: Role, supports multiple roles),
  action: String, // "create:user", "edit:project"
  conditions: Object, // { department: "IT", location: "India" }
  effect: "allow" | "deny",
  isActive: Boolean,
  createdBy: ObjectId
}
```

## ⚡ Quick Start

### **Prerequisites**
- Node.js 18+ 
- MongoDB Atlas account
- Git

### **1-Minute Setup**
```bash
# Clone repository
git clone https://github.com/Siddharth-Dev2310/RBAC-ABAC.git
cd secureCloud_Project

# Install dependencies
npm install

# Setup environment
cp .env.example .env
# Edit .env with your MongoDB URI and JWT secrets

# Seed database with default data
npm run seed:all

# Start development server
npm run dev
```

**🎉 Server running at:** `http://localhost:3000`

## 🔧 Installation

### **Detailed Setup**

1. **Clone & Install**
   ```bash
   git clone https://github.com/Siddharth-Dev2310/RBAC-ABAC.git
   cd secureCloud_Project
   npm install
   ```

2. **Environment Configuration**
   ```bash
   # Create .env file
   touch .env
   ```
   
   Add these variables:
   ```env
   # Server Configuration
   PORT=3000
   NODE_ENV=development
   
   # Database
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/SECURECLOUD_DB
   
   # JWT Configuration
   ACCESS_TOKEN_SECRET=your-super-secret-access-token-key-256-bits
   ACCESS_TOKEN_EXPIRY=1d
   REFRESH_TOKEN_SECRET=your-super-secret-refresh-token-key-256-bits
   REFRESH_TOKEN_EXPIRY=10d
   
   # Security
   BCRYPT_SALT_ROUNDS=10
   ```

3. **Database Setup**
   ```bash
   # Seed roles, policies, and test users
   npm run seed:all
   
   # Or seed individually
   npm run seed:roles
   npm run seed:policies
   npm run seed:users
   ```

4. **Start Development**
   ```bash
   # Development mode (auto-reload)
   npm run dev
   
   # Production mode
   npm start
   ```

## 📖 API Documentation

### **Base URL**: `http://localhost:3000/api`

### **Authentication Endpoints**

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| POST | `/auth/login` | User login | Public |
| POST | `/auth/logout` | User logout | Authenticated |
| GET | `/auth/verify` | Verify JWT token | Authenticated |

**Login Example:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@securecloud.com",
    "password": "Admin@123"
  }'
```

### **User Management Endpoints**

| Method | Endpoint | Description | RBAC | ABAC |
|--------|----------|-------------|------|------|
| GET | `/users` | Get all users | Admin, SuperAdmin | - |
| GET | `/users/:id` | Get user by ID | All roles | `read:user` |
| POST | `/users/register` | Create new user | Admin, SuperAdmin | `create:user` |
| PUT | `/users/:id` | Update user | Admin, SuperAdmin | `edit:user` |

**Create User Example:**
```bash
curl -X POST http://localhost:3000/api/users/register \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "SecurePass@123",
    "role": "editor",
    "department": "IT",
    "location": "India"
  }'
```

### **Policy Management Endpoints**

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| GET | `/policies` | Get all policies | Admin, SuperAdmin |
| GET | `/policies/:id` | Get policy by ID | Admin, SuperAdmin |
| POST | `/policies` | Create policy | Admin, SuperAdmin |
| PUT | `/policies/:id` | Update policy | Admin, SuperAdmin |
| DELETE | `/policies/:id` | Delete policy | SuperAdmin only |
| PATCH | `/policies/:id/toggle` | Toggle policy status | Admin, SuperAdmin |

## 🔐 Authentication & Authorization

### **1. Authentication Flow**
```mermaid
sequenceDiagram
    participant C as Client
    participant A as Auth API
    participant DB as Database
    
    C->>A: POST /auth/login {email, password}
    A->>DB: Verify credentials
    DB-->>A: User data + role
    A-->>C: JWT tokens {access, refresh}
    
    Note over C: Store tokens securely
    
    C->>A: API Request + Authorization header
    A->>A: Verify JWT token
    A-->>C: Protected resource
```

### **2. RBAC (Role-Based Access Control)**

**Default Roles:**
- **SuperAdmin**: Full system access, cannot be deleted
- **Admin**: Manage users and resources
- **Editor**: Create and edit projects
- **Viewer**: Read-only access

**Implementation:**
```javascript
// In routes
router.post('/users/register',
  authMiddleware,                           // Verify JWT
  rbacMiddleware(['admin', 'superadmin']),  // Check role
  createUser
);
```

### **3. ABAC (Attribute-Based Access Control)**

**Policy Conditions:**
- `ownResource: true` - User can only access their own resources
- `department: "IT"` - Department-based access
- `location: "India"` - Location-based access
- `sensitivity: "confidential"` - Resource sensitivity levels

**Example Policies:**
```javascript
// Editor can edit projects only in their department
{
  role: [editorRole._id],
  action: "edit:project",
  conditions: { department: "sales" },
  effect: "allow"
}

// Viewer can only read their own profile
{
  role: [viewerRole._id],
  action: "read:user",
  conditions: { ownResource: true },
  effect: "allow"
}
```

## 🧪 Testing

### **Test Credentials**
```javascript
// Seeded test users
const testUsers = {
  superadmin: {
    email: "superadmin@securecloud.com",
    password: "SuperAdmin@123"
  },
  admin: {
    email: "admin@securecloud.com",
    password: "Admin@123"
  },
  editor: {
    email: "editor@securecloud.com",
    password: "Editor@123"
  },
  viewer: {
    email: "viewer@securecloud.com",
    password: "Viewer@123"
  }
};
```

### **Postman Testing**

1. **Login & Get Token**
   ```javascript
   // POST {{baseUrl}}/auth/login
   // Save token to environment variable
   const response = pm.response.json();
   pm.environment.set("accessToken", response.data.token);
   ```

2. **Test Protected Endpoints**
   ```javascript
   // Add to request headers
   Authorization: Bearer {{accessToken}}
   ```

3. **Test RBAC Scenarios**
   - Login as different roles
   - Try accessing restricted endpoints
   - Verify proper 403 responses

4. **Test ABAC Scenarios**
   - Create users in different departments
   - Test department-based access
   - Verify `ownResource` conditions

### **Manual Testing Commands**
```bash
# Test user creation (requires admin token)
curl -X POST http://localhost:3000/api/users/register \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "Test@123", "role": "viewer"}'

# Test unauthorized access
curl -X POST http://localhost:3000/api/users/register \
  -H "Authorization: Bearer <VIEWER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser2", "email": "test2@example.com", "password": "Test@123", "role": "viewer"}'
# Expected: 403 Forbidden
```

## 📁 Project Structure

```
secureCloud_Project/
├── 📄 README.md                    # This documentation
├── 📄 CODE_REVIEW.md              # Code review & improvements
├── 📄 package.json                # Dependencies & scripts
├── 📄 .env                        # Environment variables
├── 📄 .gitignore                  # Git ignore rules
└── src/
    ├── 📄 app.js                  # Express app configuration
    ├── 📄 index.js                # Server entry point
    ├── 📄 constants.js            # Application constants
    ├── 📁 controller/             # Business logic
    │   ├── auth.controller.js     # Authentication logic
    │   ├── user.controller.js     # User management
    │   ├── policy.controller.js   # Policy management
    │   └── seeder.controller.js   # Database seeding
    ├── 📁 middleware/             # Custom middleware
    │   ├── auth.middleware.js     # JWT verification
    │   ├── rbac.middleware.js     # Role-based access
    │   └── abac.middleware.js     # Attribute-based access
    ├── 📁 models/                 # Database schemas
    │   ├── users.models.js        # User schema
    │   ├── role.models.js         # Role schema
    │   ├── policy.models.js       # Policy schema
    │   ├── resource.models.js     # Resource schema
    │   └── auditLog.models.js     # Audit logging
    ├── 📁 routes/                 # API routes
    │   ├── auth.routes.js         # Authentication routes
    │   ├── user.routes.js         # User management routes
    │   └── policy.routes.js       # Policy management routes
    ├── 📁 utils/                  # Helper utilities
    │   ├── ApiError.utils.js      # Custom error handling
    │   ├── ApiResponse.utils.js   # Standardized responses
    │   ├── asyncHandler.utils.js  # Async error wrapper
    │   ├── auditLogger.utils.js   # Audit logging utility
    │   └── policyEvaluator.utils.js # Policy evaluation
    ├── 📁 scripts/                # Utility scripts
    │   ├── seeder.js              # Database seeding script
    │   └── policy.js              # Policy management script
    ├── 📁 db/                     # Database configuration
    │   └── index.js               # MongoDB connection
    └── 📁 validation/             # Input validation schemas
```

## 🌱 Database Seeding

### **Available Scripts**
```bash
# Seed everything (recommended for first setup)
npm run seed:all

# Seed individual components
npm run seed:roles        # Create default roles
npm run seed:policies     # Create ABAC policies
npm run seed:users        # Create test users
npm run seed:superadmin   # Create only superadmin
```

### **What Gets Seeded**

**Roles (4):**
- SuperAdmin, Admin, Editor, Viewer

**Policies (17):**
- Role-specific permissions
- Multi-role policies
- Condition-based access rules

**Users (4):**
- One user per role with test credentials
- Different departments and locations

### **Seeding Output Example**
```
🚀 Starting RBAC + ABAC seeding process...
════════════════════════════════════════

📋 Step 1: Seeding Roles...
✅ Created 4 roles successfully:
   - superadmin: Full system access (cannot be deleted)
   - admin: Manage organization users and resources
   - editor: Create and edit project resources
   - viewer: View only permissions

🔐 Step 2: Seeding ABAC Policies...
✅ Created 17 ABAC policies successfully:
   superadmin: manage:all, delete:user, delete:policy, create:policy, edit:policy
   admin: create:user, edit:user, read:user, create:resource, edit:resource, create:policy, edit:policy
   editor: create:project, edit:project, read:project, create:resource
   viewer: read:user, read:project, read:resource

👥 Step 3: Seeding Users...
✅ Created 4 users successfully:
   - superadmin (superadmin@securecloud.com)
   - adminuser (admin@securecloud.com)
   - editoruser (editor@securecloud.com)
   - vieweruser (viewer@securecloud.com)

📊 Database Summary:
   Roles: 4
   Policies: 17
   Users: 4

🔑 Test Credentials:
   SuperAdmin: superadmin@securecloud.com / SuperAdmin@123
   Admin:      admin@securecloud.com / Admin@123
   Editor:     editor@securecloud.com / Editor@123
   Viewer:     viewer@securecloud.com / Viewer@123
```

## 🔄 Environment Variables

### **Required Variables**
```env
# Server Configuration
PORT=3000                           # Server port
NODE_ENV=development                # Environment (development/production)

# Database
MONGODB_URI=mongodb+srv://...       # MongoDB Atlas connection string

# JWT Security
ACCESS_TOKEN_SECRET=<256-bit-key>   # JWT access token secret
ACCESS_TOKEN_EXPIRY=1d              # Access token expiration
REFRESH_TOKEN_SECRET=<256-bit-key>  # JWT refresh token secret
REFRESH_TOKEN_EXPIRY=10d            # Refresh token expiration

# Optional
BCRYPT_SALT_ROUNDS=10               # Password hashing rounds
```

### **Security Recommendations**
- Use strong, unique secrets (256-bit minimum)
- Different secrets for different environments
- Store secrets in secure vaults in production
- Rotate secrets regularly

## 🛠️ Development

### **Available Scripts**
```bash
npm run dev          # Start development server (nodemon)
npm start            # Start production server
npm run seed:all     # Seed database with default data
npm run test         # Run tests (when implemented)
npm run lint         # Code linting (when configured)
```

### **Development Workflow**
1. Make changes to source files
2. Server auto-reloads (nodemon)
3. Test endpoints with Postman
4. Check console logs for debugging
5. Commit changes

### **Debugging**
- Console logs in middleware show request flow
- Error details logged to console
- JWT token contents logged (development only)
- MongoDB queries can be logged via Mongoose debug

## 📊 Monitoring & Logging

### **Audit Logging**
All user actions are logged to the `auditlogs` collection:
```javascript
{
  userId: ObjectId,
  action: "create:user",
  resource: "user-id-here",
  status: "allowed" | "denied",
  timestamp: Date,
  metadata: Object,
  ipAddress: String,
  userAgent: String
}
```

### **Error Logging**
- All errors logged with stack traces
- JWT verification failures logged
- RBAC/ABAC denials logged
- Database connection issues logged

### **Performance Monitoring**
- MongoDB query performance can be monitored
- JWT token validation timing
- Middleware execution time

## 🤝 Contributing

### **Development Setup**
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Test thoroughly
5. Commit: `git commit -m 'Add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Create a Pull Request

### **Code Standards**
- Use ES6+ features
- Follow existing code style
- Add comments for complex logic
- Include error handling
- Test new features

### **Commit Message Format**
```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(auth): add refresh token rotation`
- `fix(rbac): resolve role permission check bug`
- `docs(readme): update API documentation`

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by Microsoft Azure's access management system
- Built with modern Node.js and Express.js best practices
- Implements industry-standard JWT authentication
- Follows OWASP security guidelines

---

**📧 Support:** For questions or issues, please create an issue in the GitHub repository.

**🔗 Repository:** [https://github.com/Siddharth-Dev2310/RBAC-ABAC](https://github.com/Siddharth-Dev2310/RBAC-ABAC)