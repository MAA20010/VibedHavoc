# Havoc Authentication System

A comprehensive database-backed authentication system for the Havoc C2 framework, designed to replace the existing profile-based authentication while maintaining backward compatibility.

## Features

### Core Authentication
- **Database-backed user management** using SQLite
- **Strong password hashing** with Argon2id (OWASP recommended)
- **Session management** with JWT-like tokens
- **Role-based access control** (Admin/Operator roles)
- **Account lockout protection** against brute force attacks
- **Session timeout and cleanup** for security

### Security Features
- **Salt-based password hashing** for rainbow table protection
- **Configurable password policies** (length, complexity requirements)
- **Failed login attempt tracking** with automatic lockouts
- **Client fingerprinting** for session validation
- **Secure session IDs** using cryptographically secure random generation
- **Protection against timing attacks** using constant-time comparisons

### Backward Compatibility
- **Profile system fallback** for existing deployments
- **Migration utilities** to move from profiles to database
- **Legacy session support** during transition period
- **Graceful degradation** when database is unavailable

### Administration
- **Web-based user management** with RESTful APIs
- **Comprehensive logging** of authentication events
- **Configurable security policies** via JSON configuration
- **Built-in admin user creation** for initial setup

## Architecture

### Package Structure
```
pkg/auth/
├── types.go         # Core data structures and constants
├── crypto.go        # Password hashing and cryptographic functions
├── database.go      # Database operations and SQLite management
├── service.go       # Main authentication service logic
├── middleware.go    # HTTP middleware for web authentication
├── integration.go   # Backward compatibility wrapper
├── config.go        # Configuration management
└── example/         # Usage examples and demonstrations
```

### Database Schema
```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    created_by TEXT NOT NULL,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until DATETIME,
    password_changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    session_timeout_minutes INTEGER DEFAULT 480,
    max_concurrent_sessions INTEGER DEFAULT 3
);

-- Sessions table
CREATE TABLE user_sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    active BOOLEAN NOT NULL DEFAULT 1,
    login_method TEXT DEFAULT 'password',
    client_fingerprint TEXT,
    revoked_at DATETIME,
    revoked_by TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## Quick Start

### 1. Basic Setup
```go
package main

import (
    "log"
    "Havoc/pkg/auth"
)

func main() {
    // Load configuration (creates default if not exists)
    config, err := auth.LoadAuthConfig("./auth_config.json")
    if err != nil {
        log.Fatal(err)
    }
    
    // Initialize authentication service
    authService, err := auth.NewAuthService(config.GetDatabasePath())
    if err != nil {
        log.Fatal(err)
    }
    defer authService.Close()
    
    // Service is ready to use
    // Default admin user is created automatically
}
```

### 2. User Authentication
```go
// Authenticate a user
session, err := authService.Authenticate("username", "password", "127.0.0.1", "User-Agent")
if err != nil {
    // Authentication failed
    log.Printf("Login failed: %v", err)
    return
}

// Session contains user info and session details
fmt.Printf("User %s logged in with role %s", session.User.Username, session.User.Role)

// Validate session later
validSession, err := authService.ValidateSession(session.SessionID)
if err != nil {
    // Session invalid or expired
    return
}
```

### 3. Web Integration
```go
// Create HTTP middleware
middleware := auth.NewMiddleware(authService)

// Setup routes
mux := http.NewServeMux()
mux.HandleFunc("/auth/login", middleware.LoginHandler)
mux.HandleFunc("/auth/logout", middleware.LogoutHandler)
mux.HandleFunc("/admin/users", middleware.RequireAdmin(adminHandler))
mux.HandleFunc("/operator/agents", middleware.RequireAuth(operatorHandler))

// Start server
http.ListenAndServe(":8080", mux)
```

### 4. Backward Compatibility
```go
// Create compatibility wrapper for existing profiles
legacyAuth := func(username, password string) bool {
    // Your existing ClientAuthenticate logic here
    return validateProfile(username, password)
}

wrapper, err := auth.NewProfileCompatibilityWrapper("./auth.db", legacyAuth)
if err != nil {
    log.Fatal(err)
}

// Wrapper handles both database and profile authentication
session, err := wrapper.AuthenticateUser("user", "pass", "127.0.0.1", "Client")
```

## Configuration

### Default Configuration File (auth_config.json)
```json
{
  "database_path": "./auth.db",
  "database_type": "sqlite",
  "default_session_timeout": 480,
  "max_concurrent_sessions": 5,
  "session_cleanup_interval": 60,
  "min_password_length": 8,
  "require_special_chars": true,
  "require_numbers": true,
  "require_uppercase": true,
  "require_lowercase": true,
  "max_failed_attempts": 5,
  "lockout_duration_minutes": 30,
  "force_password_change": false,
  "password_history_size": 5,
  "enable_profile_fallback": true,
  "profile_path": "./profiles",
  "log_auth_attempts": true,
  "log_level": "info"
}
```

## Roles and Permissions

### Available Roles
- **Admin**: Full system access including user management
- **Operator**: Standard operational access (agents, listeners, files)

### Permission System
```go
// Check permissions
if user.HasPermission(auth.PermissionUserManagement) {
    // User can manage other users
}

// Available permissions
auth.PermissionUserManagement     // Create/modify/delete users
auth.PermissionListenerManagement // Manage listeners
auth.PermissionAgentManagement    // Manage agents
auth.PermissionViewLogs           // View system logs
auth.PermissionChat               // Access chat system
auth.PermissionFileManagement     // File operations
auth.PermissionSystemSettings     // System configuration
```

## Migration from Profiles

### Automatic Migration
```go
// Migrate existing profile users to database
err := wrapper.MigrateProfileToDatabase("username", "password", "operator")
if err != nil {
    log.Printf("Migration failed: %v", err)
}
```

### Manual Migration Process
1. **Backup existing profiles** before migration
2. **Run migration utility** for each user
3. **Test authentication** with both systems
4. **Disable profile fallback** once migration is complete
5. **Remove old profile files** after verification

## Security Best Practices

### Password Security
- **Minimum 12 characters** for strong security
- **Mixed case, numbers, and special characters** required
- **Password history** prevents reuse
- **Argon2id hashing** with appropriate parameters

### Session Security
- **Short session timeouts** for sensitive environments
- **IP address validation** for additional security
- **Client fingerprinting** to detect session hijacking
- **Regular session cleanup** to prevent accumulation

### Database Security
- **SQLite WAL mode** for better concurrency
- **Foreign key constraints** for data integrity
- **Regular backups** of authentication database
- **File permissions** to protect database access

## API Reference

### Core Services

#### AuthService
```go
// Create new auth service
NewAuthService(databasePath string) (*AuthService, error)

// Authenticate user
Authenticate(username, password, clientIP, userAgent string) (*UserSession, error)

// Validate session
ValidateSession(sessionID string) (*UserSession, error)

// Create user (admin only)
CreateUser(adminSessionID, username, password, role string) (*User, error)

// Logout user
Logout(sessionID string) error
```

#### Middleware
```go
// Create middleware
NewMiddleware(authService *AuthService) *Middleware

// Require authentication
RequireAuth(next http.HandlerFunc) http.HandlerFunc

// Require specific role
RequireRole(role string) func(http.HandlerFunc) http.HandlerFunc

// Require specific permission
RequirePermission(permission string) func(http.HandlerFunc) http.HandlerFunc
```

### HTTP Endpoints

#### Authentication
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout  
- `GET /auth/user` - Get current user info

#### User Management (Admin only)
- `GET /auth/users` - List all users
- `POST /auth/users/create` - Create new user
- `PUT /auth/users/:id` - Update user
- `DELETE /auth/users/:id` - Delete user

### Request/Response Examples

#### Login Request
```json
POST /auth/login
{
  "username": "admin",
  "password": "secure_password"
}
```

#### Login Response
```json
{
  "success": true,
  "session_id": "abc123...",
  "user": {
    "username": "admin",
    "role": "admin"
  },
  "expires_at": "2025-01-01T12:00:00Z"
}
```

## Troubleshooting

### Common Issues

#### Database Connection Errors
```bash
# Check file permissions
ls -la auth.db

# Check SQLite installation
sqlite3 auth.db ".tables"
```

#### Authentication Failures
```bash
# Check logs for detailed error messages
tail -f havoc.log | grep AUTH

# Verify password requirements
./havoc-auth check-password "test_password"
```

#### Session Issues
```bash
# Clean expired sessions manually
sqlite3 auth.db "DELETE FROM user_sessions WHERE expires_at < datetime('now');"
```

### Debug Mode
```go
// Enable debug logging
config.LogLevel = "debug"

// Check authentication details
session, err := authService.Authenticate(username, password, ip, ua)
if err != nil {
    log.Printf("Auth failed: %v", err)
}
```

## Performance Considerations

### Database Optimization
- **SQLite WAL mode** enabled by default
- **Prepared statements** for common queries
- **Connection pooling** with single connection for SQLite
- **Regular VACUUM** operations for maintenance

### Session Management
- **Automatic cleanup** of expired sessions
- **Configurable cleanup intervals** 
- **Efficient indexing** on session queries
- **Memory-efficient** session storage

### Scalability
- **Single SQLite file** suitable for most C2 deployments
- **Read-heavy workload optimization** 
- **Future PostgreSQL support** for large deployments
- **Horizontal scaling** considerations documented

## Development

### Testing
```bash
# Run auth package tests
go test ./pkg/auth

# Run with coverage
go test -cover ./pkg/auth

# Run example application
go run ./pkg/auth/example/main.go
```

### Contributing
1. **Follow Go conventions** for code style
2. **Add comprehensive tests** for new features
3. **Update documentation** for API changes
4. **Maintain backward compatibility** when possible

## License

This authentication system is part of the Havoc C2 framework and follows the same license terms.
