package auth

import (
	"context"
	"time"
)

// User represents a user in the authentication system
type User struct {
	ID                    uint       `json:"id"`
	Username              string     `json:"username"`
	PasswordHash          string     `json:"-"` // Never expose password hash in JSON
	Salt                  string     `json:"-"` // Never expose salt in JSON
	Role                  string     `json:"role"`
	Active                bool       `json:"active"`
	CreatedAt             time.Time  `json:"created_at"`
	LastLogin             *time.Time `json:"last_login"`
	CreatedBy             string     `json:"created_by"`
	FailedLoginAttempts   int        `json:"failed_login_attempts"`
	AccountLockedUntil    *time.Time `json:"account_locked_until"`
	PasswordChangedAt     time.Time  `json:"password_changed_at"`
	SessionTimeoutMinutes int        `json:"session_timeout_minutes"`
	MaxConcurrentSessions int        `json:"max_concurrent_sessions"`
}

// HasPermission checks if the user has a specific permission
func (u *User) HasPermission(permission string) bool {
	permissions, exists := RolePermissions[u.Role]
	if !exists {
		return false
	}

	for _, perm := range permissions {
		if perm == permission {
			return true
		}
	}

	return false
}

// GetRole returns the user's role
func (u *User) GetRole() string {
	return u.Role
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(role string) bool {
	return u.Role == role
}

// UserSession represents an active user session
type UserSession struct {
	SessionID         string     `json:"session_id"`
	UserID            uint       `json:"user_id"`
	User              User       `json:"user"`
	CreatedAt         time.Time  `json:"created_at"`
	LastActivity      time.Time  `json:"last_activity"`
	ExpiresAt         time.Time  `json:"expires_at"`
	IPAddress         string     `json:"ip_address"`
	UserAgent         string     `json:"user_agent"`
	Active            bool       `json:"active"`
	LoginMethod       string     `json:"login_method"`
	ClientFingerprint string     `json:"client_fingerprint"`
	RevokedAt         *time.Time `json:"revoked_at"`
	RevokedBy         string     `json:"revoked_by"`
}

// Role constants
const (
	RoleAdmin         = "admin"
	RoleOperator      = "operator"
	RoleAgentOperator = "agent-operator"
)

// Permission constants
const (
	PermissionUserManagement     = "user_management"
	PermissionListenerManagement = "listener_management"
	PermissionAgentManagement    = "agent_management"
	PermissionViewLogs           = "view_logs"
	PermissionChat               = "chat"
	PermissionFileManagement     = "file_management"
	PermissionSystemSettings     = "system_settings"
)

// RolePermissions defines what permissions each role has
var RolePermissions = map[string][]string{
	RoleAdmin: {
		PermissionUserManagement,
		PermissionListenerManagement,
		PermissionAgentManagement,
		PermissionViewLogs,
		PermissionChat,
		PermissionFileManagement,
		PermissionSystemSettings,
	},
	RoleOperator: {
		PermissionListenerManagement,
		PermissionAgentManagement,
		PermissionViewLogs,
		PermissionChat,
		PermissionFileManagement,
	},
	RoleAgentOperator: {
		PermissionAgentManagement, // Limited to assigned agents only
		PermissionViewLogs,        // Limited to assigned agents only
		PermissionChat,
		PermissionFileManagement, // Limited to assigned agents only
	},
}

// Context keys for session management
type contextKey string

const sessionContextKey contextKey = "session"

// SetSessionInContext adds a session to the request context
func SetSessionInContext(ctx context.Context, session *UserSession) context.Context {
	return context.WithValue(ctx, sessionContextKey, session)
}

// GetSessionFromContext retrieves a session from the request context
func GetSessionFromContext(ctx context.Context) *UserSession {
	session, ok := ctx.Value(sessionContextKey).(*UserSession)
	if !ok {
		return nil
	}
	return session
}
