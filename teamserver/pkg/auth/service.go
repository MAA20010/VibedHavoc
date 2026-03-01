package auth

import (
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// AuthService provides authentication and authorization services
type AuthService struct {
	db       *DatabaseManager
	throttle *AuthThrottle
}

// NewAuthService creates a new authentication service
func NewAuthService(databasePath string) (*AuthService, error) {
	db, err := NewDatabaseManager(databasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	service := &AuthService{
		db:       db,
		throttle: NewAuthThrottle(),
	}

	// Create default admin user if no users exist
	err = service.ensureDefaultAdmin()
	if err != nil {
		return nil, fmt.Errorf("failed to create default admin: %v", err)
	}

	return service, nil
}

// ensureDefaultAdmin creates a default admin user if no users exist
func (as *AuthService) ensureDefaultAdmin() error {
	// Check if any users exist
	users, err := as.GetAllUsers()
	if err != nil {
		return err
	}

	if len(users) == 0 {
		// Create default admin user compatible with client SHA3 authentication
		fmt.Println("[AUTH] Creating default admin user...")

		// Use a simple password that we can hash consistently
		rawPassword := "password"

		// Create SHA3 hash like the profile system does
		passHash := sha3.New256()
		passHash.Write([]byte(rawPassword))
		sha3Hash := hex.EncodeToString(passHash.Sum(nil))

		// Print the SHA3 hash for debugging
		fmt.Printf("[AUTH] SHA3 hash of password '%s': %s\n", rawPassword, sha3Hash)

		// Bcrypt the SHA3 hash for secure storage (proper bcrypt format)
		bcryptHash, err := bcrypt.GenerateFromPassword([]byte(sha3Hash), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to create secure hash for admin: %v", err)
		}

		// Print the bcrypt hash for debugging
		fmt.Printf("[AUTH] Bcrypt hash: %s\n", string(bcryptHash))

		// Create user with the bcrypt hash
		_, err = as.db.CreateUser("admin", string(bcryptHash), RoleAdmin, "system")
		if err != nil {
			return fmt.Errorf("failed to create default admin: %v", err)
		}

		fmt.Printf("[AUTH] Default admin user created with username 'admin' and password '%s'\n", rawPassword)
		fmt.Println("[AUTH] Please change this password immediately after first login!")
	}

	return nil
}

// generateSecurePassword generates a cryptographically secure random password
func generateSecurePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	password := make([]byte, length)
	for i := range password {
		password[i] = charset[int(b[i])%len(charset)]
	}

	return string(password), nil
}

// Authenticate validates user credentials and returns a session.
// Brute-force protection: per-IP exponential backoff (no account lockout).
func (as *AuthService) Authenticate(username, password, clientIP, userAgent string) (*UserSession, error) {
	// Input validation
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return nil, errors.New("username and password are required")
	}

	// --- Per-IP throttle: sleep before processing if this IP has prior failures ---
	if delay := as.throttle.Delay(clientIP); delay > 0 {
		fmt.Printf("[AUTH] Throttle: IP %s delayed %v before auth attempt\n", clientIP, delay)
		time.Sleep(delay)
	}

	// Get user from database
	user, err := as.db.GetUserByUsername(username)
	if err != nil {
		as.throttle.RecordFailure(clientIP)
		return nil, errors.New("invalid credentials")
	}

	// Client sends SHA3 hash, verify against bcrypt-hashed SHA3 in database
	user.PasswordHash = strings.TrimSpace(user.PasswordHash)
	password = strings.TrimSpace(password)

	// Use proper bcrypt verification
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	valid := err == nil

	if !valid {
		as.throttle.RecordFailure(clientIP)
		fmt.Printf("[AUTH] Failed login for user '%s' from IP %s\n", username, clientIP)
		return nil, errors.New("invalid credentials")
	}

	// --- Success: clear throttle for this IP ---
	as.throttle.RecordSuccess(clientIP)

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, errors.New("failed to create session")
	}

	// Create client fingerprint
	fingerprint := generateClientFingerprint(clientIP, userAgent)

	// Create session in database
	session, err := as.db.CreateSession(user.ID, sessionID, clientIP, userAgent, fingerprint, user.SessionTimeoutMinutes)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	// Update last login
	err = as.db.UpdateLastLogin(user.ID)
	if err != nil {
		// Log error but don't fail authentication
		fmt.Printf("[AUTH] Warning: Failed to update last login for user %s: %v\n", username, err)
	}

	// Populate session with user data
	session.User = *user

	return session, nil
}

// ValidateSession validates a session and returns the associated user
func (as *AuthService) ValidateSession(sessionID string) (*UserSession, error) {
	if sessionID == "" {
		return nil, errors.New("session ID is required")
	}

	session, err := as.db.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	// Update session activity
	err = as.db.UpdateSessionActivity(sessionID)
	if err != nil {
		// Log error but don't fail validation
		fmt.Printf("[AUTH] Warning: Failed to update session activity: %v\n", err)
	}

	return session, nil
}

// Logout invalidates a session
func (as *AuthService) Logout(sessionID string) error {
	if sessionID == "" {
		return errors.New("session ID is required")
	}

	return as.db.InvalidateSession(sessionID)
}

// CreateUser creates a new user (admin only)
func (as *AuthService) CreateUser(adminSessionID, username, password, role string) (*User, error) {
	// Validate admin session
	session, err := as.ValidateSession(adminSessionID)
	if err != nil {
		return nil, errors.New("invalid session")
	}

	if !session.User.HasPermission(PermissionUserManagement) {
		return nil, errors.New("insufficient permissions")
	}

	// Create user
	user, err := as.db.CreateUser(username, password, role, session.User.Username)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// GetAllUsers returns all users (admin only)
func (as *AuthService) GetAllUsers() ([]User, error) {
	// Note: This method could also take a session ID for authorization
	// For now, we'll implement it as a direct database call

	// Use a simple query to get all active users
	users := []User{}

	// Since we don't have GORM, we need to implement this manually
	query := "SELECT id, username, role, active, created_at, last_login, created_by FROM users"
	rows, err := as.db.GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		var lastLogin *time.Time

		err := rows.Scan(&user.ID, &user.Username, &user.Role, &user.Active, &user.CreatedAt, &lastLogin, &user.CreatedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %v", err)
		}

		user.LastLogin = lastLogin
		users = append(users, user)
	}

	return users, nil
}

// CleanupExpiredSessions removes expired sessions
func (as *AuthService) CleanupExpiredSessions() error {
	return as.db.CleanupExpiredSessions()
}

// Close closes the authentication service
func (as *AuthService) Close() error {
	return as.db.Close()
}

// Helper functions

// generateSessionID generates a cryptographically secure session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// generateClientFingerprint creates a simple client fingerprint
func generateClientFingerprint(ip, userAgent string) string {
	// Simple fingerprint based on IP and User-Agent
	// In production, this could be more sophisticated
	return fmt.Sprintf("%s:%s", ip, userAgent)
}

// IsValidRole checks if a role is valid
func IsValidRole(role string) bool {
	return role == RoleAdmin || role == RoleOperator
}

// StartSessionCleanupRoutine starts a background routine to clean expired sessions
func (as *AuthService) StartSessionCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Clean every hour
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				err := as.CleanupExpiredSessions()
				if err != nil {
					fmt.Printf("[AUTH] Warning: Failed to cleanup expired sessions: %v\n", err)
				}
			}
		}
	}()
}
