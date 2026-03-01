package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DatabaseManager handles database operations for authentication
type DatabaseManager struct {
	db   *sql.DB
	path string
}

// NewDatabaseManager creates a new database manager
func NewDatabaseManager(databasePath string) (*DatabaseManager, error) {
	if databasePath == "" {
		databasePath = "./auth.db"
	}

	// Ensure the directory exists
	dir := filepath.Dir(databasePath)
	if dir != "." && dir != "" {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create database directory: %v", err)
		}
	}

	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Configure SQLite for better performance and concurrency
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	manager := &DatabaseManager{
		db:   db,
		path: databasePath,
	}

	// Create tables first - this will create the database file
	err = manager.CreateTables()
	if err != nil {
		return nil, fmt.Errorf("failed to create tables: %v", err)
	}

	// Execute SQLite-specific optimizations AFTER database is created
	_, err = db.Exec("PRAGMA journal_mode=WAL") // Write-Ahead Logging for better concurrency
	if err != nil {
		return nil, fmt.Errorf("failed to set WAL mode: %v", err)
	}
	_, err = db.Exec("PRAGMA synchronous=NORMAL") // Balance between safety and performance
	if err != nil {
		return nil, fmt.Errorf("failed to set synchronous mode: %v", err)
	}
	_, err = db.Exec("PRAGMA cache_size=1000") // Increase cache size
	if err != nil {
		return nil, fmt.Errorf("failed to set cache size: %v", err)
	}
	_, err = db.Exec("PRAGMA foreign_keys=ON") // Enable foreign key constraints
	if err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %v", err)
	}

	return manager, nil
}

// CreateTables creates the authentication tables
func (dm *DatabaseManager) CreateTables() error {
	// Create users table
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
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
	);`

	_, err := dm.db.Exec(usersTable)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	// Create user_sessions table
	sessionsTable := `
	CREATE TABLE IF NOT EXISTS user_sessions (
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
	);`

	_, err = dm.db.Exec(sessionsTable)
	if err != nil {
		return fmt.Errorf("failed to create user_sessions table: %v", err)
	}

	// Create agent_assignments table for agent-operator role
	agentAssignmentsTable := `
	CREATE TABLE IF NOT EXISTS agent_assignments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		agent_id TEXT NOT NULL,
		assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		assigned_by_user_id INTEGER NOT NULL,
		revoked_at DATETIME,
		revoked_by_user_id INTEGER,
		active BOOLEAN NOT NULL DEFAULT 1,
		notes TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id),
		FOREIGN KEY (assigned_by_user_id) REFERENCES users(id),
		FOREIGN KEY (revoked_by_user_id) REFERENCES users(id),
		UNIQUE(user_id, agent_id, active)
	);`

	_, err = dm.db.Exec(agentAssignmentsTable)
	if err != nil {
		return fmt.Errorf("failed to create agent_assignments table: %v", err)
	}

	// Create admin_actions table for audit logging
	adminActionsTable := `
	CREATE TABLE IF NOT EXISTS admin_actions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		admin_user_id INTEGER NOT NULL,
		action TEXT NOT NULL,
		target_user_id INTEGER,
		target_username TEXT,
		target_agent_id TEXT,
		details TEXT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		client_ip TEXT,
		success BOOLEAN NOT NULL DEFAULT 1,
		error_message TEXT,
		FOREIGN KEY (admin_user_id) REFERENCES users(id)
	);`

	_, err = dm.db.Exec(adminActionsTable)
	if err != nil {
		return fmt.Errorf("failed to create admin_actions table: %v", err)
	}

	// Create indexes for performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
		"CREATE INDEX IF NOT EXISTS idx_users_active ON users(active);",
		"CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(active);",
		"CREATE INDEX IF NOT EXISTS idx_agent_assignments_user_id ON agent_assignments(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_agent_assignments_agent_id ON agent_assignments(agent_id);",
		"CREATE INDEX IF NOT EXISTS idx_agent_assignments_active ON agent_assignments(active);",
		"CREATE INDEX IF NOT EXISTS idx_admin_actions_admin_user ON admin_actions(admin_user_id);",
		"CREATE INDEX IF NOT EXISTS idx_admin_actions_timestamp ON admin_actions(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_admin_actions_target_agent ON admin_actions(target_agent_id);",
	}

	for _, indexSQL := range indexes {
		_, err = dm.db.Exec(indexSQL)
		if err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

// CreateUser creates a new user in the database
func (dm *DatabaseManager) CreateUser(username, password, role, createdBy string) (*User, error) {
	// Validate input
	if username == "" || password == "" {
		return nil, errors.New("username and password are required")
	}

	// Check if user already exists
	var count int
	err := dm.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
	}
	if count > 0 {
		return nil, errors.New("user already exists")
	}

	// Generate salt (even though bcrypt handles salting internally)
	salt, err := GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// Create user with current timestamp
	user := &User{
		Username:              username,
		PasswordHash:          password, // This should already be a bcrypt hash from the caller
		Salt:                  salt,
		Role:                  role,
		Active:                true,
		CreatedBy:             createdBy,
		PasswordChangedAt:     time.Now(),
		SessionTimeoutMinutes: 480, // 8 hours
		MaxConcurrentSessions: 3,
		FailedLoginAttempts:   0,
	}

	// Insert into database
	query := `
		INSERT INTO users (username, password_hash, salt, role, active, created_by, password_changed_at, session_timeout_minutes, max_concurrent_sessions)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := dm.db.Exec(query, user.Username, user.PasswordHash, user.Salt, user.Role, user.Active, user.CreatedBy, user.PasswordChangedAt, user.SessionTimeoutMinutes, user.MaxConcurrentSessions)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %v", err)
	}

	user.ID = uint(id)
	user.CreatedAt = time.Now()

	return user, nil
}

// GetUserByUsername retrieves an ACTIVE user by username (for login)
func (dm *DatabaseManager) GetUserByUsername(username string) (*User, error) {
	query := `
		SELECT id, username, password_hash, salt, role, active, created_at, last_login, created_by,
		       failed_login_attempts, account_locked_until, password_changed_at, session_timeout_minutes, max_concurrent_sessions
		FROM users 
		WHERE username = ? AND active = 1
	`

	var user User
	var lastLogin sql.NullTime
	var accountLockedUntil sql.NullTime

	err := dm.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Salt, &user.Role, &user.Active,
		&user.CreatedAt, &lastLogin, &user.CreatedBy, &user.FailedLoginAttempts,
		&accountLockedUntil, &user.PasswordChangedAt, &user.SessionTimeoutMinutes, &user.MaxConcurrentSessions,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}
	if accountLockedUntil.Valid {
		user.AccountLockedUntil = &accountLockedUntil.Time
	}

	return &user, nil
}

// GetUserByUsernameAny retrieves a user by username regardless of active status (for admin operations)
func (dm *DatabaseManager) GetUserByUsernameAny(username string) (*User, error) {
	query := `
		SELECT id, username, password_hash, salt, role, active, created_at, last_login, created_by,
		       failed_login_attempts, account_locked_until, password_changed_at, session_timeout_minutes, max_concurrent_sessions
		FROM users 
		WHERE username = ?
	`

	var user User
	var lastLogin sql.NullTime
	var accountLockedUntil sql.NullTime

	err := dm.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Salt, &user.Role, &user.Active,
		&user.CreatedAt, &lastLogin, &user.CreatedBy, &user.FailedLoginAttempts,
		&accountLockedUntil, &user.PasswordChangedAt, &user.SessionTimeoutMinutes, &user.MaxConcurrentSessions,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}
	if accountLockedUntil.Valid {
		user.AccountLockedUntil = &accountLockedUntil.Time
	}

	return &user, nil
}

// UpdateLastLogin updates the user's last login timestamp
func (dm *DatabaseManager) UpdateLastLogin(userID uint) error {
	_, err := dm.db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %v", err)
	}
	return nil
}

// UpdateUser updates user information in the database
func (dm *DatabaseManager) UpdateUser(user *User) error {
	query := `
		UPDATE users SET 
			username = ?, password_hash = ?, salt = ?, role = ?, 
			active = ?, failed_login_attempts = ?, account_locked_until = ?,
			session_timeout_minutes = ?, max_concurrent_sessions = ?
		WHERE id = ?
	`

	_, err := dm.db.Exec(query,
		user.Username, user.PasswordHash, user.Salt, user.Role,
		user.Active, user.FailedLoginAttempts, user.AccountLockedUntil,
		user.SessionTimeoutMinutes, user.MaxConcurrentSessions, user.ID)

	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}
	return nil
}

// CreateSession creates a new user session
func (dm *DatabaseManager) CreateSession(userID uint, sessionID, clientIP, userAgent, fingerprint string, timeoutMinutes int) (*UserSession, error) {
	expiresAt := time.Now().Add(time.Duration(timeoutMinutes) * time.Minute)

	query := `
		INSERT INTO user_sessions (session_id, user_id, expires_at, ip_address, user_agent, client_fingerprint)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := dm.db.Exec(query, sessionID, userID, expiresAt, clientIP, userAgent, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	session := &UserSession{
		SessionID:         sessionID,
		UserID:            userID,
		CreatedAt:         time.Now(),
		LastActivity:      time.Now(),
		ExpiresAt:         expiresAt,
		IPAddress:         clientIP,
		UserAgent:         userAgent,
		Active:            true,
		LoginMethod:       "password",
		ClientFingerprint: fingerprint,
	}

	return session, nil
}

// GetSession retrieves a session by session ID
func (dm *DatabaseManager) GetSession(sessionID string) (*UserSession, error) {
	query := `
		SELECT s.session_id, s.user_id, s.created_at, s.last_activity, s.expires_at, s.ip_address, 
		       s.user_agent, s.active, s.login_method, s.client_fingerprint, s.revoked_at, s.revoked_by,
		       u.username, u.role
		FROM user_sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.session_id = ? AND s.active = 1 AND u.active = 1
	`

	var session UserSession
	var revokedAt sql.NullTime
	var revokedBy sql.NullString

	err := dm.db.QueryRow(query, sessionID).Scan(
		&session.SessionID, &session.UserID, &session.CreatedAt, &session.LastActivity,
		&session.ExpiresAt, &session.IPAddress, &session.UserAgent, &session.Active,
		&session.LoginMethod, &session.ClientFingerprint, &revokedAt, &revokedBy,
		&session.User.Username, &session.User.Role,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("session not found")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}
	if revokedBy.Valid {
		session.RevokedBy = revokedBy.String
	}

	// IMPORTANT: Populate User.ID from session.UserID (for foreign key references)
	session.User.ID = session.UserID

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		// Mark session as inactive
		dm.InvalidateSession(sessionID)
		return nil, errors.New("session expired")
	}

	return &session, nil
}

// UpdateSessionActivity updates the session's last activity and extends expiration (sliding window)
func (dm *DatabaseManager) UpdateSessionActivity(sessionID string) error {
	// Implement sliding window - extend session expiration on each activity
	// This prevents active users from being logged out mid-operation
	
	// First, get the user's session timeout setting
	query := `
		SELECT u.session_timeout_minutes 
		FROM user_sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.session_id = ? AND s.active = 1
	`
	
	var timeoutMinutes int
	err := dm.db.QueryRow(query, sessionID).Scan(&timeoutMinutes)
	if err != nil {
		return fmt.Errorf("failed to get session timeout: %v", err)
	}
	
	// Update last_activity AND extend expires_at
	newExpiresAt := time.Now().Add(time.Duration(timeoutMinutes) * time.Minute)
	updateQuery := `
		UPDATE user_sessions 
		SET last_activity = CURRENT_TIMESTAMP, expires_at = ? 
		WHERE session_id = ?
	`
	
	_, err = dm.db.Exec(updateQuery, newExpiresAt, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update session activity: %v", err)
	}
	return nil
}

// InvalidateSession marks a session as inactive
func (dm *DatabaseManager) InvalidateSession(sessionID string) error {
	_, err := dm.db.Exec("UPDATE user_sessions SET active = 0, revoked_at = CURRENT_TIMESTAMP WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to invalidate session: %v", err)
	}
	return nil
}

// RevokeAllUserSessions revokes all active sessions for a specific user
// Used when user is deactivated or role changes to force re-authentication
func (dm *DatabaseManager) RevokeAllUserSessions(userID uint, revokedBy string) error {
	query := `UPDATE user_sessions SET active = 0, revoked_at = CURRENT_TIMESTAMP, revoked_by = ? WHERE user_id = ? AND active = 1`
	result, err := dm.db.Exec(query, revokedBy, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke user sessions: %v", err)
	}
	
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		fmt.Printf("[AUTH] Revoked %d active session(s) for user ID %d by %s\n", rowsAffected, userID, revokedBy)
	}
	
	return nil
}

// CleanupExpiredSessions removes expired sessions from the database
func (dm *DatabaseManager) CleanupExpiredSessions() error {
	_, err := dm.db.Exec("DELETE FROM user_sessions WHERE expires_at < ? OR active = 0", time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %v", err)
	}
	return nil
}

// AssignAgentToUser assigns an agent to an agent-operator user
func (dm *DatabaseManager) AssignAgentToUser(userID uint, agentID string, assignedByUserID uint, notes string) error {
	// Verify user has agent-operator role
	user, err := dm.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	if user.Role != RoleAgentOperator {
		return fmt.Errorf("agent assignment only available for agent-operator role, user has role: %s", user.Role)
	}

	// Check if assignment already exists
	query := `SELECT id FROM agent_assignments WHERE user_id = ? AND agent_id = ? AND active = 1`
	var existingID int
	err = dm.db.QueryRow(query, userID, agentID).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("agent %s is already assigned to user", agentID)
	}

	// Create new assignment
	insertQuery := `
		INSERT INTO agent_assignments (user_id, agent_id, assigned_by_user_id, notes)
		VALUES (?, ?, ?, ?)
	`

	_, err = dm.db.Exec(insertQuery, userID, agentID, assignedByUserID, notes)
	if err != nil {
		return fmt.Errorf("failed to assign agent: %v", err)
	}

	return nil
}

// RevokeAgentFromUser revokes an agent assignment
func (dm *DatabaseManager) RevokeAgentFromUser(userID uint, agentID string, revokedByUserID uint) error {
	query := `
		UPDATE agent_assignments 
		SET active = 0, revoked_at = CURRENT_TIMESTAMP, revoked_by_user_id = ?
		WHERE user_id = ? AND agent_id = ? AND active = 1
	`

	result, err := dm.db.Exec(query, revokedByUserID, userID, agentID)
	if err != nil {
		return fmt.Errorf("failed to revoke agent assignment: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no active assignment found for user %d and agent %s", userID, agentID)
	}

	return nil
}

// GetUserAssignedAgents returns all agents assigned to a user
func (dm *DatabaseManager) GetUserAssignedAgents(userID uint) ([]string, error) {
	query := `
		SELECT agent_id FROM agent_assignments 
		WHERE user_id = ? AND active = 1
		ORDER BY assigned_at DESC
	`

	rows, err := dm.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query assigned agents: %v", err)
	}
	defer rows.Close()

	var agentIDs []string
	for rows.Next() {
		var agentID string
		err := rows.Scan(&agentID)
		if err != nil {
			return nil, fmt.Errorf("failed to scan agent ID: %v", err)
		}
		agentIDs = append(agentIDs, agentID)
	}

	return agentIDs, nil
}

// HasAgentAccess checks if a user has access to a specific agent
func (dm *DatabaseManager) HasAgentAccess(userID uint, agentID string) (bool, error) {
	user, err := dm.GetUserByID(userID)
	if err != nil {
		return false, err
	}

	// Inactive users have no access
	if !user.Active {
		return false, nil
	}

	// Admin and operator roles have access to all agents
	if user.Role == RoleAdmin || user.Role == RoleOperator {
		return true, nil
	}

	// agent-operator role only has access to assigned agents
	if user.Role == RoleAgentOperator {
		query := `
			SELECT COUNT(*) FROM agent_assignments 
			WHERE user_id = ? AND agent_id = ? AND active = 1
		`
		var count int
		err := dm.db.QueryRow(query, userID, agentID).Scan(&count)
		if err != nil {
			return false, fmt.Errorf("failed to check agent assignment: %v", err)
		}
		return count > 0, nil
	}

	// Unknown role has no access
	return false, nil
}

// GetUserByID retrieves a user by ID (used for admin operations, returns any user regardless of active status)
func (dm *DatabaseManager) GetUserByID(userID uint) (*User, error) {
	query := `
		SELECT id, username, password_hash, salt, role, active, created_at, last_login, created_by,
		       failed_login_attempts, account_locked_until, password_changed_at, 
		       session_timeout_minutes, max_concurrent_sessions
		FROM users 
		WHERE id = ?
	`

	var user User
	var lastLogin sql.NullTime
	var accountLockedUntil sql.NullTime

	err := dm.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Salt, &user.Role, &user.Active,
		&user.CreatedAt, &lastLogin, &user.CreatedBy, &user.FailedLoginAttempts,
		&accountLockedUntil, &user.PasswordChangedAt, &user.SessionTimeoutMinutes, &user.MaxConcurrentSessions,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}
	if accountLockedUntil.Valid {
		user.AccountLockedUntil = &accountLockedUntil.Time
	}

	return &user, nil
}

// Close closes the database connection
func (dm *DatabaseManager) Close() error {
	return dm.db.Close()
}

// GetDB returns the underlying database instance
func (dm *DatabaseManager) GetDB() *sql.DB {
	return dm.db
}

// LogAdminAction logs an administrative action for audit purposes
func (dm *DatabaseManager) LogAdminAction(adminUserID uint, action, details string) error {
	query := `
		INSERT INTO admin_actions (admin_user_id, action, details)
		VALUES (?, ?, ?)
	`

	_, err := dm.db.Exec(query, adminUserID, action, details)
	if err != nil {
		return fmt.Errorf("failed to log admin action: %v", err)
	}

	return nil
}

// DeleteUser deletes a user from the database (includes cascade deletion of agent assignments)
func (dm *DatabaseManager) DeleteUser(username string) error {
	// Start transaction for atomic deletion
	tx, err := dm.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Check if user exists and get user ID
	var userID int64
	err = tx.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("user not found")
		}
		return fmt.Errorf("failed to find user: %v", err)
	}

	// Delete agent assignments (cascade)
	_, err = tx.Exec("DELETE FROM agent_assignments WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete agent assignments: %v", err)
	}

	// Delete admin actions (cascade)
	_, err = tx.Exec("DELETE FROM admin_actions WHERE admin_user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete admin actions: %v", err)
	}

	// Delete user sessions
	_, err = tx.Exec("DELETE FROM user_sessions WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %v", err)
	}

	// Delete the user
	result, err := tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	// Commit transaction
	return tx.Commit()
}
