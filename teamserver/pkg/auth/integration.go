package auth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	//"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

// Integration example for the Havoc teamserver
// This shows how to integrate the new authentication system

// DatabaseAuthWrapper wraps the authentication system for database-only auth
type DatabaseAuthWrapper struct {
	authService           *AuthService
	disconnectClientsFunc func(username string) int // Callback to disconnect clients
}

// NewDatabaseAuthWrapper creates a wrapper for pure database authentication
func NewDatabaseAuthWrapper(databasePath string) (*DatabaseAuthWrapper, error) {
	authService, err := NewAuthService(databasePath)
	if err != nil {
		return nil, err
	}

	wrapper := &DatabaseAuthWrapper{
		authService: authService,
	}

	// Start session cleanup routine
	authService.StartSessionCleanupRoutine()

	return wrapper, nil
}

// AuthenticateUser attempts authentication using database only
func (daw *DatabaseAuthWrapper) AuthenticateUser(username, password, clientIP, userAgent string) (*UserSession, error) {
	// Use only database authentication - no legacy fallback
	session, err := daw.authService.Authenticate(username, password, clientIP, userAgent)
	if err == nil {
		return session, nil
	}

	return nil, err
}

// createLegacySession creates a session for legacy profile-based authentication
// ValidateSession validates database sessions only
func (daw *DatabaseAuthWrapper) ValidateSession(sessionID string) (*UserSession, error) {
	// Use only database session validation
	return daw.authService.ValidateSession(sessionID)
}

// SetupAuthRoutes sets up HTTP routes for authentication
func (daw *DatabaseAuthWrapper) SetupAuthRoutes(mux *http.ServeMux) {
	middleware := NewMiddleware(daw.authService)

	// Authentication endpoints
	mux.HandleFunc("/auth/login", middleware.LoginHandler)
	mux.HandleFunc("/auth/logout", middleware.LogoutHandler)
	mux.HandleFunc("/auth/user", middleware.RequireAuth(middleware.UserInfoHandler))

	// Admin endpoints
	mux.HandleFunc("/auth/users", middleware.RequireAdmin(daw.listUsersHandler))
	mux.HandleFunc("/auth/users/create", middleware.RequireAdmin(daw.createUserHandler))
	mux.HandleFunc("/auth/users/delete", middleware.RequireAdmin(daw.deleteUserHandler))
	mux.HandleFunc("/auth/agents/assign", middleware.RequireAdmin(daw.assignAgentHandler))
	mux.HandleFunc("/auth/agents/revoke", middleware.RequireAdmin(daw.revokeAgentHandler))
}

// SetupGinAuthRoutes registers authentication routes with a Gin router
func (daw *DatabaseAuthWrapper) SetupGinAuthRoutes(router interface{}) {
	middleware := NewMiddleware(daw.authService)

	// Type assert to gin.Engine
	if ginEngine, ok := router.(*gin.Engine); ok {
		// Authentication endpoints
		log.Println("[AUTH] Registering authentication routes...")
		ginEngine.POST("/auth/login", gin.WrapF(middleware.LoginHandler))
		ginEngine.POST("/auth/logout", gin.WrapF(middleware.LogoutHandler))
		ginEngine.GET("/auth/user", gin.WrapF(middleware.RequireAuth(middleware.UserInfoHandler)))

		// WebSocket to HTTP session bridge endpoint
		ginEngine.POST("/auth/websocket-session", gin.WrapF(daw.createWebSocketSessionHandler))
		log.Println("[AUTH] Registered: POST /auth/websocket-session")

		// Admin endpoints
		ginEngine.GET("/auth/users", gin.WrapF(middleware.RequireAdmin(daw.listUsersHandler)))
		log.Println("[AUTH] Registered: GET /auth/users")
		
		ginEngine.POST("/auth/users/create", gin.WrapF(middleware.RequireAdmin(daw.createUserHandler)))
		log.Println("[AUTH] Registered: POST /auth/users/create")
		
		ginEngine.POST("/auth/users/update", gin.WrapF(middleware.RequireAdmin(daw.updateUserHandler)))
		log.Println("[AUTH] Registered: POST /auth/users/update")
		
		ginEngine.DELETE("/auth/users/delete", gin.WrapF(middleware.RequireAdmin(daw.deleteUserHandler)))
		log.Println("[AUTH] Registered: DELETE /auth/users/delete")
		
	ginEngine.POST("/auth/agents/assign", gin.WrapF(middleware.RequireAdmin(daw.assignAgentHandler)))
	ginEngine.POST("/auth/agents/revoke", gin.WrapF(middleware.RequireAdmin(daw.revokeAgentHandler)))
	ginEngine.GET("/auth/agents/assigned", gin.WrapF(middleware.RequireAdmin(daw.getAssignedAgentsHandler)))
	
	log.Println("[AUTH] All authentication routes registered successfully")
	} else {
		log.Println("[AUTH] ERROR: Router is not a *gin.Engine, routes NOT registered")
	}
}

// requireAdminUser validates that the current user is an admin
func (daw *DatabaseAuthWrapper) requireAdminUser(r *http.Request) (*User, error) {
	// Get session from context (middleware stores it with key "session")
	session := GetSessionFromContext(r.Context())
	if session == nil {
		return nil, errors.New("no session in context")
	}

	// Extract user from session
	if session.User.Role != RoleAdmin {
		return nil, errors.New("admin role required")
	}

	return &session.User, nil
}

// Example handlers for user management
func (daw *DatabaseAuthWrapper) listUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Get all users from the database
	users, err := daw.authService.GetAllUsers()
	if err != nil {
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}

	// Convert users to response format (excluding sensitive data)
	var userList []map[string]interface{}
	for _, user := range users {
		userInfo := map[string]interface{}{
			"id":         user.ID,
			"username":   user.Username,
			"role":       user.Role,
			"active":     user.Active,
			"created_at": user.CreatedAt,
			"created_by": user.CreatedBy,
		}
		userList = append(userList, userInfo)
	}

	response := map[string]interface{}{
		"success": true,
		"users":   userList,
		"count":   len(userList),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// createWebSocketSessionHandler creates HTTP session tokens for WebSocket-authenticated users
func (daw *DatabaseAuthWrapper) createWebSocketSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	// Authenticate using the same method as WebSocket (to maintain consistency)
	session, err := daw.authService.Authenticate(req.Username, req.Password, r.RemoteAddr, r.UserAgent())
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Return the session token for HTTP requests
	response := map[string]interface{}{
		"success":    true,
		"session_id": session.SessionID,
		"user":       session.User,
		"expires_at": session.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (daw *DatabaseAuthWrapper) createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Active   bool   `json:"active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	// Validate role
	if req.Role != "admin" && req.Role != "operator" && req.Role != "agent-operator" {
		http.Error(w, "Invalid role. Must be admin, operator, or agent-operator", http.StatusBadRequest)
		return
	}

	// Get admin user info for audit trail - middleware already validated admin role
	session := GetSessionFromContext(r.Context())
	var adminUsername string
	var adminUserID uint
	if session != nil && session.User.Username != "" {
		adminUsername = session.User.Username
		adminUserID = session.User.ID
	} else {
		// Fallback to unknown admin if context is not available
		adminUsername = "unknown_admin"
		adminUserID = 0  // System/unknown admin
	}

	// Hash the SHA3 password with bcrypt for secure storage
	bcryptHash, err := HashPasswordBcrypt(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Create user
	newUser, err := daw.authService.db.CreateUser(req.Username, bcryptHash, req.Role, adminUsername)
	if err != nil {
		if strings.Contains(err.Error(), "user already exists") {
			http.Error(w, "Username already exists", http.StatusConflict)
		} else {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
		}
		return
	}

	// Update active status if different from default (true)
	if !req.Active {
		newUser.Active = req.Active
		err = daw.authService.db.UpdateUser(newUser)
		if err != nil {
			http.Error(w, "Failed to set user status", http.StatusInternalServerError)
			return
		}
	}

	// Log admin action
	statusStr := "active"
	if !req.Active {
		statusStr = "inactive"
	}
	daw.authService.db.LogAdminAction(adminUserID, "CREATE_USER", fmt.Sprintf("Created user %s with role %s (%s)", req.Username, req.Role, statusStr))

	// Return success
	resp := map[string]interface{}{
		"success": true,
		"user_id": newUser.ID,
		"message": "User created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (daw *DatabaseAuthWrapper) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	// Get admin user info for audit trail - middleware already validated admin role
	session := GetSessionFromContext(r.Context())
	var adminUsername string
	var adminUserID uint
	if session != nil && session.User.Username != "" {
		adminUsername = session.User.Username
		adminUserID = session.User.ID
	} else {
		// Fallback to unknown admin if context is not available
		adminUsername = "unknown_admin"
		adminUserID = 0  // System/unknown admin
	}

	// Prevent self-deletion
	if adminUsername == req.Username {
		http.Error(w, "Cannot delete your own account", http.StatusForbidden)
		return
	}

	// Delete user (includes cascade deletion of agent assignments)
	err := daw.authService.db.DeleteUser(req.Username)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		}
		return
	}

	// Log admin action
	daw.authService.db.LogAdminAction(adminUserID, "DELETE_USER", fmt.Sprintf("Deleted user %s", req.Username))

	// Return success
	resp := map[string]interface{}{
		"success": true,
		"message": "User deleted successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (daw *DatabaseAuthWrapper) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	//startTime := time.Now()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OriginalUsername string `json:"original_username"`
		Username         string `json:"username"`
		Password         string `json:"password,omitempty"`
		Role             string `json:"role"`
		Active           bool   `json:"active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.OriginalUsername == "" {
		http.Error(w, "Original username required", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "New username required", http.StatusBadRequest)
		return
	}

	// Validate role
	if req.Role != "admin" && req.Role != "operator" && req.Role != "agent-operator" {
		http.Error(w, "Invalid role. Must be admin, operator, or agent-operator", http.StatusBadRequest)
		return
	}

	// Get admin user info for audit trail - middleware already validated admin role
	session := GetSessionFromContext(r.Context())
	var adminUsername string
	var adminUserID uint
	if session != nil && session.User.Username != "" {
		adminUsername = session.User.Username
		adminUserID = session.User.ID
		// Prevent role change if modifying self (admin shouldn't demote themselves)
		if session.User.Username == req.OriginalUsername && req.Role != "admin" {
			http.Error(w, "Cannot change your own role from admin", http.StatusForbidden)
			return
		}
	} else {
		// Fallback to unknown admin if context is not available
		adminUsername = "unknown_admin"
		adminUserID = 0  // System/unknown admin
	}

	// Get existing user to verify it exists (including inactive users for admin operations)
	existingUser, err := daw.authService.db.GetUserByUsernameAny(req.OriginalUsername)
	if err != nil {
		if strings.Contains(err.Error(), "user not found") {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to retrieve user", http.StatusInternalServerError)
		}
		return
	}

	// Prevent role change if modifying self (admin shouldn't demote themselves)
	if adminUsername == req.OriginalUsername && req.Role != "admin" {
		http.Error(w, "Cannot change your own role from admin", http.StatusForbidden)
		return
	}

	// Prevent deactivating self
	if adminUsername == req.OriginalUsername && !req.Active {
		http.Error(w, "Cannot deactivate your own account", http.StatusForbidden)
		return
	}

	// Check if new username is already taken (if username is being changed)
	if req.Username != req.OriginalUsername {
		_, err := daw.authService.db.GetUserByUsernameAny(req.Username)
		if err == nil {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	// Update user data
	updatedUser := &User{
		ID:                    existingUser.ID, // Keep original ID for database update
		Username:              req.Username,
		Role:                  req.Role,
		Active:                req.Active,
		CreatedBy:             existingUser.CreatedBy, // Keep original creator
		CreatedAt:             existingUser.CreatedAt, // Keep original creation time
		Salt:                  existingUser.Salt,      // Keep original salt
		FailedLoginAttempts:   existingUser.FailedLoginAttempts,
		AccountLockedUntil:    existingUser.AccountLockedUntil,
		SessionTimeoutMinutes: existingUser.SessionTimeoutMinutes,
		MaxConcurrentSessions: existingUser.MaxConcurrentSessions,
	}

	// Update password if provided
	if req.Password != "" {
		// Hash the SHA3 password with bcrypt for secure storage
		bcryptHash, err := HashPasswordBcrypt(req.Password)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		updatedUser.PasswordHash = bcryptHash
	} else {
		updatedUser.PasswordHash = existingUser.PasswordHash // Keep existing password
	}

	// Perform the update
	err = daw.authService.db.UpdateUser(updatedUser)
	if err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	// Revoke all sessions if user is deactivated or role changed
	// This forces immediate logout and re-authentication with new permissions
	shouldRevokeSessions := false
	if req.Active != existingUser.Active && !req.Active {
		// User was deactivated
		shouldRevokeSessions = true
	}
	if req.Role != existingUser.Role {
		// Role changed (privilege escalation or demotion)
		shouldRevokeSessions = true
	}
	
	if shouldRevokeSessions {
		err = daw.authService.db.RevokeAllUserSessions(existingUser.ID, adminUsername)
		if err != nil {
			// Log error but don't fail the request
			fmt.Printf("[AUTH] Warning: Failed to revoke sessions for user %s: %v\n", req.OriginalUsername, err)
		} else {
			fmt.Printf("[AUTH] Revoked all sessions for user %s (deactivated or role changed)\n", req.OriginalUsername)
		}
		
		// Force disconnect all active clients for this user
		if daw.disconnectClientsFunc != nil {
			disconnected := daw.disconnectClientsFunc(req.OriginalUsername)
			if disconnected > 0 {
				fmt.Printf("[AUTH] Force disconnected %d client(s) for user %s\n", disconnected, req.OriginalUsername)
			}
		}
	}

	// Build audit log message
	changes := []string{}
	if req.Username != req.OriginalUsername {
		changes = append(changes, fmt.Sprintf("username: %s -> %s", req.OriginalUsername, req.Username))
	}
	if req.Role != existingUser.Role {
		changes = append(changes, fmt.Sprintf("role: %s -> %s", existingUser.Role, req.Role))
	}
	if req.Active != existingUser.Active {
		activeStr := map[bool]string{true: "active", false: "inactive"}
		changes = append(changes, fmt.Sprintf("status: %s -> %s", activeStr[existingUser.Active], activeStr[req.Active]))
	}
	if req.Password != "" {
		changes = append(changes, "password changed")
	}

	logMessage := fmt.Sprintf("Updated user %s: %s", req.OriginalUsername, strings.Join(changes, ", "))

	// Log admin action asynchronously to avoid blocking response
	go func() {
		daw.authService.db.LogAdminAction(adminUserID, "UPDATE_USER", logMessage)
	}()

	// Return success immediately
	resp := map[string]interface{}{
		"success": true,
		"message": "User updated successfully",
		"user": map[string]interface{}{
			"username": updatedUser.Username,
			"role":     updatedUser.Role,
			"active":   updatedUser.Active,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	// Log timing for performance debugging
	//log.Printf("UpdateUser request completed in %v", time.Since(startTime))
}

func (daw *DatabaseAuthWrapper) assignAgentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		AgentID  string `json:"agent_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.AgentID == "" {
		http.Error(w, "Username and agent_id required", http.StatusBadRequest)
		return
	}

	// Get admin user info for audit trail and verify admin role
	adminUser, err := daw.requireAdminUser(r)
	if err != nil {
		http.Error(w, "Admin role required", http.StatusForbidden)
		return
	}

	// Get target user (including inactive users - admins can manage all users)
	targetUser, err := daw.authService.db.GetUserByUsernameAny(req.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Only allow assignment to agent-operators (admins and operators have access to all agents)
	if targetUser.Role != RoleAgentOperator {
		http.Error(w, "Can only assign agents to users with agent-operator role", http.StatusBadRequest)
		return
	}

	// Assign agent
	err = daw.authService.db.AssignAgentToUser(targetUser.ID, req.AgentID, adminUser.ID, fmt.Sprintf("Assigned by %s", adminUser.Username))
	if err != nil {
		// Log the actual error for debugging
		log.Printf("[ERROR] AssignAgentToUser failed: %v", err)
		
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Agent already assigned to this user", http.StatusConflict)
		} else if strings.Contains(err.Error(), "already assigned") {
			http.Error(w, err.Error(), http.StatusConflict)
		} else {
			http.Error(w, fmt.Sprintf("Failed to assign agent: %v", err), http.StatusInternalServerError)
		}
		return
	}

	// Log admin action
	daw.authService.db.LogAdminAction(adminUser.ID, "ASSIGN_AGENT", fmt.Sprintf("Assigned agent %s to user %s", req.AgentID, req.Username))

	// Return success
	resp := map[string]interface{}{
		"success": true,
		"message": "Agent assigned successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (daw *DatabaseAuthWrapper) revokeAgentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		AgentID  string `json:"agent_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.AgentID == "" {
		http.Error(w, "Username and agent_id required", http.StatusBadRequest)
		return
	}

	// Get admin user info for audit trail and verify admin role
	adminUser, err := daw.requireAdminUser(r)
	if err != nil {
		http.Error(w, "Admin role required", http.StatusForbidden)
		return
	}

	// Get target user (including inactive users - admins can manage all users)
	targetUser, err := daw.authService.db.GetUserByUsernameAny(req.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Revoke agent assignment
	err = daw.authService.db.RevokeAgentFromUser(targetUser.ID, req.AgentID, adminUser.ID)
	if err != nil {
		http.Error(w, "Failed to revoke agent assignment", http.StatusInternalServerError)
		return
	}

	// Log admin action
	daw.authService.db.LogAdminAction(adminUser.ID, "REVOKE_AGENT", fmt.Sprintf("Revoked agent %s from user %s", req.AgentID, req.Username))

	// Return success
	resp := map[string]interface{}{
		"success": true,
		"message": "Agent assignment revoked successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (daw *DatabaseAuthWrapper) getAssignedAgentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get username from query parameter
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username query parameter required", http.StatusBadRequest)
		return
	}

	// Get admin user info for audit trail and verify admin role
	_, err := daw.requireAdminUser(r)
	if err != nil {
		http.Error(w, "Admin role required", http.StatusForbidden)
		return
	}

	// Get target user (including inactive users - admins can view assignments for all users)
	targetUser, err := daw.authService.db.GetUserByUsernameAny(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Get assigned agents
	agentIDs, err := daw.authService.db.GetUserAssignedAgents(targetUser.ID)
	if err != nil {
		http.Error(w, "Failed to get assigned agents", http.StatusInternalServerError)
		return
	}

	// Return agent IDs
	resp := map[string]interface{}{
		"success":   true,
		"agent_ids": agentIDs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CheckAgentAccess checks if a user has access to a specific agent
func (daw *DatabaseAuthWrapper) CheckAgentAccess(userID uint, agentID string) (bool, error) {
	return daw.authService.db.HasAgentAccess(userID, agentID)
}

// RefreshSessionForConnectedClient creates a new session for a user whose session expired but WebSocket is still connected
// This prevents session expiry from disrupting long-running operations
func (daw *DatabaseAuthWrapper) RefreshSessionForConnectedClient(username, clientIP, userAgent string) (*UserSession, error) {
	// Get user from database (must be active)
	user, err := daw.authService.db.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("user not found or inactive: %v", err)
	}
	
	// Generate new session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}
	
	// Create client fingerprint
	fingerprint := generateClientFingerprint(clientIP, userAgent)
	
	// Create new session in database
	session, err := daw.authService.db.CreateSession(user.ID, sessionID, clientIP, userAgent, fingerprint, user.SessionTimeoutMinutes)
	if err != nil {
		return nil, fmt.Errorf("failed to create refreshed session: %v", err)
	}
	
	// Populate session with user data
	session.User = *user
	
	fmt.Printf("[AUTH] Refreshed expired session for connected user %s (new session: %s)\n", username, sessionID)
	
	return session, nil
}

// SetDisconnectClientsCallback sets the callback function to disconnect clients
func (daw *DatabaseAuthWrapper) SetDisconnectClientsCallback(callback func(username string) int) {
	daw.disconnectClientsFunc = callback
}

// Close closes the authentication system
func (daw *DatabaseAuthWrapper) Close() error {
	return daw.authService.Close()
}

// Migration utility to help migrate from profiles to database
func (daw *DatabaseAuthWrapper) MigrateProfileToDatabase(username, password, role string) error {
	// This function could be used to migrate existing profile users
	// to the new database system

	_, err := daw.authService.CreateUser("system", username, password, role)
	if err != nil {
		log.Printf("[AUTH] Failed to migrate user %s: %v", username, err)
		return err
	}

	log.Printf("[AUTH] Successfully migrated user %s to database", username)
	return nil
}

// MigrateHashedProfileUser migrates a user with bcrypt-secured SHA3 hashing
func (daw *DatabaseAuthWrapper) MigrateHashedProfileUser(username, profilePassword, role string) error {
	// Check if user already exists in database
	_, err := daw.authService.db.GetUserByUsername(username)
	if err == nil {
		// User already exists, skip migration
		log.Printf("[AUTH] User %s already exists in database, skipping migration", username)
		return fmt.Errorf("user already exists")
	}

	// Hash the profile password with SHA3 (like the profile system does)
	passHash := sha3.New256()
	passHash.Write([]byte(profilePassword))
	sha3Hash := hex.EncodeToString(passHash.Sum(nil))

	// Then bcrypt the SHA3 hash for secure storage (proper bcrypt format)
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(sha3Hash), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[AUTH] Failed to bcrypt hash for user %s: %v", username, err)
		return fmt.Errorf("failed to create secure hash: %v", err)
	}

	// Create user with the bcrypt hash
	_, err = daw.authService.db.CreateUser(username, string(bcryptHash), role, "system")
	if err != nil {
		log.Printf("[AUTH] Failed to migrate user %s: %v", username, err)
		return fmt.Errorf("migration failed: %v", err)
	}

	log.Printf("[AUTH] Successfully migrated user %s from profile to database with bcrypt security", username)
	return nil
}

// GetAuthService returns the underlying auth service for advanced operations
func (daw *DatabaseAuthWrapper) GetAuthService() *AuthService {
	return daw.authService
}
