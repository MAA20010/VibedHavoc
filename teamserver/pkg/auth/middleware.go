package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Middleware provides HTTP authentication middleware
type Middleware struct {
	authService *AuthService
}

// NewMiddleware creates a new authentication middleware
func NewMiddleware(authService *AuthService) *Middleware {
	return &Middleware{
		authService: authService,
	}
}

// RequireAuth is a middleware that requires authentication
func (m *Middleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := m.getSessionFromRequest(r)
		if err != nil {
			m.sendUnauthorized(w, err.Error())
			return
		}

		// Add session to request context for use in handlers
		ctx := r.Context()
		ctx = SetSessionInContext(ctx, session)
		r = r.WithContext(ctx)

		next(w, r)
	}
}

// RequireRole is a middleware that requires a specific role
func (m *Middleware) RequireRole(role string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			session, err := m.getSessionFromRequest(r)
			if err != nil {
				m.sendUnauthorized(w, err.Error())
				return
			}

			if session.User.Role != role {
				m.sendForbidden(w, fmt.Sprintf("role %s required", role))
				return
			}

			// Add session to request context
			ctx := r.Context()
			ctx = SetSessionInContext(ctx, session)
			r = r.WithContext(ctx)

			next(w, r)
		}
	}
}

// RequirePermission is a middleware that requires a specific permission
func (m *Middleware) RequirePermission(permission string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			session, err := m.getSessionFromRequest(r)
			if err != nil {
				m.sendUnauthorized(w, err.Error())
				return
			}

			if !session.User.HasPermission(permission) {
				m.sendForbidden(w, fmt.Sprintf("permission %s required", permission))
				return
			}

			// Add session to request context
			ctx := r.Context()
			ctx = SetSessionInContext(ctx, session)
			r = r.WithContext(ctx)

			next(w, r)
		}
	}
}

// RequireAdmin is a middleware that requires admin role
func (m *Middleware) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return m.RequireRole(RoleAdmin)(next)
}

// getSessionFromRequest extracts and validates session from HTTP request
func (m *Middleware) getSessionFromRequest(r *http.Request) (*UserSession, error) {
	// Try to get session ID from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Expected format: "Bearer <session_id>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			sessionID := parts[1]
			return m.authService.ValidateSession(sessionID)
		}
	}

	// Try to get session ID from cookie
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		return m.authService.ValidateSession(cookie.Value)
	}

	// Try to get session ID from query parameter (less secure, use with caution)
	sessionID := r.URL.Query().Get("session_id")
	if sessionID != "" {
		return m.authService.ValidateSession(sessionID)
	}

	return nil, fmt.Errorf("no valid session found")
}

// sendUnauthorized sends a 401 Unauthorized response
func (m *Middleware) sendUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]interface{}{
		"error":   "unauthorized",
		"message": message,
	}

	json.NewEncoder(w).Encode(response)
}

// sendForbidden sends a 403 Forbidden response
func (m *Middleware) sendForbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	response := map[string]interface{}{
		"error":   "forbidden",
		"message": message,
	}

	json.NewEncoder(w).Encode(response)
}

// LoginHandler handles user login
func (m *Middleware) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get client information
	clientIP := getClientIP(r)
	userAgent := r.UserAgent()

	// Authenticate user
	session, err := m.authService.Authenticate(loginRequest.Username, loginRequest.Password, clientIP, userAgent)
	if err != nil {
		m.sendUnauthorized(w, err.Error())
		return
	}

	// Send successful response
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"success":    true,
		"session_id": session.SessionID,
		"user": map[string]interface{}{
			"username": session.User.Username,
			"role":     session.User.Role,
		},
		"expires_at": session.ExpiresAt,
	}

	json.NewEncoder(w).Encode(response)
}

// LogoutHandler handles user logout
func (m *Middleware) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := m.getSessionFromRequest(r)
	if err != nil {
		// Even if we can't find the session, we should return success
		// to prevent information leakage
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	// Invalidate session
	err = m.authService.Logout(session.SessionID)
	if err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// UserInfoHandler returns information about the current user
func (m *Middleware) UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionFromContext(r.Context())
	if session == nil {
		m.sendUnauthorized(w, "No session found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":       session.User.ID,
			"username": session.User.Username,
			"role":     session.User.Role,
			"active":   session.User.Active,
		},
		"session": map[string]interface{}{
			"created_at":    session.CreatedAt,
			"last_activity": session.LastActivity,
			"expires_at":    session.ExpiresAt,
			"login_method":  session.LoginMethod,
		},
	}

	json.NewEncoder(w).Encode(response)
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP if there are multiple
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to remote address
	return r.RemoteAddr
}
