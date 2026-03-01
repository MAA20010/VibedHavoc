package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AuthConfig represents the configuration for the authentication system
type AuthConfig struct {
	// Database configuration
	DatabasePath string `json:"database_path"`
	DatabaseType string `json:"database_type"` // "sqlite" for now

	// Session configuration
	DefaultSessionTimeout  int `json:"default_session_timeout"` // minutes
	MaxConcurrentSessions  int `json:"max_concurrent_sessions"`
	SessionCleanupInterval int `json:"session_cleanup_interval"` // minutes

	// Password policy
	MinPasswordLength   int  `json:"min_password_length"`
	RequireSpecialChars bool `json:"require_special_chars"`
	RequireNumbers      bool `json:"require_numbers"`
	RequireUppercase    bool `json:"require_uppercase"`
	RequireLowercase    bool `json:"require_lowercase"`

	// Account lockout policy
	MaxFailedAttempts      int `json:"max_failed_attempts"`
	LockoutDurationMinutes int `json:"lockout_duration_minutes"`

	// Security settings
	ForcePasswordChange bool `json:"force_password_change"`
	PasswordHistorySize int  `json:"password_history_size"`

	// Backward compatibility
	EnableProfileFallback bool   `json:"enable_profile_fallback"`
	ProfilePath           string `json:"profile_path"`

	// Logging
	LogAuthAttempts bool   `json:"log_auth_attempts"`
	LogLevel        string `json:"log_level"` // "debug", "info", "warn", "error"
}

// DefaultAuthConfig returns a default configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		DatabasePath:           "./auth.db",
		DatabaseType:           "sqlite",
		DefaultSessionTimeout:  480, // 8 hours
		MaxConcurrentSessions:  5,
		SessionCleanupInterval: 60, // 1 hour
		MinPasswordLength:      8,
		RequireSpecialChars:    true,
		RequireNumbers:         true,
		RequireUppercase:       true,
		RequireLowercase:       true,
		MaxFailedAttempts:      5,
		LockoutDurationMinutes: 30,
		ForcePasswordChange:    false,
		PasswordHistorySize:    5,
		EnableProfileFallback:  true,
		ProfilePath:            "./profiles",
		LogAuthAttempts:        true,
		LogLevel:               "info",
	}
}

// LoadAuthConfig loads configuration from a JSON file
func LoadAuthConfig(configPath string) (*AuthConfig, error) {
	config := DefaultAuthConfig()

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config file
		err = config.SaveToFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create default config: %v", err)
		}
		fmt.Printf("[AUTH] Created default configuration file: %s\n", configPath)
		return config, nil
	}

	// Read existing config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Validate configuration
	err = config.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// SaveToFile saves the configuration to a JSON file
func (c *AuthConfig) SaveToFile(configPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Write to file
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// Validate validates the configuration values
func (c *AuthConfig) Validate() error {
	if c.DatabasePath == "" {
		return fmt.Errorf("database_path cannot be empty")
	}

	if c.DefaultSessionTimeout <= 0 {
		return fmt.Errorf("default_session_timeout must be positive")
	}

	if c.MaxConcurrentSessions <= 0 {
		return fmt.Errorf("max_concurrent_sessions must be positive")
	}

	if c.MinPasswordLength < 4 {
		return fmt.Errorf("min_password_length must be at least 4")
	}

	if c.MaxFailedAttempts <= 0 {
		return fmt.Errorf("max_failed_attempts must be positive")
	}

	if c.LockoutDurationMinutes <= 0 {
		return fmt.Errorf("lockout_duration_minutes must be positive")
	}

	return nil
}

// GetDatabasePath returns the absolute path to the database
func (c *AuthConfig) GetDatabasePath() string {
	if filepath.IsAbs(c.DatabasePath) {
		return c.DatabasePath
	}

	// Make relative to current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return c.DatabasePath
	}

	return filepath.Join(cwd, c.DatabasePath)
}

// IsPasswordPolicyStrict returns true if the password policy is considered strict
func (c *AuthConfig) IsPasswordPolicyStrict() bool {
	return c.MinPasswordLength >= 12 &&
		c.RequireSpecialChars &&
		c.RequireNumbers &&
		c.RequireUppercase &&
		c.RequireLowercase
}

// GetPasswordRequirements returns a human-readable description of password requirements
func (c *AuthConfig) GetPasswordRequirements() string {
	requirements := fmt.Sprintf("Password must be at least %d characters long", c.MinPasswordLength)

	var additional []string
	if c.RequireUppercase {
		additional = append(additional, "uppercase letters")
	}
	if c.RequireLowercase {
		additional = append(additional, "lowercase letters")
	}
	if c.RequireNumbers {
		additional = append(additional, "numbers")
	}
	if c.RequireSpecialChars {
		additional = append(additional, "special characters")
	}

	if len(additional) > 0 {
		requirements += " and must include "
		for i, req := range additional {
			if i == len(additional)-1 && len(additional) > 1 {
				requirements += " and " + req
			} else if i > 0 {
				requirements += ", " + req
			} else {
				requirements += req
			}
		}
	}

	return requirements + "."
}
