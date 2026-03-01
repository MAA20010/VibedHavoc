package main

import (
	"fmt"
	"log"

	"Havoc/pkg/auth"
)

// Example usage of the authentication system
func main() {
	fmt.Println("=== Havoc Authentication System Demo ===")

	// Load configuration
	config, err := auth.LoadAuthConfig("./auth_config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("Configuration loaded: Database at %s\n", config.GetDatabasePath())

	// Initialize authentication service
	authService, err := auth.NewAuthService(config.GetDatabasePath())
	if err != nil {
		log.Fatalf("Failed to initialize auth service: %v", err)
	}
	defer authService.Close()

	fmt.Println("Authentication service initialized")

	// List existing users
	users, err := authService.GetAllUsers()
	if err != nil {
		log.Printf("Warning: Failed to get users: %v", err)
	} else {
		fmt.Printf("Found %d existing users:\n", len(users))
		for _, user := range users {
			fmt.Printf("  - %s (%s)\n", user.Username, user.Role)
		}
	}

	// Demo authentication flow
	demoAuthentication(authService)

	// Demo user creation (if we had admin privileges)
	demoUserManagement(authService)

	fmt.Println("Demo completed successfully!")
}

func demoAuthentication(authService *auth.AuthService) {
	fmt.Println("\n=== Authentication Demo ===")

	// Try to authenticate with default admin (if it exists)
	session, err := authService.Authenticate("admin", "incorrect_password", "127.0.0.1", "Demo Client")
	if err != nil {
		fmt.Printf("Expected failure: %v\n", err)
	} else {
		fmt.Printf("Unexpected success: %+v\n", session)
	}

	// Note: In a real scenario, you would use the actual admin password
	fmt.Println("Note: To test successful authentication, use the admin password shown during service initialization")
}

func demoUserManagement(authService *auth.AuthService) {
	fmt.Println("\n=== User Management Demo ===")

	// This would require admin session ID in practice
	fmt.Println("User management operations require admin privileges")
	fmt.Println("In practice, you would:")
	fmt.Println("1. Authenticate as admin to get a session")
	fmt.Println("2. Use that session ID to create/manage users")
	fmt.Println("3. Validate permissions before each operation")
}

// Example of how to integrate with existing Havoc code
func exampleIntegration() {
	fmt.Println("\n=== Integration Example ===")

	// This shows how the new auth system integrates
	// with pure database authentication

	// Create database auth wrapper
	wrapper, err := auth.NewDatabaseAuthWrapper("./auth.db")
	if err != nil {
		log.Printf("Failed to create compatibility wrapper: %v", err)
		return
	}
	defer wrapper.Close()

	// Test authentication with both systems
	session, err := wrapper.AuthenticateUser("admin", "some_password", "127.0.0.1", "Integration Test")
	if err != nil {
		fmt.Printf("Authentication attempt failed: %v\n", err)
	} else {
		fmt.Printf("Authentication successful: %s (%s)\n", session.User.Username, session.LoginMethod)
	}

	fmt.Println("Integration wrapper ready for production use")
}
