package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
)

const (
	// Argon2id parameters
	ArgonTime    = 1         // Number of iterations
	ArgonMemory  = 64 * 1024 // Memory usage in KB (64MB)
	ArgonThreads = 4         // Number of threads
	ArgonKeyLen  = 32        // Length of derived key
	SaltLength   = 32        // Salt length in bytes
)

// GenerateSalt creates a random salt for password hashing
func GenerateSalt() (string, error) {
	salt := make([]byte, SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// HashPasswordArgon2id hashes a password using Argon2id (secure method)
func HashPasswordArgon2id(password, salt string) (string, error) {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return "", fmt.Errorf("failed to decode salt: %v", err)
	}

	hash := argon2.IDKey([]byte(password), saltBytes, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
	return base64.StdEncoding.EncodeToString(hash), nil
}

// VerifyPassword is a general password verification function
// It automatically detects the hash type and uses the appropriate verification method
func VerifyPassword(password, hash, salt string) (bool, error) {
	if salt == "" {
		// Legacy SHA3 hash (no salt)
		return VerifyPasswordSHA3(password, hash), nil
	}

	// Modern Argon2id hash with salt
	return VerifyPasswordArgon2id(password, salt, hash), nil
}

// VerifyPasswordArgon2id verifies a password against its Argon2id hash
func VerifyPasswordArgon2id(password, salt, hash string) bool {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false
	}

	hashBytes, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), saltBytes, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(hashBytes, computedHash) == 1
}

// HashPasswordSHA3 hashes a password using SHA3-256 (legacy method for profile compatibility)
func HashPasswordSHA3(password string) string {
	hash := sha3.New256()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyPasswordSHA3 verifies a password against its SHA3 hash (legacy method)
func VerifyPasswordSHA3(password, hash string) bool {
	computedHash := HashPasswordSHA3(password)
	return subtle.ConstantTimeCompare([]byte(hash), []byte(computedHash)) == 1
}

// HashPasswordBcrypt hashes a SHA3 hash using bcrypt (for client compatibility)
func HashPasswordBcrypt(sha3Hash string) (string, error) {
	// Use cost 10 for optimal security vs performance balance in C2 operations
	// Cost 10 = ~100ms vs cost 12 = ~400ms, still cryptographically sound
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(sha3Hash), 10)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %v", err)
	}
	return string(hashedBytes), nil
}

// VerifyPasswordBcrypt verifies a SHA3 hash against its bcrypt hash
func VerifyPasswordBcrypt(sha3Hash, bcryptHash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(sha3Hash))
	return err == nil
}

// CreateUser creates a new user with secure password hashing
func CreateUser(username, password, role, createdBy string) (*User, error) {
	if username == "" || password == "" {
		return nil, errors.New("username and password are required")
	}

	if role != "admin" && role != "operator" {
		return nil, errors.New("role must be 'admin' or 'operator'")
	}

	salt, err := GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	passwordHash, err := HashPasswordArgon2id(password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	user := &User{
		Username:              username,
		PasswordHash:          passwordHash,
		Salt:                  salt,
		Role:                  role,
		Active:                true,
		CreatedBy:             createdBy,
		PasswordChangedAt:     time.Now(),
		SessionTimeoutMinutes: 480, // 8 hours
		MaxConcurrentSessions: 3,
		FailedLoginAttempts:   0,
	}

	return user, nil
}
