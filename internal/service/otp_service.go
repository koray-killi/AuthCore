// Package service contains business logic. Services depend on repository interfaces,
// never on concrete implementations. They return domain errors, never HTTP-level concerns.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/repository"
	"golang.org/x/crypto/argon2"
)

// OTPService handles one-time password generation and validation.
type OTPService struct {
	repo repository.OTPRepository
}

// NewOTPService creates a new OTPService.
func NewOTPService(repo repository.OTPRepository) *OTPService {
	return &OTPService{repo: repo}
}

// Argon2id parameters for OTP hashing (lighter than password hashing since OTPs are short-lived).
var otpArgon2Params = argon2Params{
	memory:  32 * 1024,
	time:    1,
	threads: 2,
	keyLen:  32,
	saltLen: 16,
}

// Generate creates a new 6-digit OTP, hashes it with Argon2id, stores the hash,
// and returns the plain-text code for sending via email.
func (s *OTPService) Generate(ctx context.Context, userID uuid.UUID, purpose string) (string, error) {
	// Generate cryptographically secure 6-digit code.
	code, err := generateSecureCode(6)
	if err != nil {
		return "", fmt.Errorf("generate otp code: %w", err)
	}

	// Hash the code with Argon2id before storage.
	hash, err := hashArgon2id(code, otpArgon2Params)
	if err != nil {
		return "", fmt.Errorf("hash otp code: %w", err)
	}

	otp := &domain.OTPCode{
		ID:           uuid.New(),
		UserID:       userID,
		Purpose:      purpose,
		CodeHash:     hash,
		AttemptCount: 0,
		ExpiresAt:    time.Now().Add(time.Duration(domain.OTPExpiryMins) * time.Minute),
		CreatedAt:    time.Now(),
	}

	if err := s.repo.Create(ctx, otp); err != nil {
		return "", fmt.Errorf("store otp: %w", err)
	}

	return code, nil
}

// Validate checks the OTP code against the latest valid OTP for the given user and purpose.
// It enforces expiry, attempt limits, and single use.
func (s *OTPService) Validate(ctx context.Context, userID uuid.UUID, purpose, code string) error {
	otp, err := s.repo.GetLatestValid(ctx, userID, purpose)
	if err != nil {
		return domain.ErrOTPInvalid
	}

	if otp.IsExpired() {
		return domain.ErrOTPExpired
	}

	if otp.IsMaxAttemptsReached() {
		return domain.ErrOTPMaxAttempts
	}

	// Increment attempt count before checking hash (to prevent unlimited brute-force).
	if err := s.repo.IncrementAttempt(ctx, otp.ID); err != nil {
		return fmt.Errorf("increment otp attempt: %w", err)
	}

	// Verify the hash.
	if !verifyArgon2id(code, otp.CodeHash) {
		return domain.ErrOTPInvalid
	}

	// Mark as consumed.
	if err := s.repo.Consume(ctx, otp.ID); err != nil {
		return fmt.Errorf("consume otp: %w", err)
	}

	return nil
}

// InvalidatePending expires all unconsumed OTPs for a user and purpose.
func (s *OTPService) InvalidatePending(ctx context.Context, userID uuid.UUID, purpose string) error {
	return s.repo.InvalidatePending(ctx, userID, purpose)
}

// generateSecureCode produces a cryptographically secure numeric code of the given length.
func generateSecureCode(length int) (string, error) {
	max := new(big.Int)
	max.SetString(fmt.Sprintf("1%s", repeat("0", length)), 10) // 10^length

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, n), nil
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

// argon2Params holds Argon2id parameters.
type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
	saltLen int
}

// Default Argon2id parameters for password hashing.
var passwordArgon2Params = argon2Params{
	memory:  64 * 1024,
	time:    3,
	threads: 4,
	keyLen:  32,
	saltLen: 16,
}

// hashArgon2id creates an Argon2id hash of the given plain text.
// Returns a formatted string: $argon2id$v=19$m=MEMORY,t=TIME,p=THREADS$SALT$HASH
func hashArgon2id(plain string, params argon2Params) (string, error) {
	salt := make([]byte, params.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(plain), salt, params.time, params.memory, params.threads, params.keyLen)

	saltEncoded := hex.EncodeToString(salt)
	hashEncoded := hex.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		params.memory, params.time, params.threads, saltEncoded, hashEncoded), nil
}

// verifyArgon2id verifies a plain text against an Argon2id hash string.
func verifyArgon2id(plain, encoded string) bool {
	params, salt, hash, err := parseArgon2id(encoded)
	if err != nil {
		return false
	}

	otherHash := argon2.IDKey([]byte(plain), salt, params.time, params.memory, params.threads, params.keyLen)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1
}

// parseArgon2id extracts parameters, salt, and hash from an Argon2id encoded string.
func parseArgon2id(encoded string) (argon2Params, []byte, []byte, error) {
	var params argon2Params
	var saltHex string
	var version int

	_, err := fmt.Sscanf(encoded, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s",
		&version, &params.memory, &params.time, &params.threads, &saltHex)
	if err != nil {
		return params, nil, nil, fmt.Errorf("parse argon2id: %w", err)
	}

	// Split saltHex which contains "SALT$HASH".
	parts := splitOnce(saltHex, "$")
	if len(parts) != 2 {
		return params, nil, nil, fmt.Errorf("parse argon2id: invalid format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return params, nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	hash, err := hex.DecodeString(parts[1])
	if err != nil {
		return params, nil, nil, fmt.Errorf("decode hash: %w", err)
	}

	params.keyLen = uint32(len(hash))
	params.saltLen = len(salt)

	return params, salt, hash, nil
}

func splitOnce(s, sep string) []string {
	for i := 0; i < len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return []string{s[:i], s[i+len(sep):]}
		}
	}
	return []string{s}
}

// HashPassword hashes a password using Argon2id with production parameters.
func HashPassword(password string) (string, error) {
	return hashArgon2id(password, passwordArgon2Params)
}

// VerifyPassword checks a plain password against an Argon2id hash.
func VerifyPassword(password, hash string) bool {
	return verifyArgon2id(password, hash)
}

// HashToken creates a SHA-256 hash of a refresh token for storage.
// The raw token is never stored in the database.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// ValidatePasswordStrength enforces the minimum password policy.
func ValidatePasswordStrength(password string) error {
	if len(password) < 10 {
		return domain.ErrWeakPassword
	}
	return nil
}
