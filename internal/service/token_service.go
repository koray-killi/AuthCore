package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/config"
	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/repository"
)

// TokenService handles JWT access tokens and refresh token session management.
type TokenService struct {
	jwtCfg      config.JWTConfig
	sessionRepo repository.SessionRepository
}

// NewTokenService creates a new TokenService.
func NewTokenService(jwtCfg config.JWTConfig, sessionRepo repository.SessionRepository) *TokenService {
	return &TokenService{
		jwtCfg:      jwtCfg,
		sessionRepo: sessionRepo,
	}
}

// TokenPair holds the generated access and refresh tokens.
type TokenPair struct {
	AccessToken  string
	RefreshToken string // raw token, to be sent to the client; never stored
	SessionID    uuid.UUID
	ExpiresAt    time.Time // refresh token expiry
}

// GenerateAccessToken creates a signed JWT access token with standard claims.
func (s *TokenService) GenerateAccessToken(userID uuid.UUID, role string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  userID.String(),
		"role": role,
		"iat":  now.Unix(),
		"exp":  now.Add(s.jwtCfg.AccessExpiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtCfg.Secret))
}

// ValidateAccessToken parses and validates a JWT access token, returning the claims.
func (s *TokenService) ValidateAccessToken(tokenStr string) (uuid.UUID, string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.jwtCfg.Secret), nil
	})
	if err != nil {
		return uuid.Nil, "", domain.ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return uuid.Nil, "", domain.ErrTokenInvalid
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, "", domain.ErrTokenInvalid
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil, "", domain.ErrTokenInvalid
	}

	role, _ := claims["role"].(string)

	return userID, role, nil
}

// IssueTokenPair generates both an access and refresh token, creating a new session in the database.
func (s *TokenService) IssueTokenPair(ctx context.Context, userID uuid.UUID, role, userAgent, ip string) (*TokenPair, error) {
	accessToken, err := s.GenerateAccessToken(userID, role)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// Generate cryptographically secure raw refresh token.
	rawRefresh, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// Store only the SHA-256 hash of the refresh token.
	tokenHash := HashToken(rawRefresh)
	sessionID := uuid.New()
	expiresAt := time.Now().Add(s.jwtCfg.RefreshExpiry)

	session := &domain.RefreshSession{
		ID:        sessionID,
		UserID:    userID,
		TokenHash: tokenHash,
		UserAgent: userAgent,
		IP:        ip,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		SessionID:    sessionID,
		ExpiresAt:    expiresAt,
	}, nil
}

// RotateRefreshToken verifies the old refresh token, revokes the old session,
// creates a new session, and links them via replaced_by. If the old token has
// already been revoked, this is a REUSE ATTACK — all user sessions are revoked.
func (s *TokenService) RotateRefreshToken(ctx context.Context, oldRawToken, userAgent, ip string) (*TokenPair, uuid.UUID, error) {
	oldHash := HashToken(oldRawToken)

	session, err := s.sessionRepo.GetByTokenHash(ctx, oldHash)
	if err != nil {
		return nil, uuid.Nil, domain.ErrTokenInvalid
	}

	// REUSE DETECTION: if this session is already revoked, an attacker is replaying
	// a stolen token. Revoke ALL sessions for this user as a security precaution.
	if session.IsRevoked() {
		_ = s.sessionRepo.RevokeAllByUserID(ctx, session.UserID)
		return nil, session.UserID, domain.ErrTokenRevoked
	}

	if session.IsExpired() {
		return nil, uuid.Nil, domain.ErrTokenExpired
	}

	// Revoke the old session.
	if err := s.sessionRepo.RevokeByID(ctx, session.ID); err != nil {
		return nil, uuid.Nil, fmt.Errorf("revoke old session: %w", err)
	}

	// Issue a new token pair.
	pair, err := s.IssueTokenPair(ctx, session.UserID, "", userAgent, ip)
	if err != nil {
		return nil, uuid.Nil, err
	}

	// Link old session to the new one.
	if err := s.sessionRepo.MarkReplacedBy(ctx, session.ID, pair.SessionID); err != nil {
		return nil, uuid.Nil, fmt.Errorf("mark replaced: %w", err)
	}

	return pair, session.UserID, nil
}

// RevokeSession revokes a single session by its token hash.
func (s *TokenService) RevokeSession(ctx context.Context, rawToken string) error {
	tokenHash := HashToken(rawToken)
	session, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return domain.ErrTokenInvalid
	}
	return s.sessionRepo.RevokeByID(ctx, session.ID)
}

// RevokeAllSessions revokes all active sessions for a user.
func (s *TokenService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	return s.sessionRepo.RevokeAllByUserID(ctx, userID)
}

// generateRefreshToken creates a cryptographically secure random token.
func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
