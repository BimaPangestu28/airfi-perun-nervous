package auth

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims for WiFi access.
type Claims struct {
	SessionID string `json:"session_id"`
	ChannelID string `json:"channel_id"`
	jwt.RegisteredClaims
}

// JWTService handles JWT generation and validation.
type JWTService struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
}

// NewJWTService creates a new JWT service with the given key pair.
func NewJWTService(keyPair *KeyPair, issuer string) *JWTService {
	return &JWTService{
		privateKey: keyPair.PrivateKey,
		publicKey:  keyPair.PublicKey,
		issuer:     issuer,
	}
}

// NewJWTServiceFromKeys creates a JWT service from separate keys.
func NewJWTServiceFromKeys(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, issuer string) *JWTService {
	return &JWTService{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
	}
}

// GenerateToken creates a signed JWT for a session.
func (s *JWTService) GenerateToken(sessionID, channelID string, duration time.Duration) (string, error) {
	now := time.Now()

	claims := &Claims{
		SessionID: sessionID,
		ChannelID: channelID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   sessionID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// ValidateToken verifies a JWT and returns the claims.
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// RefreshToken creates a new token with extended expiration.
func (s *JWTService) RefreshToken(tokenString string, additionalDuration time.Duration) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", fmt.Errorf("failed to validate existing token: %w", err)
	}

	// Calculate new expiration
	currentExpiry := claims.ExpiresAt.Time
	newExpiry := currentExpiry.Add(additionalDuration)

	return s.GenerateToken(claims.SessionID, claims.ChannelID, time.Until(newExpiry))
}

// IsExpired checks if a token is expired.
func (s *JWTService) IsExpired(tokenString string) bool {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return true
	}

	return time.Now().After(claims.ExpiresAt.Time)
}

// GetRemainingTime returns the remaining validity time for a token.
func (s *JWTService) GetRemainingTime(tokenString string) (time.Duration, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return 0, err
	}

	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < 0 {
		return 0, nil
	}

	return remaining, nil
}
