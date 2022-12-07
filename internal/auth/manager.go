package auth

import (
  "time"
  "fmt"
  "github.com/dgrijalva/jwt-go"
  "github.com/google/uuid"
)

const claimId = "sub"

type TokenManager interface {
  NewJWT(id string, ttl time.Duration) (string, error)
  Parse(accessToken string) (string, error)
  NewRefreshToken() (string, error)
}

type Manager struct {
  signInKey string
}

func NewManager(signInKey string) (*Manager, error) {
  if signInKey == "" {
    return nil, fmt.Errorf("sign in key is mandatory")
  }
  return &Manager{
    signInKey: signInKey,
  }, nil
}

func (m *Manager) NewJWT(id string, ttl time.Duration) (string, error) {
  token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
    ExpiresAt: time.Now().Add(ttl).Unix(),
    Subject:   id,
  })
  return token.SignedString([]byte(m.signInKey))
}

func (m *Manager) Parse(accessToken string) (string, error) {
  token, err := jwt.Parse(accessToken, func(t *jwt.Token) (any, error) {
    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
      return nil, fmt.Errorf("unexpected sign in method")
    }
    return []byte(m.signInKey), nil
  })
  if err != nil {
    return "", err
  }
  claims, ok := token.Claims.(jwt.MapClaims)
  if !ok {
    return "", fmt.Errorf("failed get user claims from token")
  }
  id, ok := claims[claimId]
  if !ok {
    return "", fmt.Errorf("user id not found in token")
  }
  return id.(string), nil
}

func (m *Manager) NewRefreshToken() (string, error) {
  gen, err := uuid.NewUUID()
  if err != nil {
    return "", err
  }
  token := gen.String()
  if token == "" {
    return "", fmt.Errorf("failed to create new refresh token")
  }
  return token, nil
}
