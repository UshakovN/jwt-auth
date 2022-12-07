package hash

import (
  "crypto/sha256"
  "fmt"
)

type PasswordManager interface {
  Hash(password string) string
}

type Manager struct {
  salt string
}

func NewManager(options ...Option) *Manager {
  m := &Manager{}
  for _, opt := range options {
    opt(m)
  }
  return m
}

type Option func(*Manager)

func WithSalt(salt string) Option {
  return func(m *Manager) {
    m.salt = salt
  }
}

func (m *Manager) Hash(password string) string {
  hash := sha256.New()
  hash.Write([]byte(password))
  return fmt.Sprintf("%x", hash.Sum([]byte(m.salt)))
}
