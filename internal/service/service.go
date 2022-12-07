package service

import (
  "Lab8/cmd/pkg/utils"
  "Lab8/internal/auth"
  "Lab8/internal/domain"
  "Lab8/internal/repo"
  "bytes"
  "fmt"
  "time"
)

const tokenTTL = 15 * time.Minute // expired token

type Service interface {
  UserSignIn(input *domain.SignInInput) (*domain.Tokens, error)
  UserSignUp(input *domain.SignUpInput) (*domain.Tokens, error)
  GetUserInfo(string) (*User, error)
  FindUserByEmail(string) (*User, bool, error)
  newUserId(email string) (string, error)
  confirmUser(userId, passwordHash string) (*User, error)
}

type User struct {
  Id           string `json:"id"`
  Email        string `json:"email"`
  PasswordHash string `json:"password_hash"`
}

type UserService struct {
  tokenTTL     time.Duration
  tokenManager auth.TokenManager
  storage      repo.Storage
}

func NewUserService(tokenManager auth.TokenManager, storage repo.Storage) *UserService {
  return &UserService{
    tokenTTL:     tokenTTL,
    tokenManager: tokenManager,
    storage:      storage,
  }
}

func (s *UserService) confirmUser(userId, passwordHash string) (*User, error) {
  res, err := s.storage.Get(userId)
  if err != nil {
    return nil, err
  }
  user, ok := res.(*User)
  if !ok {
    return nil, fmt.Errorf("failed cast user data")
  }
  if user.PasswordHash != passwordHash {
    return nil, fmt.Errorf("password mismatch")
  }
  return user, nil
}

func (s *UserService) newUserId(email string) (string, error) {
  var b bytes.Buffer
  _, err := b.Write([]byte(email))
  if err != nil {
    return "", err
  }
  return fmt.Sprintf("%x", b.String()), nil
}

func (s *UserService) FindUserByEmail(email string) (*User, bool, error) {
  userId, err := s.newUserId(email)
  if err != nil {
    return nil, false, err
  }
  res, err := s.storage.Get(userId)
  if err != nil {
    return nil, false, err
  }
  user, ok := res.(*User)
  return user, ok, nil
}

func (s *UserService) UserSignIn(input *domain.SignInInput) (*domain.Tokens, error) {
  if err := utils.CheckMandatoryFields(input); err != nil {
    return nil, err
  }
  user, err := s.confirmUser(input.Id, input.PasswordHash)
  if err != nil {
    return nil, err
  }
  return s.createSession(user.Id)
}

func (s *UserService) UserSignUp(input *domain.SignUpInput) (*domain.Tokens, error) {
  if err := utils.CheckMandatoryFields(input); err != nil {
    return nil, err
  }
  id, err := s.newUserId(input.Email)
  if err != nil {
    return nil, err
  }
  user := &User{
    Id:           id,
    Email:        input.Email,
    PasswordHash: input.PasswordHash,
  }
  if err := s.storage.Put(id, user); err != nil {
    return nil, err
  }
  return s.createSession(id)
}

func (s *UserService) GetUserInfo(userId string) (*User, error) {
  res, err := s.storage.Get(userId)
  if err != nil {
    return nil, err
  }
  user, ok := res.(*User)
  if !ok {
    return nil, fmt.Errorf("failed cast storage result to user")
  }
  return user, nil
}

func (s *UserService) createSession(userId string) (*domain.Tokens, error) {
  accessToken, err := s.tokenManager.NewJWT(userId, s.tokenTTL)
  if err != nil {
    return nil, err
  }
  refreshToken, err := s.tokenManager.NewRefreshToken()
  if err != nil {
    return nil, err
  }
  return &domain.Tokens{
    Access:  accessToken,
    Refresh: refreshToken,
  }, nil
}
