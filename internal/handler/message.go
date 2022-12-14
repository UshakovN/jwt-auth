package handler

import (
  "Lab8/internal/domain"
  "Lab8/internal/service"
)

const statusOK = "ok"

type allowedRequest interface {
  *signRequest | *refreshRequest
}

type allowedDomains interface {
  *service.User | *domain.Tokens
}

type allowedResponse interface {
  *userInfoResponse | *signResponse | *healthResponse
}

type userInfoResponse struct {
  Id    string `json:"id"`
  Email string `json:"email"`
}

type signRequest struct {
  Email    string `json:"email" mandatory:"true"`
  Password string `json:"password" mandatory:"true"`
}

type signResponse struct {
  AccessToken  string `json:"access_token"`
  RefreshToken string `json:"refresh_token"`
}

type refreshRequest struct {
  RefreshToken string `json:"refresh_token" mandatory:"true"`
}

type healthResponse struct {
  Status    string `json:"status"`
  StartedAt string `json:"started_at"`
}
