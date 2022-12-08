package handler

import (
  "fmt"
  "net/http"
)

func (h *Handler) StartServing(port int) error {
  http.Handle("/sign-in", http.HandlerFunc(h.handleSignIn))
  http.Handle("/sign-up", http.HandlerFunc(h.handleSignUp))
  http.Handle("/refresh", http.HandlerFunc(h.handleRefreshTokens))
  http.Handle("/user-info", h.AuthMiddleware(http.HandlerFunc(h.handleUserInfo)))
  http.Handle("/health", http.HandlerFunc(h.handleHealth))

  return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
