package handler

import (
  "net/http"
  "fmt"
)

func (h *Handler) StartServing(port int) error {
  http.Handle("/sign-in", http.HandlerFunc(h.handleSignIn))
  http.Handle("/sign-up", http.HandlerFunc(h.handleSignUp))
  http.Handle("/user-info", http.HandlerFunc(h.handleUserInfo))
  http.Handle("/health", http.HandlerFunc(h.handleHealth))

  return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
