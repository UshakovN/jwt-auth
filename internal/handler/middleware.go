package handler

import (
  "context"
  "net/http"
)

const ctxUserId = "user-id"

func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    accessToken, err := extractAuthToken(r)
    if err != nil {
      http.Error(w, err.Error(), http.StatusUnauthorized)
      return
    }
    userId, err := h.tokenManager.Parse(accessToken)
    if err != nil {
      http.Error(w, err.Error(), http.StatusForbidden)
      return
    }
    ctx := context.WithValue(r.Context(), ctxUserId, userId)
    next.ServeHTTP(w, r.WithContext(ctx))
  })
}
