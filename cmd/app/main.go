package main

import (
  "Lab8/internal/auth"
  "Lab8/internal/handler"
  "Lab8/internal/hash"
  "Lab8/internal/repo"
  "Lab8/internal/service"
  "flag"
  "os"
  "os/signal"
  "syscall"

  log "github.com/sirupsen/logrus"
)

func continuouslyServe(h *handler.Handler, port int) {
  if err := h.StartServing(port); err != nil {
    log.Fatal(err)
  }
}

func buildHandler(signInKey, hashSalt string) *handler.Handler {
  mockStorage := repo.NewMockStorage()
  tokenManager, err := auth.NewManager(signInKey)
  if err != nil {
    log.Fatal(err)
  }
  passwordManager := hash.NewManager(hash.WithSalt(hashSalt))
  userService := service.NewUserService(tokenManager, mockStorage)
  config := &handler.Config{
    Service:         userService,
    TokenManager:    tokenManager,
    PasswordManager: passwordManager,
  }
  routeHandler, err := handler.NewHandler(config)
  if err != nil {
    log.Fatal(err)
  }
  return routeHandler
}

func main() {
  port := flag.Int("port", 8080, "serving port")
  key := flag.String("sign", "ushakov", "token sign in key")
  salt := flag.String("salt", "nikita", "hashing salt")
  flag.Parse()

  h := buildHandler(*key, *salt)
  go continuouslyServe(h, *port)

  exitSignal := make(chan os.Signal)
  signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
  <-exitSignal
}
