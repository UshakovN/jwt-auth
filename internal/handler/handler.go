package handler

import (
  "net/http"
  "Lab8/internal/service"
  "Lab8/internal/auth"
  "fmt"
  "encoding/json"
  log "github.com/sirupsen/logrus"
  "io"
  "Lab8/internal/domain"
  "Lab8/internal/hash"
  "Lab8/cmd/pkg/utils"
  "time"
)

const authHeader = "x-auth-token"

type ServiceHandler interface {
  handleSignIn(http.ResponseWriter, *http.Request)
  handleSignUp(http.ResponseWriter, *http.Request)
  handleHealth(http.ResponseWriter, *http.Request)
  handleUserInfo(http.ResponseWriter, *http.Request)
  StartServing(port int) error
}

type Handler struct {
  startTime       time.Time
  service         service.Service
  tokenManager    auth.TokenManager
  passwordManager hash.PasswordManager
}

type Config struct {
  Service         service.Service      `mandatory:"true"`
  TokenManager    auth.TokenManager    `mandatory:"true"`
  PasswordManager hash.PasswordManager `mandatory:"true"`
}

func NewHandler(config *Config) (*Handler, error) {
  if err := utils.CheckMandatoryFields(config); err != nil {
    return nil, fmt.Errorf("invalid handler config: %v", err)
  }
  return &Handler{
    startTime:       time.Now().UTC(),
    service:         config.Service,
    tokenManager:    config.TokenManager,
    passwordManager: config.PasswordManager,
  }, nil
}

func extractAuthToken(r *http.Request) (string, error) {
  accessToken := r.Header.Get(authHeader)
  if accessToken == "" {
    return "", fmt.Errorf("empty token recieved")
  }
  return accessToken, nil
}

func (h *Handler) handleSignUp(w http.ResponseWriter, r *http.Request) {
  req := &signRequest{}
  err := readRequest(r, req)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  _, hasFound, err := h.service.FindUserByEmail(req.Email)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  if hasFound {
    errMsg := fmt.Sprintf("user with email %s already exist", req.Email)
    http.Error(w, errMsg, http.StatusBadRequest)
    return
  }
  tokens, err := h.service.UserSignUp(&domain.SignUpInput{
    Email:        req.Email,
    PasswordHash: h.passwordManager.Hash(req.Password),
  })
  resp := &signResponse{}
  if err = mapResponse(tokens, resp); err != nil {
    return
  }
  if err = writeResponse(w, resp); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    log.Error(err)
    return
  }
}

func (h *Handler) handleSignIn(w http.ResponseWriter, r *http.Request) {
  req := &signRequest{}
  err := readRequest(r, req)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  user, hasFound, err := h.service.FindUserByEmail(req.Email)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  if !hasFound {
    errMsg := fmt.Sprintf("user with email %s not found", req.Email)
    http.Error(w, errMsg, http.StatusBadRequest)
    return
  }
  tokens, err := h.service.UserSignIn(&domain.SignInInput{
    Id:           user.Id,
    PasswordHash: h.passwordManager.Hash(req.Password),
  })
  resp := &signResponse{}
  if err = mapResponse(tokens, resp); err != nil {
    return
  }
  if err = writeResponse(w, resp); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    log.Error(err)
    return
  }
}

func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
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
  user, err := h.service.GetUserInfo(userId)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  resp := &userInfoResponse{}
  if err = mapResponse(user, resp); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  if err = writeResponse(w, resp); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    log.Error(err)
    return
  }
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
  resp := &healthResponse{
    Status:    statusOK,
    StartedAt: utils.GetTimeString(h.startTime),
  }
  if err := writeResponse(w, resp); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    log.Error(err)
    return
  }
}

func readRequest[R allowedRequest](r *http.Request, req R) error {
  if r.Method != http.MethodPost {
    return fmt.Errorf("method not supported")
  }
  b, err := io.ReadAll(r.Body)
  if err != nil {
    return err
  }
  if err = utils.UnmarshalJSON(b, req); err != nil {
    return err
  }
  return nil
}

func writeResponse[R allowedResponse](w http.ResponseWriter, resp R) error {
  b, err := json.MarshalIndent(resp, "", "  ")
  if err != nil {
    return err
  }
  w.Header().Add("Content-Type", "application/json")
  w.WriteHeader(http.StatusOK)
  _, err = w.Write(b)
  if err != nil {
    return err
  }
  return nil
}

func mapResponse[T allowedDomains, R allowedResponse](domain T, resp R) error {
  b, err := json.Marshal(domain)
  if err != nil {
    return err
  }
  if err := json.Unmarshal(b, resp); err != nil {
    return err
  }
  return nil
}
