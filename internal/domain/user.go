package domain

type ServiceInput interface {
  *SignInInput | *SignUpInput | *UserInfoInput
}

type SignInInput struct {
  Id           string `json:"id"`
  PasswordHash string `json:"password_hash"`
}

type UserInfoInput struct {
  Id string `json:"id"`
}

type SignUpInput struct {
  Email        string `json:"email"`
  PasswordHash string `json:"password_hash"`
}

type Tokens struct {
  Access  string `json:"access_token"`
  Refresh string `json:"refresh_token"`
}
