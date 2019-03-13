package auth

type SignUpForm struct {
	UserName string `json:"user"`
	Email string `json:"email"`
	Password string `json:"password"`
}

type SignInForm struct {
	UserName string `json:"user"`
	Password string `json:"password"`
}

type Password struct {
	Email string
	Hash []byte
	Groups []string
}

type Claims struct {
	Expiry         int64    `json:"exp"`
	IssuedAt       int64    `json:"iat"`
	Nonce          string   `json:"nonce,omitempty"`
	Email          string   `json:"email,omitempty"`
	EmailVerified  *bool    `json:"email_verified,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Name           string   `json:"name,omitempty"`
}
