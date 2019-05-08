package server

import (
	"context"
	"crypto/rsa"
	"net/http"

	"github.com/hainesc/banyan/pkg/config"
	"github.com/hainesc/banyan/pkg/handler"
	"github.com/hainesc/banyan/pkg/mail"
	"github.com/hainesc/banyan/pkg/store"
	"github.com/hainesc/banyan/pkg/store/memory"
	"gopkg.in/square/go-jose.v2"
)

type Server struct {
	store store.Store
}

// NewServer constructs a server from the provided config.
func NewServer(ctx context.Context, c *config.BanyanConf) (*Server, error) {
	return &Server{
		store: memory.NewMemory(),
	}, nil
}

func SigningKeyGenerator() (priv *jose.JSONWebKey, pub *jose.JSONWebKey) {
	tmp, _ := store.RS256.Generator()
	key := tmp.(*rsa.PrivateKey)
	priv = &jose.JSONWebKey{
		Key: key,
		KeyID: "1",
		Algorithm: "RS256",
		Use: "sig",
	}
	pub = &jose.JSONWebKey{
		Key: key.Public(),
		KeyID: "1",
		Algorithm: "RS256",
		Use: "sig",
	}
	return
}

func (s *Server) Serve() error {
	SigningKey, SigningKeyPub := SigningKeyGenerator()
	// TODO: change them to the real ones.
	sender, _ := mail.NewSender("smtp.example.com", "587", "sender@example.com", "Password-here")
	banyan := handler.NewBanyanHandler(s.store, SigningKey, SigningKeyPub, sender)
	http.Handle("/", http.FileServer(http.Dir("./magpie")))
	http.HandleFunc("/api/signup", banyan.HandleSignUp)
	http.HandleFunc("/api/signin", banyan.HandleSignIn)
	http.HandleFunc("/api/confirm", banyan.HandleConfirm)
	http.Handle("/api/teams", banyan.Auth(banyan.HandleTeams))
	// TODO: https, it is very simple.
	return http.ListenAndServe(":8090", nil)
}
