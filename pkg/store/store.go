package store

import (
	"github.com/hainesc/banyan/pkg/auth"
)

type Store interface {
	SignUp(auth.SignUpForm, []byte, []string) error
	GetHash(string) ([]byte, error)
	GetPassword(string) (*auth.Password, error)
	GetTeams(string, string) ([]Team, error)
	AddTeam(Team) error
	SetMailVerified(string) error
}
