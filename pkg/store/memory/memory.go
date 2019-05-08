package memory
import (
	"fmt"
	"strings"
	"github.com/hainesc/banyan/pkg/auth"
	"github.com/hainesc/banyan/pkg/store"
)
type Memory struct {
	password map[string]auth.Password
	teams map[string]store.Team
}

func NewMemory() *Memory {
	return &Memory{
		password: make(map[string]auth.Password),
		teams: make(map[string]store.Team),
	}
}
// Memory implements the Store interface
var _ store.Store = &Memory{}

func (m *Memory) SignUp(form auth.SignUpForm, hash []byte, groups []string) error {
	// TODO: email check, smtp
	// smtp.partner.outlook.cn
	// 587
	// STARTTLS
	if _, ok := m.password[form.UserName]; ok {
		return fmt.Errorf("User name exists")
	}

	parts := strings.Split(form.Email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("Email format error")
	}

	if parts[1] != "daocloud.io" {
		return fmt.Errorf("Use daocloud.io email only")
	}
	emailVerified := false
	m.password[form.UserName] = auth.Password{
		Email:          form.Email,
		EmailVerified:  &emailVerified,
		Hash:           hash,
		Groups:         groups,
	}
	return nil
}

func (m *Memory) GetHash(user string) ([]byte, error) {
	if _, ok := m.password[user]; !ok {
		return nil, fmt.Errorf("User not found")
	}

	return m.password[user].Hash, nil
}

func (m *Memory) SignIn() error {
	return nil
}

func (m *Memory) GetPassword(user string) (*auth.Password, error) {
	if _, ok := m.password[user]; !ok {
		return nil, fmt.Errorf("User not found")
	}
	ret := m.password[user]
	return &ret, nil
}

func (m *Memory) GetTeams(user string, group string) ([]store.Team, error) {
	var result []store.Team
	for _, v := range m.teams {
		result = append(result, v)
	}
	return result, nil
}

func (m *Memory) AddTeam(team store.Team) error {
	m.teams[team.Name] = team
	return nil
}

func (m *Memory) SetMailVerified(user string) error {
	t := true
	item := m.password[user]
	item.EmailVerified = &t
	m.password[user] = item
	return nil
}
