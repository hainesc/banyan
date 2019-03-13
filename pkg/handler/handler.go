package handler

import (
	"bytes"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"golang.org/x/crypto/bcrypt"
	"github.com/hainesc/banyan/pkg/store"
	"github.com/hainesc/banyan/pkg/auth"
	jose "gopkg.in/square/go-jose.v2"
)

type BanyanHandler struct {
	store store.Store
	priv *jose.JSONWebKey
	pub *jose.JSONWebKey
}

func NewBanyanHandler(store store.Store, priv *jose.JSONWebKey, pub *jose.JSONWebKey) *BanyanHandler {
	return &BanyanHandler{
		store: store,
		priv: priv,
		pub: pub,
	}
}

const (
	HRGroup = "hr"
	ManagerGroup = "manager"
	StaffGroup = "staff"
)

var (
	HRs = map[string]struct{}{
		"yunhai.chen@daocloud.io": struct{}{},
		"hr@daocloud.io": struct{}{},
	}
	Managers = map[string]struct{}{
		"hongbing.zhang@daocloud.io": struct{}{},
		"manager@daocloud.io": struct{}{},
	}
)

func (b *BanyanHandler) HandleSignUp(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	case http.MethodPost:
		var form auth.SignUpForm
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&form)
		if err != nil {
			fmt.Println("Decode json error")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(form.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
		fmt.Println(string(hash))
		// Comparing the password with the hash
		err = bcrypt.CompareHashAndPassword(hash, []byte(form.Password))

		if (err != nil) {
			fmt.Println("Compare hash value")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}

		groups := []string{StaffGroup}
		if _, ok := HRs[form.Email]; ok {
			groups = append(groups, HRGroup)
		}

		if _, ok := Managers[form.Email]; ok {
			groups = append(groups, ManagerGroup)
		}

		err = b.store.SignUp(form, hash, groups)
		if err != nil {
			// TODO: error v2, CausedBy
			fmt.Println("Write store error")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}

}

func (b *BanyanHandler) HandleSignIn(w http.ResponseWriter, r *http.Request) {
	// TODO: setcookie
	switch r.Method {
	case http.MethodGet:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	case http.MethodPost:
		// TODO: maybe signin
		var form auth.SignInForm
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&form)
		if err != nil {
			fmt.Println("Decode json error")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		password, err := b.store.GetPassword(form.UserName)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		// Comparing the password with the hash
		err = bcrypt.CompareHashAndPassword(password.Hash, []byte(form.Password))

		if (err != nil) {
			fmt.Println("Compare hash value")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		issuedAt := time.Now()
		expiry := issuedAt.Add(time.Hour * 24)
		claims := auth.Claims{
			Name: form.UserName,
			Groups: password.Groups,
			Email: password.Email,
			IssuedAt: issuedAt.Unix(),
			Expiry: expiry.Unix(),
		}
		payload, _ := json.Marshal(claims)
		signer, _ := jose.NewSigner(jose.SigningKey{Key: b.priv, Algorithm: jose.RS256}, &jose.SignerOptions{})

		signature, _ := signer.Sign(payload)
		jwt, _ := signature.CompactSerialize()
		http.SetCookie(w, &http.Cookie{
			Name:       "BID",
			Value:      jwt,
			Path:       "/",
			RawExpires: "0",
		})
	}
}

func (b *BanyanHandler) Auth(next func(http.ResponseWriter, *http.Request, string, string)) http.Handler {
	// func (b *BanyanHandler) HandleSignIn(w http.ResponseWriter, r *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Checking whether authed")
		// read auth in the header
		bearer := r.Header.Get("Authorization")
		parts := strings.Fields(bearer)
		if len(parts) == 2 {
			token := parts[1]
			user, groups, err := b.VerifyJWT(token)
			if err == nil {
				next(w, r, user, groups)
				return
			} else {
				fmt.Println("Error verify: %v", err)
			}
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

	})
}

func (b *BanyanHandler) VerifyJWT(token string) (string, string, error) {
	jws, err := jose.ParseSigned(token)
	if err != nil {
		return "", "", fmt.Errorf("error in jwt: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("jwt token must have three parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}
	var claims auth.Claims
	if err = json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal claims")
	}

	if time.Unix(claims.Expiry, 0).Before(time.Now()) {
		return "", "", fmt.Errorf("token is expired")
	}

	p, err := jws.Verify(b.pub)
	if err != nil {
		return "", "", fmt.Errorf("failed to verify the token: %v", err)
	}

	if !bytes.Equal(p, payload) {
		return "", "", fmt.Errorf("payload parsed does not matched")
	}
	fmt.Println(claims.Groups[0])
	// hr < manager < staff
	sort.Strings(claims.Groups)
	fmt.Println(claims.Groups[0])
	return claims.Name, claims.Groups[0], nil

}

func (b *BanyanHandler) HandleTeams(w http.ResponseWriter, r *http.Request, user string, group string) {
	switch r.Method {
	case http.MethodGet:
		teams, _ := b.store.GetTeams(user, group)
		response, _ := json.Marshal(teams)
		w.Write(response)
	case http.MethodPost:

		fmt.Println(group)
		if group != "hr" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		var team store.Team
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&team)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		err = b.store.AddTeam(team)
		if err != nil {
			fmt.Printf(err.Error())
		}

	case http.MethodPut:
		// Update an existing record.
		fmt.Printf("receive a post mothod with parameter: ")
	case http.MethodDelete:
		fmt.Printf("receive a post mothod with parameter: ")
	case http.MethodPatch:
		fmt.Printf("receive a post mothod with parameter: ")
	default:
		// Give an error message.
		http.Error(w, "Invalid request method.", 405)
	}
}
// http.HandleFunc("/provisions/", Provisions)
// id := strings.TrimPrefix(req.URL.Path, "/provisions/")
