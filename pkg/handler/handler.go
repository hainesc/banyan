package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"golang.org/x/crypto/bcrypt"
	"github.com/hainesc/banyan/pkg/store"
	"github.com/hainesc/banyan/pkg/auth"
	"gopkg.in/square/go-jose.v2"
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
		var form auth.SignUpForm
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&form)
		if err != nil {
			fmt.Println("Decode json error")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}

		password, err := b.store.GetPassword(form.UserName)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}

		// Comparing the password with the hash
		err = bcrypt.CompareHashAndPassword(password.Hash, []byte(form.Password))

		if (err != nil) {
			fmt.Println("Compare hash value")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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

// TODO: Auth Decorator
// https://github.com/auth0-blog/auth0-golang-jwt/blob/master/main.go
// 401 Unauthenticated or redirect to ...
/*
func Auth(func h(w http.ResponseWriter, r *http.Request)) {
	h
}
*/
