package handler

import (
	"net/http"
	"github.com/hainesc/banyan/pkg/store"
)

type BanyanHandler struct {
	store store.Store
}

func NewBanyanHandler(store store.Store) *BanyanHandler {
	return &BanyanHandler{
		store: store,
	}
}

func (b *BanyanHandler) HandleTODO(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not implemented now."))
}
