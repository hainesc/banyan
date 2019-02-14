package server

import (
	"context"
	"net/http"
	"github.com/hainesc/banyan/pkg/config"
	"github.com/hainesc/banyan/pkg/handler"
	"github.com/hainesc/banyan/pkg/store"
	"github.com/hainesc/banyan/pkg/store/memory"
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

func (s *Server) Serve() error {
	banyan := handler.NewBanyanHandler(s.store)
	http.HandleFunc("/", banyan.HandleTODO)
	return http.ListenAndServe(":8090", nil)
}
