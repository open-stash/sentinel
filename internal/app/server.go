package app

import (
	"context"
	"fmt"
	"net/http"
)

type Server struct {
	httpServer *http.Server
}

func NewServer(container *Container) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:    fmt.Sprintf(":%d", container.Config.Server.Port),
			Handler: container.Router,
		},
	}
}

func (s *Server) Addr() string {
	return s.httpServer.Addr
}

func (s *Server) Run() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
