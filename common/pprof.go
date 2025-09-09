package common

import (
	"net/http"
	_ "net/http/pprof" //nolint:gosec // Import for pprof, only enabled via env
	"strings"
	"time"

	sreCommon "github.com/devopsext/sre/common"
)

type Server interface {
	Start(string)
	ErrChan() <-chan error
}

type PprofServer struct {
	err chan error
}

func NewPprofServer() *PprofServer {
	return &PprofServer{
		err: make(chan error),
	}
}

func (p *PprofServer) Start(address string, logger *sreCommon.Logs) {
	go func() {
		pprofHostPort := address
		parts := strings.Split(pprofHostPort, ":")
		if len(parts) == 2 && parts[0] == "" {
			pprofHostPort = "localhost:" + parts[1]
		}
		pprofHostPort = "http://" + pprofHostPort + "/debug/pprof"

		logger.Debug("Starting pprof HTTP server at: %s", pprofHostPort)

		server := &http.Server{
			Addr:         address,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 60 * time.Second,
		}

		if err := server.ListenAndServe(); err != nil {
			p.err <- err
		}
		close(p.err)
	}()
}

func (p *PprofServer) ErrChan() <-chan error {
	return p.err
}
