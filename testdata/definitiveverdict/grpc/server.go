// Package grpc models the affected module's server surface: server
// construction, the listener-driven accept loop and the dispatch callback the
// transport invokes. Its shape mirrors gRPC-Go v1.55.0 — the transport calls
// the dispatch synchronously and the asynchronous handler lifetime belongs to
// serveStreams.
package grpc

import (
	"context"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc/internal/transport"
)

// Stream is one active server stream.
type Stream = transport.Stream

// Handler serves one admitted stream.
type Handler func(context.Context, *Stream) error

// Option configures a Server.
type Option func(*serverOptions)

type serverOptions struct {
	maxConcurrentStreams uint32
	numServerWorkers     uint32
	interceptor          Handler
}

// NumStreamWorkers configures the server worker pool.
func NumStreamWorkers(n uint32) Option {
	return func(o *serverOptions) { o.numServerWorkers = n }
}

// MaxConcurrentStreams bounds the transport's own stream admission.
func MaxConcurrentStreams(n uint32) Option {
	return func(o *serverOptions) { o.maxConcurrentStreams = n }
}

// UnaryInterceptor installs a handler-level interceptor. The handler chain
// applies it after the transport admitted and dispatched the stream.
func UnaryInterceptor(h Handler) Option {
	return func(o *serverOptions) { o.interceptor = h }
}

// Server accepts client connections and dispatches their HTTP/2 streams.
type Server struct {
	opts    serverOptions
	handler Handler

	serverWorkerChannel chan *serverWorkerData
}

// serverWorkerData is one admitted stream handed to a worker goroutine.
type serverWorkerData struct {
	st     *transport.ServerTransport
	wg     *sync.WaitGroup
	stream *transport.Stream
}

// NewServer constructs a server. Nothing is served until Serve runs.
func NewServer(opts ...Option) *Server {
	s := &Server{}
	for _, opt := range opts {
		opt(&s.opts)
	}
	if s.opts.numServerWorkers > 0 {
		s.initServerWorkers()
	}
	return s
}

// serverWorker processes admitted streams on one worker goroutine.
func (s *Server) serverWorker() {
	for data := range s.serverWorkerChannel {
		s.handleSingleStream(data)
	}
}

func (s *Server) handleSingleStream(data *serverWorkerData) {
	defer data.wg.Done()
	s.handleStream(data.st, data.stream)
}

// initServerWorkers creates worker goroutines and a channel to process
// incoming connections to reduce the time spent overall on runtime.morestack.
func (s *Server) initServerWorkers() {
	s.serverWorkerChannel = make(chan *serverWorkerData)
	for i := uint32(0); i < s.opts.numServerWorkers; i++ {
		go s.serverWorker()
	}
}

// RegisterHandler installs the stream handler.
func (s *Server) RegisterHandler(h Handler) { s.handler = h }

// Serve accepts connections from lis and serves the peer's streams.
func (s *Server) Serve(lis net.Listener) error {
	for {
		rawConn, err := lis.Accept()
		if err != nil {
			return err
		}
		st, terr := transport.NewServerTransport(rawConn)
		if terr != nil {
			_ = rawConn.Close()
			continue
		}
		s.serveStreams(st)
	}
}

// serveStreams supplies the dispatch callback to the transport. The handler's
// lifetime is asynchronous to the transport's frame loop.
func (s *Server) serveStreams(st *transport.ServerTransport) {
	defer st.Close(errors.New("finished serving streams for the server transport"))
	var wg sync.WaitGroup
	st.HandleStreams(func(stream *transport.Stream) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleStream(st, stream)
		}()
	}, func(ctx context.Context, method string) context.Context {
		return ctx
	})
	wg.Wait()
}

// handleStream runs the registered handler for one admitted stream.
func (s *Server) handleStream(_ *transport.ServerTransport, stream *transport.Stream) {
	if s.opts.interceptor != nil {
		if err := s.opts.interceptor(stream.Ctx(), stream); err != nil {
			return
		}
	}
	if s.handler != nil {
		_ = s.handler(stream.Ctx(), stream)
	}
}
