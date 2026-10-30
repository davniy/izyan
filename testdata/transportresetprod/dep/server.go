package dep

import (
	"context"
	"net"

	"example.com/transportresetdep/transport"
)

// Stream is one active server stream.
type Stream = transport.Stream

// Handler serves one stream.
type Handler func(context.Context, *Stream) error

// Option configures a Server.
type Option func(*Server)

// UnaryInterceptor installs a handler-level interceptor around every stream
// handler. The handler chain applies it after the transport admitted and
// dispatched the stream.
func UnaryInterceptor(h Handler) Option {
	return func(s *Server) { s.interceptor = h }
}

// MaxConcurrentStreams bounds the transport's own stream admission.
func MaxConcurrentStreams(n uint32) Option {
	return func(s *Server) { s.maxStreams = n }
}

// Server accepts client connections and dispatches their HTTP/2 streams.
type Server struct {
	interceptor Handler
	maxStreams  uint32
	handler     func(context.Context, *Stream) error
}

// NewServer constructs a server. Nothing is served until Serve runs.
func NewServer(opts ...Option) (*Server, error) {
	s := &Server{}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Serve accepts connections from lis and dispatches the peer's frames.
func (s *Server) Serve(lis net.Listener) error {
	for {
		rawConn, err := lis.Accept()
		if err != nil {
			return err
		}
		onConn := func(rawConn net.Conn) {
			st, err := s.newHTTP2Transport(rawConn)
			if err != nil {
				rawConn.Close()
				return
			}
			st.HandleStreams(context.Background(), s.serveStreams)
		}
		go s.handleRawConn(rawConn, onConn)
	}
}

func (s *Server) handleRawConn(rawConn net.Conn, onConn func(net.Conn)) {
	onConn(rawConn)
}

func (s *Server) newHTTP2Transport(conn net.Conn) (*transport.ServerTransport, error) {
	return transport.NewServerTransport(conn)
}

// serveStreams is the handler the transport invokes for an admitted stream.
func (s *Server) serveStreams(ctx context.Context, st *Stream) {
	if s.interceptor != nil {
		if err := s.interceptor(ctx, st); err != nil {
			return
		}
	}
	if s.handler != nil {
		_ = s.handler(ctx, st)
	}
}

// Client is the outbound half of the module: a product may use it without ever
// serving a transport.
type Client struct {
	conn net.Conn
}

// NewClient wraps an outbound connection.
func NewClient(conn net.Conn) *Client { return &Client{conn: conn} }

// Call sends one request over the outbound connection.
func (c *Client) Call(_ context.Context, method string) error {
	_, err := c.conn.Write([]byte(method))
	return err
}
