package transport

import (
	"context"
	"net"
	"sync"

	"example.com/transportresetdep/http2"
)

// Stream is one active HTTP/2 stream.
type Stream struct {
	id     uint32
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	replicas int
}

// ID reports the stream id the peer chose.
func (s *Stream) ID() uint32 { return s.id }

// Ctx is the stream's cancellation context.
func (s *Stream) Ctx() context.Context { return s.ctx }

// Replicas reports how many list items the handler materialized.
func (s *Stream) Replicas() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replicas
}

func (s *Stream) addReplica() {
	s.mu.Lock()
	s.replicas++
	s.mu.Unlock()
}

// ServerTransport consumes the peer's frames off one accepted connection.
type ServerTransport struct {
	conn   net.Conn
	framer *http2.Framer
	ctx    context.Context
	cancel context.CancelFunc
	handle func(context.Context, *Stream)

	mu            sync.Mutex
	activeStreams map[uint32]*Stream
}

// ServerOption configures a ServerTransport.
type ServerOption func(*ServerTransport)

// NewServerTransport builds the server transport for one accepted connection.
func NewServerTransport(conn net.Conn, opts ...ServerOption) (*ServerTransport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	t := &ServerTransport{
		conn:          conn,
		framer:        http2.NewFramer(conn),
		ctx:           ctx,
		cancel:        cancel,
		activeStreams: make(map[uint32]*Stream),
	}
	for _, opt := range opts {
		opt(t)
	}
	return t, nil
}

// HandleStreams consumes peer-supplied frames until the connection ends.
func (t *ServerTransport) HandleStreams(ctx context.Context, handle func(context.Context, *Stream)) {
	t.handle = handle
	for {
		frame, err := t.framer.ReadFrame()
		if err != nil {
			t.closeConn()
			return
		}
		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			t.operateHeaders(f)
		case *http2.DataFrame:
			t.handleData(f)
		case *http2.RSTStreamFrame:
			t.handleRSTStream(f)
		}
	}
}

// operateHeaders admits a stream the peer asked for and starts its handler.
func (t *ServerTransport) operateHeaders(f *http2.MetaHeadersFrame) {
	ctx, cancel := context.WithCancel(t.ctx)
	s := &Stream{id: f.StreamID, ctx: ctx, cancel: cancel}
	t.mu.Lock()
	t.activeStreams[f.StreamID] = s
	t.mu.Unlock()
	go t.runHandler(s)
}

func (t *ServerTransport) runHandler(s *Stream) {
	handle := t.handle
	if handle == nil {
		return
	}
	handle(s.ctx, s)
}

func (t *ServerTransport) handleData(f *http2.DataFrame) {
	t.mu.Lock()
	s := t.activeStreams[f.StreamID]
	t.mu.Unlock()
	if s == nil {
		return
	}
	s.addReplica()
}

func (t *ServerTransport) handleRSTStream(f *http2.RSTStreamFrame) {
	t.mu.Lock()
	s := t.activeStreams[f.StreamID]
	t.mu.Unlock()
	if s == nil {
		return
	}
	t.closeStream(s, true, f.ErrCode)
}

// closeStream cancels the stream and drops it from the active set. It does not
// wait for the handler goroutine, so the peer may open the next stream at once.
func (t *ServerTransport) closeStream(s *Stream, rst bool, code http2.ErrCode) {
	if rst && s.cancel != nil {
		s.cancel()
	}
	t.mu.Lock()
	delete(t.activeStreams, s.id)
	t.mu.Unlock()
}

func (t *ServerTransport) closeConn() {
	t.cancel()
	_ = t.conn.Close()
}
