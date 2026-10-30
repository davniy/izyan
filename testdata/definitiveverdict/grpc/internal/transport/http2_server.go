// Package transport models the server transport of the affected module. The
// stream lifecycle mirrors the version the worked case pins (gRPC-Go v1.55.0):
// a reset removes the stream from the active set without joining its handler,
// and the handler's asynchronous lifetime is established by the dispatch
// callback's supplier in the parent package.
package transport

import (
	"context"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc/internal/http2"
)

// Stream is one active server stream.
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

// ServerTransport consumes the peer's frames off one accepted connection.
type ServerTransport struct {
	conn   net.Conn
	framer *http2.Framer
	ctx    context.Context
	cancel context.CancelFunc

	done   chan struct{}
	mu     sync.Mutex
	closed bool

	activeStreams map[uint32]*Stream
}

// NewServerTransport builds the server transport for one accepted connection.
func NewServerTransport(conn net.Conn) (*ServerTransport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &ServerTransport{
		conn:          conn,
		framer:        http2.NewFramer(conn),
		ctx:           ctx,
		cancel:        cancel,
		done:          make(chan struct{}),
		activeStreams: make(map[uint32]*Stream),
	}, nil
}

// HandleStreams receives incoming streams using the given handler.
func (t *ServerTransport) HandleStreams(handle func(*Stream), traceCtx func(context.Context, string) context.Context) {
	defer close(t.done)
	for {
		frame, err := t.framer.ReadFrame()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			t.Close(err)
			return
		}
		switch frame := frame.(type) {
		case *http2.MetaHeadersFrame:
			if err := t.operateHeaders(frame, handle, traceCtx); err != nil {
				t.Close(err)
				break
			}
		case *http2.DataFrame:
			t.handleData(frame)
		case *http2.RSTStreamFrame:
			t.handleRSTStream(frame)
		}
	}
}

// operateHeaders admits a stream the peer asked for and invokes the dispatch.
func (t *ServerTransport) operateHeaders(frame *http2.MetaHeadersFrame, handle func(*Stream),
	traceCtx func(context.Context, string) context.Context) error {
	ctx, cancel := context.WithCancel(t.ctx)
	s := &Stream{id: frame.StreamID, ctx: ctx, cancel: cancel}
	s.ctx = traceCtx(s.ctx, frame.Method)

	t.mu.Lock()
	t.activeStreams[s.id] = s
	t.mu.Unlock()

	handle(s)
	return nil
}

func (t *ServerTransport) handleData(f *http2.DataFrame) {
	t.mu.Lock()
	s := t.activeStreams[f.StreamID]
	t.mu.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	s.replicas++
	s.mu.Unlock()
}

func (t *ServerTransport) handleRSTStream(f *http2.RSTStreamFrame) {
	if s, ok := t.getStream(f); ok {
		t.closeStream(s, true, f.ErrCode)
	}
}

func (t *ServerTransport) getStream(f http2.Frame) (*Stream, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var id uint32
	switch frame := f.(type) {
	case *http2.RSTStreamFrame:
		id = frame.StreamID
	default:
		return nil, false
	}
	s := t.activeStreams[id]
	return s, s != nil
}

// closeStream cancels the stream and drops it from the active set.
func (t *ServerTransport) closeStream(s *Stream, rst bool, rstCode http2.ErrCode) {
	s.cancel()
	t.deleteStream(s)
	_ = rst
	_ = rstCode
}

// deleteStream removes the stream from the active set. It does not wait for
// the handler goroutine, so the peer may open the next stream at once.
func (t *ServerTransport) deleteStream(s *Stream) {
	t.mu.Lock()
	if _, ok := t.activeStreams[s.id]; ok {
		delete(t.activeStreams, s.id)
	}
	t.mu.Unlock()
}

// Close tears the transport down.
func (t *ServerTransport) Close(err error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()
	t.cancel()
	_ = t.conn.Close()
	_ = err
}
