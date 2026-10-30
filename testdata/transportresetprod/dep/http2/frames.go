package http2

import (
	"encoding/binary"
	"errors"
	"io"
)

// ErrCode is an HTTP/2 error code.
type ErrCode uint32

// ErrCodeCancel is the RST_STREAM code a client sends to abandon a stream.
const ErrCodeCancel ErrCode = 0x8

// Frame is one HTTP/2 frame read off the peer connection.
type Frame interface {
	FrameType() byte
}

// MetaHeadersFrame opens a stream.
type MetaHeadersFrame struct {
	StreamID uint32
	Method   string
}

// FrameType implements Frame.
func (*MetaHeadersFrame) FrameType() byte { return 0x1 }

// DataFrame carries stream payload.
type DataFrame struct {
	StreamID uint32
	Data     []byte
}

// FrameType implements Frame.
func (*DataFrame) FrameType() byte { return 0x0 }

// RSTStreamFrame resets a stream.
type RSTStreamFrame struct {
	StreamID uint32
	ErrCode  ErrCode
}

// FrameType implements Frame.
func (*RSTStreamFrame) FrameType() byte { return 0x3 }

// Framer decodes peer frames.
type Framer struct {
	r io.Reader
}

// NewFramer returns a framer reading from the peer connection.
func NewFramer(r io.Reader) *Framer { return &Framer{r: r} }

// ReadFrame reads the next frame. Every byte comes from the client side of the
// accepted connection.
func (f *Framer) ReadFrame() (Frame, error) {
	var header [5]byte
	if _, err := io.ReadFull(f.r, header[:]); err != nil {
		return nil, err
	}
	streamID := binary.BigEndian.Uint32(header[1:])
	switch header[0] {
	case 0x1:
		return &MetaHeadersFrame{StreamID: streamID, Method: "GET"}, nil
	case 0x0:
		return &DataFrame{StreamID: streamID}, nil
	case 0x3:
		var code uint32
		if err := binary.Read(f.r, binary.BigEndian, &code); err != nil {
			return nil, err
		}
		return &RSTStreamFrame{StreamID: streamID, ErrCode: ErrCode(code)}, nil
	default:
		return nil, errors.New("http2: unknown frame type")
	}
}
