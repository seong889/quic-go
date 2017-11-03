package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A StreamIDBlockedFrame is a STREAM_ID_BLOCKED frame
type StreamIDBlockedFrame struct{}

// ParseStreamIDBlockedFrame parses a STREAM_ID_BLOCKED frame
func ParseStreamIDBlockedFrame(r *bytes.Reader, version protocol.VersionNumber) (*StreamIDBlockedFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	return &StreamIDBlockedFrame{}, nil
}

func (f *StreamIDBlockedFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	typeByte := uint8(0x0a)
	b.WriteByte(typeByte)
	return nil
}

// MinLength of a written frame
func (f *StreamIDBlockedFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	return 1, nil
}
