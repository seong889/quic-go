package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A MaxStreamIDFrame is a MAX_STREAM_ID frame
type MaxStreamIDFrame struct {
	StreamID protocol.StreamID
}

// ParseMaxStreamIDFrame parses a MAX_STREAM_ID frame
func ParseMaxStreamIDFrame(r *bytes.Reader, version protocol.VersionNumber) (*MaxStreamIDFrame, error) {
	// read the Type byte
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}
	streamID, err := utils.GetByteOrder(version).ReadUint32(r)
	if err != nil {
		return nil, err
	}
	return &MaxStreamIDFrame{StreamID: protocol.StreamID(streamID)}, nil
}

func (f *MaxStreamIDFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.WriteByte(0x6)
	utils.GetByteOrder(version).WriteUint32(b, uint32(f.StreamID))
	return nil
}

// MinLength of a written frame
func (f *MaxStreamIDFrame) MinLength(protocol.VersionNumber) (protocol.ByteCount, error) {
	return 1 + 4, nil
}
