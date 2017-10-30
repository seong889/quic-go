package wire

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

var (
	// ErrInvalidAckRanges occurs when a client sends inconsistent ACK ranges
	ErrInvalidAckRanges = errors.New("AckFrame: ACK frame contains invalid ACK ranges")
	// ErrInvalidFirstAckRange occurs when the first ACK range contains no packets
	ErrInvalidFirstAckRange = errors.New("AckFrame: ACK frame has invalid first ACK range")
)

var (
	errInconsistentAckLargestAcked = errors.New("internal inconsistency: LargestAcked does not match ACK ranges")
	errInconsistentAckLowestAcked  = errors.New("internal inconsistency: LowestAcked does not match ACK ranges")
)

// An AckFrame is an ACK frame in QUIC
type AckFrame struct {
	LargestAcked protocol.PacketNumber
	LowestAcked  protocol.PacketNumber
	AckRanges    []AckRange // has to be ordered. The highest ACK range goes first, the lowest ACK range goes last

	// time when the LargestAcked was receiveid
	// this field Will not be set for received ACKs frames
	PacketReceivedTime time.Time
	DelayTime          time.Duration
}

// ParseAckFrame reads an ACK frame
func ParseAckFrame(r *bytes.Reader, version protocol.VersionNumber) (*AckFrame, error) {
	frame := &AckFrame{}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	var hasMissingRanges bool
	if (version.UsesIETFAckFrame() && typeByte&0x10 == 0x10) || (!version.UsesIETFAckFrame() && typeByte&0x20 == 0x20) {
		hasMissingRanges = true
	}

	var largestAckedLen uint8
	if version.UsesIETFAckFrame() {
		largestAckedLen = 1 << ((typeByte & 0x0c) >> 2)
	} else {
		largestAckedLen = 2 * ((typeByte & 0x0c) >> 2)
		if largestAckedLen == 0 {
			largestAckedLen = 1
		}
	}

	var missingSequenceNumberDeltaLen uint8
	if version.UsesIETFAckFrame() {
		missingSequenceNumberDeltaLen = 1 << (typeByte & 0x03)
	} else {
		missingSequenceNumberDeltaLen = 2 * (typeByte & 0x03)
		if missingSequenceNumberDeltaLen == 0 {
			missingSequenceNumberDeltaLen = 1
		}
	}

	var numAckBlocks uint8
	if version.UsesIETFAckFrame() && hasMissingRanges {
		numAckBlocks, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	var numTimestamps uint8
	if version.UsesIETFAckFrame() {
		numTimestamps, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	largestAcked, err := utils.GetByteOrder(version).ReadUintN(r, largestAckedLen)
	if err != nil {
		return nil, err
	}
	frame.LargestAcked = protocol.PacketNumber(largestAcked)

	delay, err := utils.GetByteOrder(version).ReadUfloat16(r)
	if err != nil {
		return nil, err
	}
	frame.DelayTime = time.Duration(delay) * time.Microsecond

	if !version.UsesIETFAckFrame() && hasMissingRanges {
		numAckBlocks, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if hasMissingRanges && numAckBlocks == 0 {
		return nil, ErrInvalidAckRanges
	}

	ackBlockLength, err := utils.GetByteOrder(version).ReadUintN(r, missingSequenceNumberDeltaLen)
	if err != nil {
		return nil, err
	}
	if frame.LargestAcked > 0 && ackBlockLength < 1 {
		return nil, ErrInvalidFirstAckRange
	}

	if ackBlockLength > largestAcked {
		return nil, ErrInvalidAckRanges
	}

	if hasMissingRanges {
		ackRange := AckRange{
			First: protocol.PacketNumber(largestAcked-ackBlockLength) + 1,
			Last:  frame.LargestAcked,
		}
		frame.AckRanges = append(frame.AckRanges, ackRange)

		var inLongBlock bool
		var lastRangeComplete bool
		for i := uint8(0); i < numAckBlocks; i++ {
			var gap uint8
			gap, err = r.ReadByte()
			if err != nil {
				return nil, err
			}

			ackBlockLength, err = utils.GetByteOrder(version).ReadUintN(r, missingSequenceNumberDeltaLen)
			if err != nil {
				return nil, err
			}

			length := protocol.PacketNumber(ackBlockLength)

			if inLongBlock {
				frame.AckRanges[len(frame.AckRanges)-1].First -= protocol.PacketNumber(gap) + length
				frame.AckRanges[len(frame.AckRanges)-1].Last -= protocol.PacketNumber(gap)
			} else {
				lastRangeComplete = false
				ackRange := AckRange{
					Last: frame.AckRanges[len(frame.AckRanges)-1].First - protocol.PacketNumber(gap) - 1,
				}
				ackRange.First = ackRange.Last - length + 1
				frame.AckRanges = append(frame.AckRanges, ackRange)
			}

			if length > 0 {
				lastRangeComplete = true
			}

			inLongBlock = (ackBlockLength == 0)
		}

		// if the last range was not complete, First and Last make no sense
		// remove the range from frame.AckRanges
		if !lastRangeComplete {
			frame.AckRanges = frame.AckRanges[:len(frame.AckRanges)-1]
		}

		frame.LowestAcked = frame.AckRanges[len(frame.AckRanges)-1].First
	} else {
		if frame.LargestAcked == 0 {
			frame.LowestAcked = 0
		} else {
			frame.LowestAcked = protocol.PacketNumber(largestAcked + 1 - ackBlockLength)
		}
	}

	if !frame.validateAckRanges() {
		return nil, ErrInvalidAckRanges
	}

	if !version.UsesIETFAckFrame() {
		numTimestamps, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if numTimestamps > 0 {
		// Delta Largest acked
		_, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
		// First Timestamp
		_, err = utils.GetByteOrder(version).ReadUint32(r)
		if err != nil {
			return nil, err
		}

		for i := 0; i < int(numTimestamps)-1; i++ {
			// Delta Largest acked
			_, err = r.ReadByte()
			if err != nil {
				return nil, err
			}

			// Time Since Previous Timestamp
			_, err = utils.GetByteOrder(version).ReadUint16(r)
			if err != nil {
				return nil, err
			}
		}
	}
	return frame, nil
}

// Write writes an ACK frame.
func (f *AckFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	largestAckedLen := protocol.GetPacketNumberLength(f.LargestAcked)

	var typeByte uint8
	if version.UsesIETFAckFrame() {
		typeByte = uint8(0xa0)
	} else {
		typeByte = uint8(0x40)
	}

	if largestAckedLen != protocol.PacketNumberLen1 {
		if version.UsesIETFAckFrame() {
			switch largestAckedLen {
			case protocol.PacketNumberLen2:
				typeByte ^= 0x1 << 2
			case protocol.PacketNumberLen4:
				typeByte ^= 0x2 << 2
			case protocol.PacketNumberLen8:
				typeByte ^= 0x3 << 2
			}
		} else {
			typeByte ^= (uint8(largestAckedLen / 2)) << 2
		}
	}

	// 1 bytes: 00 = 0 => 2^0
	// 2 bytes: 01 = 1 => 2^1
	// 4 bytes: 10 = 2 => 2^2
	// 8 bytes: 11 = 3 => 2^3

	missingSequenceNumberDeltaLen := f.getMissingSequenceNumberDeltaLen(version)
	if missingSequenceNumberDeltaLen != protocol.PacketNumberLen1 {
		if version.UsesIETFAckFrame() {
			switch missingSequenceNumberDeltaLen {
			case protocol.PacketNumberLen2:
				typeByte ^= 0x1
			case protocol.PacketNumberLen4:
				typeByte ^= 0x2
			case protocol.PacketNumberLen8:
				typeByte ^= 0x3
			}
		} else {
			typeByte ^= (uint8(missingSequenceNumberDeltaLen / 2))
		}
	}

	if f.HasMissingRanges() {
		if version.UsesIETFAckFrame() {
			typeByte ^= 0x10
		} else {
			typeByte ^= 0x20
		}
	}

	b.WriteByte(typeByte)

	numRanges := f.numWritableNackRanges()
	if numRanges > 0xFF {
		panic("AckFrame: Too many ACK ranges")
	}

	if version.UsesIETFAckFrame() && f.HasMissingRanges() {
		b.WriteByte(uint8(numRanges - 1))
	}

	switch largestAckedLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(f.LargestAcked))
	case protocol.PacketNumberLen2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(f.LargestAcked))
	case protocol.PacketNumberLen4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(f.LargestAcked))
	case protocol.PacketNumberLen6:
		utils.GetByteOrder(version).WriteUint48(b, uint64(f.LargestAcked)&(1<<48-1))
	case protocol.PacketNumberLen8:
		utils.GetByteOrder(version).WriteUint64(b, uint64(f.LargestAcked))
	}

	if !version.UsesIETFAckFrame() {
		f.DelayTime = time.Since(f.PacketReceivedTime)
		utils.GetByteOrder(version).WriteUfloat16(b, uint64(f.DelayTime/time.Microsecond))
	}

	var numRangesWritten uint64
	if !version.UsesIETFAckFrame() && f.HasMissingRanges() {
		b.WriteByte(uint8(numRanges - 1))
	}

	var firstAckBlockLength protocol.PacketNumber
	if !f.HasMissingRanges() {
		firstAckBlockLength = f.LargestAcked - f.LowestAcked + 1
	} else {
		if f.LargestAcked != f.AckRanges[0].Last {
			return errInconsistentAckLargestAcked
		}
		if f.LowestAcked != f.AckRanges[len(f.AckRanges)-1].First {
			return errInconsistentAckLowestAcked
		}
		firstAckBlockLength = f.LargestAcked - f.AckRanges[0].First + 1
		numRangesWritten++
	}

	switch missingSequenceNumberDeltaLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(firstAckBlockLength))
	case protocol.PacketNumberLen2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(firstAckBlockLength))
	case protocol.PacketNumberLen4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(firstAckBlockLength))
	case protocol.PacketNumberLen6:
		utils.GetByteOrder(version).WriteUint48(b, uint64(firstAckBlockLength)&(1<<48-1))
	}

	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}

		length := ackRange.Last - ackRange.First + 1
		gap := f.AckRanges[i-1].First - ackRange.Last - 1

		num := gap/0xFF + 1
		if gap%0xFF == 0 {
			num--
		}

		if num == 1 {
			b.WriteByte(uint8(gap))
			switch missingSequenceNumberDeltaLen {
			case protocol.PacketNumberLen1:
				b.WriteByte(uint8(length))
			case protocol.PacketNumberLen2:
				utils.GetByteOrder(version).WriteUint16(b, uint16(length))
			case protocol.PacketNumberLen4:
				utils.GetByteOrder(version).WriteUint32(b, uint32(length))
			case protocol.PacketNumberLen6:
				utils.GetByteOrder(version).WriteUint48(b, uint64(length)&(1<<48-1))
			}
			numRangesWritten++
		} else {
			for i := 0; i < int(num); i++ {
				var lengthWritten uint64
				var gapWritten uint8

				if i == int(num)-1 { // last block
					lengthWritten = uint64(length)
					gapWritten = uint8(1 + ((gap - 1) % 255))
				} else {
					lengthWritten = 0
					gapWritten = 0xFF
				}

				b.WriteByte(gapWritten)
				switch missingSequenceNumberDeltaLen {
				case protocol.PacketNumberLen1:
					b.WriteByte(uint8(lengthWritten))
				case protocol.PacketNumberLen2:
					utils.GetByteOrder(version).WriteUint16(b, uint16(lengthWritten))
				case protocol.PacketNumberLen4:
					utils.GetByteOrder(version).WriteUint32(b, uint32(lengthWritten))
				case protocol.PacketNumberLen6:
					utils.GetByteOrder(version).WriteUint48(b, lengthWritten&(1<<48-1))
				}

				numRangesWritten++
			}
		}

		// this is needed if not all AckRanges can be written to the ACK frame (if there are more than 0xFF)
		if numRangesWritten >= numRanges {
			break
		}
	}

	if numRanges != numRangesWritten {
		return errors.New("BUG: Inconsistent number of ACK ranges written")
	}

	b.WriteByte(0) // no timestamps
	return nil
}

// MinLength of a written frame
func (f *AckFrame) MinLength(version protocol.VersionNumber) (protocol.ByteCount, error) {
	length := protocol.ByteCount(1 + 2 + 1) // 1 TypeByte, 2 ACK delay time, 1 Num Timestamp
	length += protocol.ByteCount(protocol.GetPacketNumberLength(f.LargestAcked))

	missingSequenceNumberDeltaLen := protocol.ByteCount(f.getMissingSequenceNumberDeltaLen(version))

	if f.HasMissingRanges() {
		length += (1 + missingSequenceNumberDeltaLen) * protocol.ByteCount(f.numWritableNackRanges())
	} else {
		length += missingSequenceNumberDeltaLen
	}

	length += (1 + 2) * 0 /* TODO: num_timestamps */

	return length, nil
}

// HasMissingRanges returns if this frame reports any missing packets
func (f *AckFrame) HasMissingRanges() bool {
	return len(f.AckRanges) > 0
}

func (f *AckFrame) validateAckRanges() bool {
	if len(f.AckRanges) == 0 {
		return true
	}
	// if there are missing packets, there will always be at least 2 ACK ranges
	if len(f.AckRanges) == 1 {
		return false
	}
	if f.AckRanges[0].Last != f.LargestAcked {
		return false
	}
	// check the validity of every single ACK range
	for _, ackRange := range f.AckRanges {
		if ackRange.First > ackRange.Last {
			return false
		}
	}
	// check the consistency for ACK with multiple NACK ranges
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}
		lastAckRange := f.AckRanges[i-1]
		if lastAckRange.First <= ackRange.First {
			return false
		}
		if lastAckRange.First <= ackRange.Last+1 {
			return false
		}
	}
	return true
}

// numWritableNackRanges calculates the number of ACK blocks that are about to be written
// this number is different from len(f.AckRanges) for the case of long gaps (> 255 packets)
func (f *AckFrame) numWritableNackRanges() uint64 {
	if len(f.AckRanges) == 0 {
		return 0
	}

	var numRanges uint64
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}
		lastAckRange := f.AckRanges[i-1]
		gap := lastAckRange.First - ackRange.Last - 1
		rangeLength := 1 + uint64(gap)/0xFF
		if uint64(gap)%0xFF == 0 {
			rangeLength--
		}
		if numRanges+rangeLength < 0xFF {
			numRanges += rangeLength
		} else {
			break
		}
	}
	return numRanges + 1
}

func (f *AckFrame) getMissingSequenceNumberDeltaLen(version protocol.VersionNumber) protocol.PacketNumberLen {
	var maxRangeLength protocol.PacketNumber

	if f.HasMissingRanges() {
		for _, ackRange := range f.AckRanges {
			rangeLength := ackRange.Last - ackRange.First + 1
			if rangeLength > maxRangeLength {
				maxRangeLength = rangeLength
			}
		}
	} else {
		maxRangeLength = f.LargestAcked - f.LowestAcked + 1
	}

	if maxRangeLength <= 0xFF {
		return protocol.PacketNumberLen1
	}
	if maxRangeLength <= 0xFFFF {
		return protocol.PacketNumberLen2
	}
	if maxRangeLength <= 0xFFFFFFFF {
		return protocol.PacketNumberLen4
	}

	if !version.UsesIETFAckFrame() {
		return protocol.PacketNumberLen6
	}
	return protocol.PacketNumberLen8
}

// AcksPacket determines if this ACK frame acks a certain packet number
func (f *AckFrame) AcksPacket(p protocol.PacketNumber) bool {
	if p < f.LowestAcked || p > f.LargestAcked { // this is just a performance optimization
		return false
	}

	if f.HasMissingRanges() {
		// TODO: this could be implemented as a binary search
		for _, ackRange := range f.AckRanges {
			if p >= ackRange.First && p <= ackRange.Last {
				return true
			}
		}
		return false
	}
	// if packet doesn't have missing ranges
	return (p >= f.LowestAcked && p <= f.LargestAcked)
}
