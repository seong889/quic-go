package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_STREAM_ID frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x06,
				0xde, 0xca, 0xfb, 0xad, // stream ID
			})
			f, err := ParseMaxStreamIDFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.StreamID).To(Equal(protocol.StreamID(0xdecafbad)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x6,
				0xde, 0xad, 0xbe, 0xef, // stream id
			}
			_, err := ParseMaxStreamIDFrame(bytes.NewReader(data), protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseMaxStreamIDFrame(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := MaxStreamIDFrame{StreamID: 0x12345678}
			frame.Write(b, protocol.VersionWhatever)
			Expect(b.Bytes()).To(Equal([]byte{0x6, 0x12, 0x34, 0x56, 0x78}))
		})

		It("has the correct min length", func() {
			frame := MaxStreamIDFrame{}
			Expect(frame.MinLength(protocol.VersionWhatever)).To(Equal(protocol.ByteCount(5)))
		})
	})
})
