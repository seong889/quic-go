package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM_ID_BLOCKED frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0xa})
			_, err := ParseStreamIDBlockedFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			_, err := ParseStreamIDBlockedFrame(bytes.NewReader(nil), protocol.VersionWhatever)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := StreamIDBlockedFrame{}
			err := frame.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0xa}))
		})

		It("has the correct min length", func() {
			frame := StreamIDBlockedFrame{}
			Expect(frame.MinLength(0)).To(Equal(protocol.ByteCount(1)))
		})
	})
})
