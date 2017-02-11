package quic

import "github.com/lucas-clemente/quic-go/frames"

type unpackedPacket struct {
	frames []frames.Frame
}

func (u *unpackedPacket) IsRetransmittable() bool {
	for _, f := range u.frames {
		switch f.(type) {
		case *frames.StreamFrame:
			return true
		case *frames.RstStreamFrame:
			return true
		case *frames.WindowUpdateFrame:
			return true
		case *frames.BlockedFrame:
			return true
		case *frames.PingFrame:
			return true
		case *frames.GoawayFrame:
			return true
		}
	}
	return false
}
