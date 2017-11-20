package quic

import (
	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type streamFramer struct {
	streamsMap   *streamsMap
	cryptoStream streamI

	connFlowController flowcontrol.ConnectionFlowController

	retransmissionQueue []*wire.StreamFrame
	blockedFrameQueue   []wire.Frame
}

func newStreamFramer(
	cryptoStream streamI,
	streamsMap *streamsMap,
	cfc flowcontrol.ConnectionFlowController,
) *streamFramer {
	return &streamFramer{
		streamsMap:         streamsMap,
		cryptoStream:       cryptoStream,
		connFlowController: cfc,
	}
}

func (f *streamFramer) AddFrameForRetransmission(frame *wire.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
}

func (f *streamFramer) PopStreamFrames(maxLen protocol.ByteCount) []*wire.StreamFrame {
	fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	return append(fs, f.maybePopNormalFrames(maxLen-currentLen)...)
}

func (f *streamFramer) PopBlockedFrame() wire.Frame {
	if len(f.blockedFrameQueue) == 0 {
		return nil
	}
	frame := f.blockedFrameQueue[0]
	f.blockedFrameQueue = f.blockedFrameQueue[1:]
	return frame
}

func (f *streamFramer) HasFramesForRetransmission() bool {
	return len(f.retransmissionQueue) > 0
}

func (f *streamFramer) HasCryptoStreamFrame() bool {
	return f.cryptoStream.LenOfDataForWriting() > 0
}

// TODO(lclemente): This is somewhat duplicate with the normal path for generating frames.
func (f *streamFramer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *wire.StreamFrame {
	if !f.HasCryptoStreamFrame() {
		return nil
	}
	frame := &wire.StreamFrame{
		StreamID: f.cryptoStream.StreamID(),
		Offset:   f.cryptoStream.GetWriteOffset(),
	}
	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
	frame.Data = f.cryptoStream.GetDataForWriting(maxLen - frameHeaderBytes)
	return frame
}

func (f *streamFramer) maybePopFramesForRetransmission(maxLen protocol.ByteCount) (res []*wire.StreamFrame, currentLen protocol.ByteCount) {
	for len(f.retransmissionQueue) > 0 {
		frame := f.retransmissionQueue[0]
		frame.DataLenPresent = true

		frameHeaderLen, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderLen >= maxLen {
			break
		}

		currentLen += frameHeaderLen

		splitFrame := maybeSplitOffFrame(frame, maxLen-currentLen)
		if splitFrame != nil { // StreamFrame was split
			res = append(res, splitFrame)
			currentLen += splitFrame.DataLen()
			break
		}

		f.retransmissionQueue = f.retransmissionQueue[1:]
		res = append(res, frame)
		currentLen += frame.DataLen()
	}
	return
}

func (f *streamFramer) maybePopNormalFrames(maxBytes protocol.ByteCount) (res []*wire.StreamFrame) {
	frame := &wire.StreamFrame{DataLenPresent: true}
	var currentLen protocol.ByteCount

	fn := func(s streamI) (bool, error) {
		if s == nil {
			return true, nil
		}

		frame.StreamID = s.StreamID()
		frame.Offset = s.GetWriteOffset()
		// not perfect, but thread-safe since writeOffset is only written when getting data
		frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderBytes > maxBytes {
			return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
		}
		maxLen := maxBytes - currentLen - frameHeaderBytes

		var data []byte
		if s.LenOfDataForWriting() > 0 {
			data = s.GetDataForWriting(maxLen)
		}

		// This is unlikely, but check it nonetheless, the scheduler might have jumped in. Seems to happen in ~20% of cases in the tests.
		shouldSendFin := s.ShouldSendFin()
		if data == nil && !shouldSendFin {
			return true, nil
		}

		if shouldSendFin {
			frame.FinBit = true
			s.SentFin()
		}

		frame.Data = data

		// Finally, check if we are now FC blocked and should queue a BLOCKED frame
		if !frame.FinBit && s.IsFlowControlBlocked() {
			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.StreamBlockedFrame{StreamID: s.StreamID()})
		}
		if f.connFlowController.IsBlocked() {
			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{})
		}

		res = append(res, frame)
		currentLen += frameHeaderBytes + frame.DataLen()

		if currentLen == maxBytes {
			return false, nil
		}

		frame = &wire.StreamFrame{DataLenPresent: true}
		return true, nil
	}

	f.streamsMap.RoundRobinIterate(fn)
	return
}

// maybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(frame), nil is returned and nothing is modified.
func maybeSplitOffFrame(frame *wire.StreamFrame, n protocol.ByteCount) *wire.StreamFrame {
	if n >= frame.DataLen() {
		return nil
	}

	defer func() {
		frame.Data = frame.Data[n:]
		frame.Offset += n
	}()

	return &wire.StreamFrame{
		FinBit:         false,
		StreamID:       frame.StreamID,
		Offset:         frame.Offset,
		Data:           frame.Data[:n],
		DataLenPresent: frame.DataLenPresent,
	}
}
