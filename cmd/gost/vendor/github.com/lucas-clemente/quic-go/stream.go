package quic

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
//
// Read() and Write() may be called concurrently, but multiple calls to Read() or Write() individually must be synchronized manually.
type stream struct {
	streamID protocol.StreamID
	onData   func()

	readPosInFrame int
	writeOffset    protocol.ByteCount
	readOffset     protocol.ByteCount

	// Once set, err must not be changed!
	err   error
	mutex sync.Mutex

	// eof is set if we are finished reading
	eof int32 // really a bool
	// closed is set when we are finished writing
	closed int32 // really a bool

	frameQueue        *streamFrameSorter
	newFrameOrErrCond sync.Cond

	dataForWriting       []byte
	finSent              bool
	doneWritingOrErrCond sync.Cond

	flowControlManager flowcontrol.FlowControlManager
}

// newStream creates a new Stream
func newStream(StreamID protocol.StreamID, onData func(), flowControlManager flowcontrol.FlowControlManager) (*stream, error) {
	s := &stream{
		onData:             onData,
		streamID:           StreamID,
		flowControlManager: flowControlManager,
		frameQueue:         newStreamFrameSorter(),
	}

	s.newFrameOrErrCond.L = &s.mutex
	s.doneWritingOrErrCond.L = &s.mutex

	return s, nil
}

// Read implements io.Reader. It is not thread safe!
func (s *stream) Read(p []byte) (int, error) {
	if atomic.LoadInt32(&s.eof) != 0 {
		return 0, io.EOF
	}

	bytesRead := 0
	for bytesRead < len(p) {
		s.mutex.Lock()
		frame := s.frameQueue.Head()

		if frame == nil && bytesRead > 0 {
			s.mutex.Unlock()
			return bytesRead, s.err
		}

		var err error
		for {
			// Stop waiting on errors
			if s.err != nil {
				err = s.err
				break
			}
			if frame != nil {
				s.readPosInFrame = int(s.readOffset - frame.Offset)
				break
			}
			s.newFrameOrErrCond.Wait()
			frame = s.frameQueue.Head()
		}
		s.mutex.Unlock()
		// Here, either frame != nil xor err != nil

		if frame == nil {
			atomic.StoreInt32(&s.eof, 1)
			// We have an err and no data, return the error
			return bytesRead, err
		}

		m := utils.Min(len(p)-bytesRead, int(frame.DataLen())-s.readPosInFrame)

		if bytesRead > len(p) {
			return bytesRead, fmt.Errorf("BUG: bytesRead (%d) > len(p) (%d) in stream.Read", bytesRead, len(p))
		}
		if s.readPosInFrame > int(frame.DataLen()) {
			return bytesRead, fmt.Errorf("BUG: readPosInFrame (%d) > frame.DataLen (%d) in stream.Read", s.readPosInFrame, frame.DataLen())
		}
		copy(p[bytesRead:], frame.Data[s.readPosInFrame:])

		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += protocol.ByteCount(m)

		s.flowControlManager.AddBytesRead(s.streamID, protocol.ByteCount(m))
		s.onData() // so that a possible WINDOW_UPDATE is sent

		if s.readPosInFrame >= int(frame.DataLen()) {
			fin := frame.FinBit
			s.mutex.Lock()
			s.frameQueue.Pop()
			s.mutex.Unlock()
			if fin {
				atomic.StoreInt32(&s.eof, 1)
				return bytesRead, io.EOF
			}
		}
	}

	return bytesRead, nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.err != nil {
		return 0, s.err
	}

	if len(p) == 0 {
		return 0, nil
	}

	s.dataForWriting = make([]byte, len(p))
	copy(s.dataForWriting, p)

	s.onData()

	for s.dataForWriting != nil && s.err == nil {
		s.doneWritingOrErrCond.Wait()
	}

	if s.err != nil {
		return 0, s.err
	}

	return len(p), nil
}

func (s *stream) lenOfDataForWriting() protocol.ByteCount {
	s.mutex.Lock()
	l := protocol.ByteCount(len(s.dataForWriting))
	s.mutex.Unlock()
	return l
}

func (s *stream) getDataForWriting(maxBytes protocol.ByteCount) []byte {
	s.mutex.Lock()
	if s.dataForWriting == nil {
		s.mutex.Unlock()
		return nil
	}
	var ret []byte
	if protocol.ByteCount(len(s.dataForWriting)) > maxBytes {
		ret = s.dataForWriting[:maxBytes]
		s.dataForWriting = s.dataForWriting[maxBytes:]
	} else {
		ret = s.dataForWriting
		s.dataForWriting = nil
		s.doneWritingOrErrCond.Signal()
	}
	s.writeOffset += protocol.ByteCount(len(ret))
	s.mutex.Unlock()
	return ret
}

// Close implements io.Closer
func (s *stream) Close() error {
	atomic.StoreInt32(&s.closed, 1)
	s.onData()
	return nil
}

func (s *stream) shouldSendFin() bool {
	s.mutex.Lock()
	res := atomic.LoadInt32(&s.closed) != 0 && !s.finSent && s.err == nil && s.dataForWriting == nil
	s.mutex.Unlock()
	return res
}

func (s *stream) sentFin() {
	s.mutex.Lock()
	s.finSent = true
	s.mutex.Unlock()
}

// AddStreamFrame adds a new stream frame
func (s *stream) AddStreamFrame(frame *frames.StreamFrame) error {
	maxOffset := frame.Offset + frame.DataLen()
	err := s.flowControlManager.UpdateHighestReceived(s.streamID, maxOffset)

	if err == flowcontrol.ErrStreamFlowControlViolation {
		return qerr.FlowControlReceivedTooMuchData
	}
	if err == flowcontrol.ErrConnectionFlowControlViolation {
		return qerr.FlowControlReceivedTooMuchData
	}
	if err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	err = s.frameQueue.Push(frame)
	if err != nil && err != errDuplicateStreamData {
		return err
	}
	s.newFrameOrErrCond.Signal()
	return nil
}

// CloseRemote makes the stream receive a "virtual" FIN stream frame at a given offset
func (s *stream) CloseRemote(offset protocol.ByteCount) {
	s.AddStreamFrame(&frames.StreamFrame{FinBit: true, Offset: offset})
}

// RegisterError is called by session to indicate that an error occurred and the
// stream should be closed.
func (s *stream) RegisterError(err error) {
	atomic.StoreInt32(&s.closed, 1)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.err != nil { // s.err must not be changed!
		return
	}
	s.err = err
	s.doneWritingOrErrCond.Signal()
	s.newFrameOrErrCond.Signal()
}

func (s *stream) finishedReading() bool {
	return atomic.LoadInt32(&s.eof) != 0
}

func (s *stream) finishedWriting() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.err != nil || (atomic.LoadInt32(&s.closed) != 0 && s.finSent)
}

func (s *stream) finished() bool {
	return s.finishedReading() && s.finishedWriting()
}

func (s *stream) StreamID() protocol.StreamID {
	return s.streamID
}
