package smux

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
)

// Stream implements io.ReadWriteCloser
type Stream struct {
	id          uint32
	rstflag     int32
	sess        *Session
	buffer      bytes.Buffer
	bufferLock  sync.Mutex
	frameSize   int
	chReadEvent chan struct{} // notify a read event
	die         chan struct{} // flag the stream has closed
	dieLock     sync.Mutex
}

// newStream initiates a Stream struct
func newStream(id uint32, frameSize int, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.chReadEvent = make(chan struct{}, 1)
	s.frameSize = frameSize
	s.sess = sess
	s.die = make(chan struct{})
	return s
}

// Read implements io.ReadWriteCloser
func (s *Stream) Read(b []byte) (n int, err error) {
READ:
	select {
	case <-s.die:
		return 0, errors.New(errBrokenPipe)
	default:
	}

	s.bufferLock.Lock()
	n, err = s.buffer.Read(b)
	s.bufferLock.Unlock()

	if n > 0 {
		s.sess.returnTokens(n)
		return n, nil
	} else if atomic.LoadInt32(&s.rstflag) == 1 {
		_ = s.Close()
		return 0, errors.New(errConnReset)
	}

	select {
	case <-s.chReadEvent:
		goto READ
	case <-s.die:
		return 0, errors.New(errBrokenPipe)
	}
}

// Write implements io.ReadWriteCloser
func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.die:
		return 0, errors.New(errBrokenPipe)
	default:
	}

	frames := s.split(b, cmdPSH, s.id)
	// preallocate buffer
	buffer := make([]byte, len(frames)*headerSize+len(b))
	bts := buffer

	// combine frames into a large blob
	for k := range frames {
		bts[0] = version
		bts[1] = frames[k].cmd
		binary.LittleEndian.PutUint16(bts[2:], uint16(len(frames[k].data)))
		binary.LittleEndian.PutUint32(bts[4:], frames[k].sid)
		copy(bts[headerSize:], frames[k].data)
		bts = bts[len(frames[k].data)+headerSize:]
	}

	if _, err = s.sess.writeBinary(buffer); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close implements io.ReadWriteCloser
func (s *Stream) Close() error {
	s.dieLock.Lock()
	defer s.dieLock.Unlock()

	select {
	case <-s.die:
		return errors.New(errBrokenPipe)
	default:
		close(s.die)
		s.sess.streamClosed(s.id)
		_, err := s.sess.writeFrame(newFrame(cmdRST, s.id))
		return err
	}
}

// session closes the stream
func (s *Stream) sessionClose() {
	s.dieLock.Lock()
	defer s.dieLock.Unlock()

	select {
	case <-s.die:
	default:
		close(s.die)
	}
}

// pushBytes a slice into buffer
func (s *Stream) pushBytes(p []byte) {
	s.bufferLock.Lock()
	s.buffer.Write(p)
	s.bufferLock.Unlock()
}

// recycleTokens transform remaining bytes to tokens(will truncate buffer)
func (s *Stream) recycleTokens() (n int) {
	s.bufferLock.Lock()
	n = s.buffer.Len()
	s.buffer.Reset()
	s.bufferLock.Unlock()
	return
}

// split large byte buffer into smaller frames, reference only
func (s *Stream) split(bts []byte, cmd byte, sid uint32) []Frame {
	var frames []Frame
	for len(bts) > s.frameSize {
		frame := newFrame(cmd, sid)
		frame.data = bts[:s.frameSize]
		bts = bts[s.frameSize:]
		frames = append(frames, frame)
	}
	if len(bts) > 0 {
		frame := newFrame(cmd, sid)
		frame.data = bts
		frames = append(frames, frame)
	}
	return frames
}

// notify read event
func (s *Stream) notifyReadEvent() {
	select {
	case s.chReadEvent <- struct{}{}:
	default:
	}
}

// mark this stream has been reset
func (s *Stream) markRST() {
	atomic.StoreInt32(&s.rstflag, 1)
}
