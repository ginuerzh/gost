package quic

import (
	"errors"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

type streamsMap struct {
	mutex sync.RWMutex

	perspective protocol.Perspective

	streams map[protocol.StreamID]streamI
	// needed for round-robin scheduling
	openStreams     []protocol.StreamID
	roundRobinIndex int

	nextStream                protocol.StreamID // StreamID of the next Stream that will be returned by OpenStream()
	highestStreamOpenedByPeer protocol.StreamID
	nextStreamOrErrCond       sync.Cond
	openStreamOrErrCond       sync.Cond

	closeErr           error
	nextStreamToAccept protocol.StreamID

	newStream newStreamLambda

	numOutgoingStreams uint32
	numIncomingStreams uint32
	maxIncomingStreams uint32
	maxOutgoingStreams uint32
}

type streamLambda func(streamI) (bool, error)
type newStreamLambda func(protocol.StreamID) streamI

var errMapAccess = errors.New("streamsMap: Error accessing the streams map")

func newStreamsMap(newStream newStreamLambda, pers protocol.Perspective, ver protocol.VersionNumber) *streamsMap {
	// add some tolerance to the maximum incoming streams value
	maxStreams := uint32(protocol.MaxIncomingStreams)
	maxIncomingStreams := utils.MaxUint32(
		maxStreams+protocol.MaxStreamsMinimumIncrement,
		uint32(float64(maxStreams)*float64(protocol.MaxStreamsMultiplier)),
	)
	sm := streamsMap{
		perspective:        pers,
		streams:            make(map[protocol.StreamID]streamI),
		openStreams:        make([]protocol.StreamID, 0),
		newStream:          newStream,
		maxIncomingStreams: maxIncomingStreams,
	}
	sm.nextStreamOrErrCond.L = &sm.mutex
	sm.openStreamOrErrCond.L = &sm.mutex

	nextOddStream := protocol.StreamID(1)
	if ver.CryptoStreamID() == protocol.StreamID(1) {
		nextOddStream = 3
	}
	if pers == protocol.PerspectiveClient {
		sm.nextStream = nextOddStream
		sm.nextStreamToAccept = 2
	} else {
		sm.nextStream = 2
		sm.nextStreamToAccept = nextOddStream
	}

	return &sm
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (m *streamsMap) GetOrOpenStream(id protocol.StreamID) (streamI, error) {
	m.mutex.RLock()
	s, ok := m.streams[id]
	m.mutex.RUnlock()
	if ok {
		return s, nil // s may be nil
	}

	// ... we don't have an existing stream
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// We need to check whether another invocation has already created a stream (between RUnlock() and Lock()).
	s, ok = m.streams[id]
	if ok {
		return s, nil
	}

	if m.perspective == protocol.PerspectiveServer {
		if id%2 == 0 {
			if id <= m.nextStream { // this is a server-side stream that we already opened. Must have been closed already
				return nil, nil
			}
			return nil, qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("attempted to open stream %d from client-side", id))
		}
		if id <= m.highestStreamOpenedByPeer { // this is a client-side stream that doesn't exist anymore. Must have been closed already
			return nil, nil
		}
	}
	if m.perspective == protocol.PerspectiveClient {
		if id%2 == 1 {
			if id <= m.nextStream { // this is a client-side stream that we already opened.
				return nil, nil
			}
			return nil, qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("attempted to open stream %d from server-side", id))
		}
		if id <= m.highestStreamOpenedByPeer { // this is a server-side stream that doesn't exist anymore. Must have been closed already
			return nil, nil
		}
	}

	// sid is the next stream that will be opened
	sid := m.highestStreamOpenedByPeer + 2
	// if there is no stream opened yet, and this is the server, stream 1 should be openend
	if sid == 2 && m.perspective == protocol.PerspectiveServer {
		sid = 1
	}

	for ; sid <= id; sid += 2 {
		_, err := m.openRemoteStream(sid)
		if err != nil {
			return nil, err
		}
	}

	m.nextStreamOrErrCond.Broadcast()
	return m.streams[id], nil
}

func (m *streamsMap) openRemoteStream(id protocol.StreamID) (streamI, error) {
	if m.numIncomingStreams >= m.maxIncomingStreams {
		return nil, qerr.TooManyOpenStreams
	}
	if id+protocol.MaxNewStreamIDDelta < m.highestStreamOpenedByPeer {
		return nil, qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("attempted to open stream %d, which is a lot smaller than the highest opened stream, %d", id, m.highestStreamOpenedByPeer))
	}

	if m.perspective == protocol.PerspectiveServer {
		m.numIncomingStreams++
	} else {
		m.numOutgoingStreams++
	}

	if id > m.highestStreamOpenedByPeer {
		m.highestStreamOpenedByPeer = id
	}

	s := m.newStream(id)
	m.putStream(s)
	return s, nil
}

func (m *streamsMap) openStreamImpl() (streamI, error) {
	id := m.nextStream
	if m.numOutgoingStreams >= m.maxOutgoingStreams {
		return nil, qerr.TooManyOpenStreams
	}

	if m.perspective == protocol.PerspectiveServer {
		m.numOutgoingStreams++
	} else {
		m.numIncomingStreams++
	}

	m.nextStream += 2
	s := m.newStream(id)
	m.putStream(s)
	return s, nil
}

// OpenStream opens the next available stream
func (m *streamsMap) OpenStream() (streamI, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closeErr != nil {
		return nil, m.closeErr
	}
	return m.openStreamImpl()
}

func (m *streamsMap) OpenStreamSync() (streamI, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for {
		if m.closeErr != nil {
			return nil, m.closeErr
		}
		str, err := m.openStreamImpl()
		if err == nil {
			return str, err
		}
		if err != nil && err != qerr.TooManyOpenStreams {
			return nil, err
		}
		m.openStreamOrErrCond.Wait()
	}
}

// AcceptStream returns the next stream opened by the peer
// it blocks until a new stream is opened
func (m *streamsMap) AcceptStream() (streamI, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	var str streamI
	for {
		var ok bool
		if m.closeErr != nil {
			return nil, m.closeErr
		}
		str, ok = m.streams[m.nextStreamToAccept]
		if ok {
			break
		}
		m.nextStreamOrErrCond.Wait()
	}
	m.nextStreamToAccept += 2
	return str, nil
}

func (m *streamsMap) DeleteClosedStreams() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var numDeletedStreams int
	// for every closed stream, the streamID is replaced by 0 in the openStreams slice
	for i, streamID := range m.openStreams {
		str, ok := m.streams[streamID]
		if !ok {
			return errMapAccess
		}
		if !str.Finished() {
			continue
		}
		numDeletedStreams++
		m.openStreams[i] = 0
		if streamID%2 == 0 {
			m.numOutgoingStreams--
		} else {
			m.numIncomingStreams--
		}
		delete(m.streams, streamID)
	}

	if numDeletedStreams == 0 {
		return nil
	}

	// remove all 0s (representing closed streams) from the openStreams slice
	// and adjust the roundRobinIndex
	var j int
	for i, id := range m.openStreams {
		if i != j {
			m.openStreams[j] = m.openStreams[i]
		}
		if id != 0 {
			j++
		} else if j < m.roundRobinIndex {
			m.roundRobinIndex--
		}
	}
	m.openStreams = m.openStreams[:len(m.openStreams)-numDeletedStreams]
	m.openStreamOrErrCond.Signal()
	return nil
}

// RoundRobinIterate executes the streamLambda for every open stream, until the streamLambda returns false
// It uses a round-robin-like scheduling to ensure that every stream is considered fairly
// It prioritizes the the header-stream (StreamID 3)
func (m *streamsMap) RoundRobinIterate(fn streamLambda) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	numStreams := len(m.streams)
	startIndex := m.roundRobinIndex

	for i := 0; i < numStreams; i++ {
		streamID := m.openStreams[(i+startIndex)%numStreams]
		cont, err := m.iterateFunc(streamID, fn)
		if err != nil {
			return err
		}
		m.roundRobinIndex = (m.roundRobinIndex + 1) % numStreams
		if !cont {
			break
		}
	}
	return nil
}

// Range executes a callback for all streams, in pseudo-random order
func (m *streamsMap) Range(cb func(s streamI)) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.streams {
		if s != nil {
			cb(s)
		}
	}
}

func (m *streamsMap) iterateFunc(streamID protocol.StreamID, fn streamLambda) (bool, error) {
	str, ok := m.streams[streamID]
	if !ok {
		return true, errMapAccess
	}
	return fn(str)
}

func (m *streamsMap) putStream(s streamI) error {
	id := s.StreamID()
	if _, ok := m.streams[id]; ok {
		return fmt.Errorf("a stream with ID %d already exists", id)
	}

	m.streams[id] = s
	m.openStreams = append(m.openStreams, id)
	return nil
}

func (m *streamsMap) CloseWithError(err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.closeErr = err
	m.nextStreamOrErrCond.Broadcast()
	m.openStreamOrErrCond.Broadcast()
	for _, s := range m.openStreams {
		m.streams[s].Cancel(err)
	}
}

func (m *streamsMap) UpdateMaxStreamLimit(limit uint32) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.maxOutgoingStreams = limit
}
