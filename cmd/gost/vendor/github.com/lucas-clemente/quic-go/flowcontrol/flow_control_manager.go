package flowcontrol

import (
	"errors"
	"sync"

	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type flowControlManager struct {
	connectionParametersManager        *handshake.ConnectionParametersManager
	streamFlowController               map[protocol.StreamID]*flowController
	contributesToConnectionFlowControl map[protocol.StreamID]bool
	mutex                              sync.RWMutex
}

var (
	// ErrStreamFlowControlViolation is a stream flow control violation
	ErrStreamFlowControlViolation = errors.New("Stream level flow control violation")
	// ErrConnectionFlowControlViolation is a connection level flow control violation
	ErrConnectionFlowControlViolation = errors.New("Connection level flow control violation")
)

var errMapAccess = errors.New("Error accessing the flowController map.")

// NewFlowControlManager creates a new flow control manager
func NewFlowControlManager(connectionParametersManager *handshake.ConnectionParametersManager) FlowControlManager {
	fcm := flowControlManager{
		connectionParametersManager:        connectionParametersManager,
		streamFlowController:               make(map[protocol.StreamID]*flowController),
		contributesToConnectionFlowControl: make(map[protocol.StreamID]bool),
	}
	// initialize connection level flow controller
	fcm.streamFlowController[0] = newFlowController(0, connectionParametersManager)
	fcm.contributesToConnectionFlowControl[0] = false
	return &fcm
}

// NewStream creates new flow controllers for a stream
func (f *flowControlManager) NewStream(streamID protocol.StreamID, contributesToConnectionFlow bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if _, ok := f.streamFlowController[streamID]; ok {
		return
	}

	f.streamFlowController[streamID] = newFlowController(streamID, f.connectionParametersManager)
	f.contributesToConnectionFlowControl[streamID] = contributesToConnectionFlow
}

// RemoveStream removes a closed stream from flow control
func (f *flowControlManager) RemoveStream(streamID protocol.StreamID) {
	f.mutex.Lock()
	delete(f.streamFlowController, streamID)
	delete(f.contributesToConnectionFlowControl, streamID)
	f.mutex.Unlock()
}

// UpdateHighestReceived updates the highest received byte offset for a stream
// it adds the number of additional bytes to connection level flow control
// streamID must not be 0 here
func (f *flowControlManager) UpdateHighestReceived(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}
	increment := streamFlowController.UpdateHighestReceived(byteOffset)

	if streamFlowController.CheckFlowControlViolation() {
		return ErrStreamFlowControlViolation
	}

	if f.contributesToConnectionFlowControl[streamID] {
		connectionFlowController := f.streamFlowController[0]
		connectionFlowController.IncrementHighestReceived(increment)
		if connectionFlowController.CheckFlowControlViolation() {
			return ErrConnectionFlowControlViolation
		}
	}

	return nil
}

// streamID must not be 0 here
func (f *flowControlManager) AddBytesRead(streamID protocol.StreamID, n protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}

	streamFlowController.AddBytesRead(n)

	if f.contributesToConnectionFlowControl[streamID] {
		f.streamFlowController[0].AddBytesRead(n)
	}

	return nil
}

func (f *flowControlManager) GetWindowUpdates() (res []WindowUpdate) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for id, fc := range f.streamFlowController {
		if necessary, offset := fc.MaybeTriggerWindowUpdate(); necessary {
			res = append(res, WindowUpdate{StreamID: id, Offset: offset})
		}
	}
	return res
}

// streamID must not be 0 here
func (f *flowControlManager) AddBytesSent(streamID protocol.StreamID, n protocol.ByteCount) error {
	// Only lock the part reading from the map, since send-windows are only accessed from the session goroutine.
	f.mutex.Lock()
	streamFlowController, err := f.getFlowController(streamID)
	f.mutex.Unlock()
	if err != nil {
		return err
	}

	streamFlowController.AddBytesSent(n)

	if f.contributesToConnectionFlowControl[streamID] {
		f.streamFlowController[0].AddBytesSent(n)
	}

	return nil
}

// must not be called with StreamID 0
func (f *flowControlManager) SendWindowSize(streamID protocol.StreamID) (protocol.ByteCount, error) {
	// Only lock the part reading from the map, since send-windows are only accessed from the session goroutine.
	f.mutex.RLock()
	streamFlowController, err := f.getFlowController(streamID)
	f.mutex.RUnlock()
	if err != nil {
		return 0, err
	}
	res := streamFlowController.SendWindowSize()

	contributes, ok := f.contributesToConnectionFlowControl[streamID]
	if !ok {
		return 0, errMapAccess
	}
	if contributes {
		res = utils.MinByteCount(res, f.streamFlowController[0].SendWindowSize())
	}

	return res, nil
}

func (f *flowControlManager) RemainingConnectionWindowSize() protocol.ByteCount {
	// Only lock the part reading from the map, since send-windows are only accessed from the session goroutine.
	f.mutex.RLock()
	res := f.streamFlowController[0].SendWindowSize()
	f.mutex.RUnlock()
	return res
}

// streamID may be 0 here
func (f *flowControlManager) UpdateWindow(streamID protocol.StreamID, offset protocol.ByteCount) (bool, error) {
	// Only lock the part reading from the map, since send-windows are only accessed from the session goroutine.
	f.mutex.Lock()
	streamFlowController, err := f.getFlowController(streamID)
	f.mutex.Unlock()
	if err != nil {
		return false, err
	}

	return streamFlowController.UpdateSendWindow(offset), nil
}

func (f *flowControlManager) getFlowController(streamID protocol.StreamID) (*flowController, error) {
	streamFlowController, ok := f.streamFlowController[streamID]
	if !ok {
		return nil, errMapAccess
	}
	return streamFlowController, nil
}
