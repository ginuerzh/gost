package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// ConnectionParametersManager stores the connection parameters
// Warning: Writes may only be done from the crypto stream, see the comment
// in GetSHLOMap().
type ConnectionParametersManager struct {
	params map[Tag][]byte
	mutex  sync.RWMutex

	flowControlNegotiated bool // have the flow control parameters for sending already been negotiated

	maxStreamsPerConnection            uint32
	idleConnectionStateLifetime        time.Duration
	sendStreamFlowControlWindow        protocol.ByteCount
	sendConnectionFlowControlWindow    protocol.ByteCount
	receiveStreamFlowControlWindow     protocol.ByteCount
	receiveConnectionFlowControlWindow protocol.ByteCount
}

var errTagNotInConnectionParameterMap = errors.New("ConnectionParametersManager: Tag not found in ConnectionsParameter map")

// ErrMalformedTag is returned when the tag value cannot be read
var (
	ErrMalformedTag                         = qerr.Error(qerr.InvalidCryptoMessageParameter, "malformed Tag value")
	ErrFlowControlRenegotiationNotSupported = qerr.Error(qerr.InvalidCryptoMessageParameter, "renegotiation of flow control parameters not supported")
)

// NewConnectionParamatersManager creates a new connection parameters manager
func NewConnectionParamatersManager() *ConnectionParametersManager {
	return &ConnectionParametersManager{
		params: make(map[Tag][]byte),
		idleConnectionStateLifetime:        protocol.DefaultIdleTimeout,
		sendStreamFlowControlWindow:        protocol.InitialStreamFlowControlWindow,     // can only be changed by the client
		sendConnectionFlowControlWindow:    protocol.InitialConnectionFlowControlWindow, // can only be changed by the client
		receiveStreamFlowControlWindow:     protocol.ReceiveStreamFlowControlWindow,
		receiveConnectionFlowControlWindow: protocol.ReceiveConnectionFlowControlWindow,
		maxStreamsPerConnection:            protocol.MaxStreamsPerConnection,
	}
}

// SetFromMap reads all params
func (h *ConnectionParametersManager) SetFromMap(params map[Tag][]byte) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for key, value := range params {
		switch key {
		case TagTCID:
			h.params[key] = value
		case TagMSPC:
			clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.maxStreamsPerConnection = h.negotiateMaxStreamsPerConnection(clientValue)
		case TagICSL:
			clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.idleConnectionStateLifetime = h.negotiateIdleConnectionStateLifetime(time.Duration(clientValue) * time.Second)
		case TagSFCW:
			if h.flowControlNegotiated {
				return ErrFlowControlRenegotiationNotSupported
			}
			sendStreamFlowControlWindow, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.sendStreamFlowControlWindow = protocol.ByteCount(sendStreamFlowControlWindow)
		case TagCFCW:
			if h.flowControlNegotiated {
				return ErrFlowControlRenegotiationNotSupported
			}
			sendConnectionFlowControlWindow, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.sendConnectionFlowControlWindow = protocol.ByteCount(sendConnectionFlowControlWindow)
		}
	}

	_, containsSFCW := params[TagSFCW]
	_, containsCFCW := params[TagCFCW]
	if containsCFCW || containsSFCW {
		h.flowControlNegotiated = true
	}

	return nil
}

func (h *ConnectionParametersManager) negotiateMaxStreamsPerConnection(clientValue uint32) uint32 {
	return utils.MinUint32(clientValue, protocol.MaxStreamsPerConnection)
}

func (h *ConnectionParametersManager) negotiateIdleConnectionStateLifetime(clientValue time.Duration) time.Duration {
	return utils.MinDuration(clientValue, protocol.MaxIdleTimeout)
}

// getRawValue gets the byte-slice for a tag
func (h *ConnectionParametersManager) getRawValue(tag Tag) ([]byte, error) {
	h.mutex.RLock()
	rawValue, ok := h.params[tag]
	h.mutex.RUnlock()

	if !ok {
		return nil, errTagNotInConnectionParameterMap
	}
	return rawValue, nil
}

// GetSHLOMap gets all values (except crypto values) needed for the SHLO
func (h *ConnectionParametersManager) GetSHLOMap() map[Tag][]byte {
	sfcw := bytes.NewBuffer([]byte{})
	utils.WriteUint32(sfcw, uint32(h.GetReceiveStreamFlowControlWindow()))
	cfcw := bytes.NewBuffer([]byte{})
	utils.WriteUint32(cfcw, uint32(h.GetReceiveConnectionFlowControlWindow()))
	mspc := bytes.NewBuffer([]byte{})
	utils.WriteUint32(mspc, h.GetMaxStreamsPerConnection())
	mids := bytes.NewBuffer([]byte{})
	utils.WriteUint32(mids, protocol.MaxIncomingDynamicStreams)
	icsl := bytes.NewBuffer([]byte{})
	utils.WriteUint32(icsl, uint32(h.GetIdleConnectionStateLifetime()/time.Second))

	return map[Tag][]byte{
		TagICSL: icsl.Bytes(),
		TagMSPC: mspc.Bytes(),
		TagMIDS: mids.Bytes(),
		TagCFCW: cfcw.Bytes(),
		TagSFCW: sfcw.Bytes(),
	}
}

// GetSendStreamFlowControlWindow gets the size of the stream-level flow control window for sending data
func (h *ConnectionParametersManager) GetSendStreamFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.sendStreamFlowControlWindow
}

// GetSendConnectionFlowControlWindow gets the size of the stream-level flow control window for sending data
func (h *ConnectionParametersManager) GetSendConnectionFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.sendConnectionFlowControlWindow
}

// GetReceiveStreamFlowControlWindow gets the size of the stream-level flow control window for receiving data
func (h *ConnectionParametersManager) GetReceiveStreamFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.receiveStreamFlowControlWindow
}

// GetReceiveConnectionFlowControlWindow gets the size of the stream-level flow control window for receiving data
func (h *ConnectionParametersManager) GetReceiveConnectionFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.receiveConnectionFlowControlWindow
}

// GetMaxStreamsPerConnection gets the maximum number of streams per connection
func (h *ConnectionParametersManager) GetMaxStreamsPerConnection() uint32 {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.maxStreamsPerConnection
}

// GetIdleConnectionStateLifetime gets the idle timeout
func (h *ConnectionParametersManager) GetIdleConnectionStateLifetime() time.Duration {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.idleConnectionStateLifetime
}

// TruncateConnectionID determines if the client requests truncated ConnectionIDs
func (h *ConnectionParametersManager) TruncateConnectionID() bool {
	rawValue, err := h.getRawValue(TagTCID)
	if err != nil {
		return false
	}
	if len(rawValue) != 4 {
		return false
	}
	value := binary.LittleEndian.Uint32(rawValue)
	if value == 0 {
		return true
	}
	return false
}
