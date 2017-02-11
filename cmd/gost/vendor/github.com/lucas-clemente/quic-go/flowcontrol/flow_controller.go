package flowcontrol

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type flowController struct {
	streamID protocol.StreamID

	connectionParameters handshake.ConnectionParametersManager
	rttStats             *congestion.RTTStats

	bytesSent             protocol.ByteCount
	sendFlowControlWindow protocol.ByteCount

	lastWindowUpdateTime time.Time

	bytesRead                            protocol.ByteCount
	highestReceived                      protocol.ByteCount
	receiveFlowControlWindow             protocol.ByteCount
	receiveFlowControlWindowIncrement    protocol.ByteCount
	maxReceiveFlowControlWindowIncrement protocol.ByteCount
}

// ErrReceivedSmallerByteOffset occurs if the ByteOffset received is smaller than a ByteOffset that was set previously
var ErrReceivedSmallerByteOffset = errors.New("Received a smaller byte offset")

// newFlowController gets a new flow controller
func newFlowController(streamID protocol.StreamID, connectionParameters handshake.ConnectionParametersManager, rttStats *congestion.RTTStats) *flowController {
	fc := flowController{
		streamID:             streamID,
		connectionParameters: connectionParameters,
		rttStats:             rttStats,
	}

	if streamID == 0 {
		fc.receiveFlowControlWindow = connectionParameters.GetReceiveConnectionFlowControlWindow()
		fc.receiveFlowControlWindowIncrement = fc.receiveFlowControlWindow
		fc.maxReceiveFlowControlWindowIncrement = connectionParameters.GetMaxReceiveConnectionFlowControlWindow()
	} else {
		fc.receiveFlowControlWindow = connectionParameters.GetReceiveStreamFlowControlWindow()
		fc.receiveFlowControlWindowIncrement = fc.receiveFlowControlWindow
		fc.maxReceiveFlowControlWindowIncrement = connectionParameters.GetMaxReceiveStreamFlowControlWindow()
	}

	return &fc
}

func (c *flowController) getSendFlowControlWindow() protocol.ByteCount {
	if c.sendFlowControlWindow == 0 {
		if c.streamID == 0 {
			return c.connectionParameters.GetSendConnectionFlowControlWindow()
		}
		return c.connectionParameters.GetSendStreamFlowControlWindow()
	}
	return c.sendFlowControlWindow
}

func (c *flowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
}

func (c *flowController) GetBytesSent() protocol.ByteCount {
	return c.bytesSent
}

// UpdateSendWindow should be called after receiving a WindowUpdateFrame
// it returns true if the window was actually updated
func (c *flowController) UpdateSendWindow(newOffset protocol.ByteCount) bool {
	if newOffset > c.sendFlowControlWindow {
		c.sendFlowControlWindow = newOffset
		return true
	}
	return false
}

func (c *flowController) SendWindowSize() protocol.ByteCount {
	sendFlowControlWindow := c.getSendFlowControlWindow()

	if c.bytesSent > sendFlowControlWindow { // should never happen, but make sure we don't do an underflow here
		return 0
	}
	return sendFlowControlWindow - c.bytesSent
}

func (c *flowController) SendWindowOffset() protocol.ByteCount {
	return c.getSendFlowControlWindow()
}

// UpdateHighestReceived updates the highestReceived value, if the byteOffset is higher
// Should **only** be used for the stream-level FlowController
// it returns an ErrReceivedSmallerByteOffset if the received byteOffset is smaller than any byteOffset received before
// This error occurs every time StreamFrames get reordered and has to be ignored in that case
// It should only be treated as an error when resetting a stream
func (c *flowController) UpdateHighestReceived(byteOffset protocol.ByteCount) (protocol.ByteCount, error) {
	if byteOffset == c.highestReceived {
		return 0, nil
	}
	if byteOffset > c.highestReceived {
		increment := byteOffset - c.highestReceived
		c.highestReceived = byteOffset
		return increment, nil
	}
	return 0, ErrReceivedSmallerByteOffset
}

// IncrementHighestReceived adds an increment to the highestReceived value
// Should **only** be used for the connection-level FlowController
func (c *flowController) IncrementHighestReceived(increment protocol.ByteCount) {
	c.highestReceived += increment
}

func (c *flowController) AddBytesRead(n protocol.ByteCount) {
	c.bytesRead += n
}

// MaybeTriggerWindowUpdate determines if it is necessary to send a WindowUpdate
// if so, it returns true and the offset of the window
func (c *flowController) MaybeTriggerWindowUpdate() (bool, protocol.ByteCount) {
	diff := c.receiveFlowControlWindow - c.bytesRead

	// Chromium implements the same threshold
	if diff < (c.receiveFlowControlWindowIncrement / 2) {
		c.maybeAdjustWindowIncrement()
		c.lastWindowUpdateTime = time.Now()

		c.receiveFlowControlWindow = c.bytesRead + c.receiveFlowControlWindowIncrement

		return true, c.receiveFlowControlWindow
	}

	return false, 0
}

// maybeAdjustWindowIncrement increases the receiveFlowControlWindowIncrement if we're sending WindowUpdates too often
func (c *flowController) maybeAdjustWindowIncrement() {
	if c.lastWindowUpdateTime.IsZero() {
		return
	}

	rtt := c.rttStats.SmoothedRTT()
	if rtt == 0 {
		return
	}

	timeSinceLastWindowUpdate := time.Now().Sub(c.lastWindowUpdateTime)

	// interval between the window updates is sufficiently large, no need to increase the increment
	if timeSinceLastWindowUpdate >= 2*rtt {
		return
	}

	oldWindowSize := c.receiveFlowControlWindowIncrement
	c.receiveFlowControlWindowIncrement = utils.MinByteCount(2*c.receiveFlowControlWindowIncrement, c.maxReceiveFlowControlWindowIncrement)

	// debug log, if the window size was actually increased
	if oldWindowSize < c.receiveFlowControlWindowIncrement {
		newWindowSize := c.receiveFlowControlWindowIncrement / (1 << 10)
		if c.streamID == 0 {
			utils.Debugf("Increasing receive flow control window for the connection to %d kB", newWindowSize)
		} else {
			utils.Debugf("Increasing receive flow control window increment for stream %d to %d kB", c.streamID, newWindowSize)
		}
	}
}

func (c *flowController) CheckFlowControlViolation() bool {
	if c.highestReceived > c.receiveFlowControlWindow {
		return true
	}
	return false
}
