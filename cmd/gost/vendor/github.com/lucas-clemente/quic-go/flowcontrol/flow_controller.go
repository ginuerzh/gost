package flowcontrol

import (
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

type flowController struct {
	streamID protocol.StreamID

	connectionParametersManager *handshake.ConnectionParametersManager

	bytesSent             protocol.ByteCount
	sendFlowControlWindow protocol.ByteCount

	bytesRead                         protocol.ByteCount
	highestReceived                   protocol.ByteCount
	receiveFlowControlWindow          protocol.ByteCount
	receiveFlowControlWindowIncrement protocol.ByteCount
}

// newFlowController gets a new flow controller
func newFlowController(streamID protocol.StreamID, connectionParametersManager *handshake.ConnectionParametersManager) *flowController {
	fc := flowController{
		streamID:                    streamID,
		connectionParametersManager: connectionParametersManager,
	}

	if streamID == 0 {
		fc.receiveFlowControlWindow = connectionParametersManager.GetReceiveConnectionFlowControlWindow()
		fc.receiveFlowControlWindowIncrement = fc.receiveFlowControlWindow
	} else {
		fc.receiveFlowControlWindow = connectionParametersManager.GetReceiveStreamFlowControlWindow()
		fc.receiveFlowControlWindowIncrement = fc.receiveFlowControlWindow
	}

	return &fc
}

func (c *flowController) getSendFlowControlWindow() protocol.ByteCount {
	if c.sendFlowControlWindow == 0 {
		if c.streamID == 0 {
			return c.connectionParametersManager.GetSendConnectionFlowControlWindow()
		}
		return c.connectionParametersManager.GetSendStreamFlowControlWindow()
	}
	return c.sendFlowControlWindow
}

func (c *flowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
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
func (c *flowController) UpdateHighestReceived(byteOffset protocol.ByteCount) protocol.ByteCount {
	if byteOffset > c.highestReceived {
		increment := byteOffset - c.highestReceived
		c.highestReceived = byteOffset
		return increment
	}
	return 0
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
		c.receiveFlowControlWindow = c.bytesRead + c.receiveFlowControlWindowIncrement
		return true, c.receiveFlowControlWindow
	}
	return false, 0
}

func (c *flowController) CheckFlowControlViolation() bool {
	if c.highestReceived > c.receiveFlowControlWindow {
		return true
	}
	return false
}
