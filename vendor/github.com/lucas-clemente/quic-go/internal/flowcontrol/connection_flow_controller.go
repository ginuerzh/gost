package flowcontrol

import (
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

type connectionFlowController struct {
	baseFlowController
}

var _ ConnectionFlowController = &connectionFlowController{}

// NewConnectionFlowController gets a new flow controller for the connection
// It is created before we receive the peer's transport paramenters, thus it starts with a sendWindow of 0.
func NewConnectionFlowController(
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	rttStats *congestion.RTTStats,
) ConnectionFlowController {
	return &connectionFlowController{
		baseFlowController: baseFlowController{
			rttStats:                  rttStats,
			receiveWindow:             receiveWindow,
			receiveWindowIncrement:    receiveWindow,
			maxReceiveWindowIncrement: maxReceiveWindow,
		},
	}
}

func (c *connectionFlowController) SendWindowSize() protocol.ByteCount {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.baseFlowController.sendWindowSize()
}

// IncrementHighestReceived adds an increment to the highestReceived value
func (c *connectionFlowController) IncrementHighestReceived(increment protocol.ByteCount) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.highestReceived += increment
	if c.checkFlowControlViolation() {
		return qerr.Error(qerr.FlowControlReceivedTooMuchData, fmt.Sprintf("Received %d bytes for the connection, allowed %d bytes", c.highestReceived, c.receiveWindow))
	}
	return nil
}

func (c *connectionFlowController) GetWindowUpdate() protocol.ByteCount {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	oldWindowIncrement := c.receiveWindowIncrement
	offset := c.baseFlowController.getWindowUpdate()
	if oldWindowIncrement < c.receiveWindowIncrement {
		utils.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowIncrement/(1<<10))
	}
	return offset
}

// EnsureMinimumWindowIncrement sets a minimum window increment
// it should make sure that the connection-level window is increased when a stream-level window grows
func (c *connectionFlowController) EnsureMinimumWindowIncrement(inc protocol.ByteCount) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if inc > c.receiveWindowIncrement {
		c.receiveWindowIncrement = utils.MinByteCount(inc, c.maxReceiveWindowIncrement)
		c.lastWindowUpdateTime = time.Time{} // disables autotuning for the next window update
	}
}
