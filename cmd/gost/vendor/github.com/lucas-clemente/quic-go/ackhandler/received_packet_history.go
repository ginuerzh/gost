package ackhandler

import (
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type receivedPacketHistory struct {
	ranges *utils.PacketIntervalList

	mutex sync.RWMutex
}

// newReceivedPacketHistory creates a new received packet history
func newReceivedPacketHistory() *receivedPacketHistory {
	return &receivedPacketHistory{
		ranges: utils.NewPacketIntervalList(),
	}
}

// ReceivedPacket registers a packet with PacketNumber p and updates the ranges
func (h *receivedPacketHistory) ReceivedPacket(p protocol.PacketNumber) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.ranges.Len() == 0 {
		h.ranges.PushBack(utils.PacketInterval{Start: p, End: p})
		return
	}

	for el := h.ranges.Back(); el != nil; el = el.Prev() {
		// p already included in an existing range. Nothing to do here
		if p >= el.Value.Start && p <= el.Value.End {
			return
		}

		var rangeExtended bool
		if el.Value.End == p-1 { // extend a range at the end
			rangeExtended = true
			el.Value.End = p
		} else if el.Value.Start == p+1 { // extend a range at the beginning
			rangeExtended = true
			el.Value.Start = p
		}

		// if a range was extended (either at the beginning or at the end, maybe it is possible to merge two ranges into one)
		if rangeExtended {
			prev := el.Prev()
			if prev != nil && prev.Value.End+1 == el.Value.Start { // merge two ranges
				prev.Value.End = el.Value.End
				h.ranges.Remove(el)
				return
			}
			return // if the two ranges were not merge, we're done here
		}

		// create a new range at the end
		if p > el.Value.End {
			h.ranges.InsertAfter(utils.PacketInterval{Start: p, End: p}, el)
			return
		}
	}

	// create a new range at the beginning
	h.ranges.InsertBefore(utils.PacketInterval{Start: p, End: p}, h.ranges.Front())
}

func (h *receivedPacketHistory) DeleteBelow(leastUnacked protocol.PacketNumber) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	nextEl := h.ranges.Front()
	for el := h.ranges.Front(); nextEl != nil; el = nextEl {
		nextEl = el.Next()

		if leastUnacked > el.Value.Start && leastUnacked <= el.Value.End {
			el.Value.Start = leastUnacked
		}
		if el.Value.End < leastUnacked { // delete a whole range
			h.ranges.Remove(el)
		} else {
			return
		}
	}
}

// GetAckRanges gets a slice of all AckRanges that can be used in an AckFrame
func (h *receivedPacketHistory) GetAckRanges() []frames.AckRange {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.ranges.Len() == 0 {
		return nil
	}

	var ackRanges []frames.AckRange

	for el := h.ranges.Back(); el != nil; el = el.Prev() {
		ackRanges = append(ackRanges, frames.AckRange{FirstPacketNumber: el.Value.Start, LastPacketNumber: el.Value.End})
	}

	return ackRanges
}
