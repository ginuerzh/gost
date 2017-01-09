package frames

import "github.com/lucas-clemente/quic-go/utils"

// LogFrame logs a frame, either sent or received
func LogFrame(frame Frame, sent bool) {
	if !utils.Debug() {
		return
	}
	dir := "<-"
	if sent {
		dir = "->"
	}
	if sf, ok := frame.(*StreamFrame); ok {
		utils.Debugf("\t%s &frames.StreamFrame{StreamID: %d, FinBit: %t, Offset: 0x%x, Data length: 0x%x, Offset + Data length: 0x%x}", dir, sf.StreamID, sf.FinBit, sf.Offset, sf.DataLen(), sf.Offset+sf.DataLen())
		return
	}
	utils.Debugf("\t%s %#v", dir, frame)
}
