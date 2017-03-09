package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type streamFrameSorter struct {
	queuedFrames map[protocol.ByteCount]*frames.StreamFrame
	readPosition protocol.ByteCount
	gaps         *utils.ByteIntervalList
}

var (
	errTooManyGapsInReceivedStreamData = errors.New("Too many gaps in received StreamFrame data")
	errDuplicateStreamData             = errors.New("Overlapping Stream Data")
	errEmptyStreamData                 = errors.New("Stream Data empty")
)

func newStreamFrameSorter() *streamFrameSorter {
	s := streamFrameSorter{
		gaps:         utils.NewByteIntervalList(),
		queuedFrames: make(map[protocol.ByteCount]*frames.StreamFrame),
	}
	s.gaps.PushFront(utils.ByteInterval{Start: 0, End: protocol.MaxByteCount})
	return &s
}

func (s *streamFrameSorter) Push(frame *frames.StreamFrame) error {
	_, ok := s.queuedFrames[frame.Offset]
	if ok {
		return errDuplicateStreamData
	}

	start := frame.Offset
	end := frame.Offset + frame.DataLen()

	if start == end {
		if frame.FinBit {
			s.queuedFrames[frame.Offset] = frame
			return nil
		}
		return errEmptyStreamData
	}

	var foundInGap bool

	for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
		// the complete frame lies before or after the gap
		if end <= gap.Value.Start || start > gap.Value.End {
			continue
		}

		if start < gap.Value.Start {
			return qerr.Error(qerr.OverlappingStreamData, "start of gap in stream chunk")
		}

		if start < gap.Value.End && end > gap.Value.End {
			return qerr.Error(qerr.OverlappingStreamData, "end of gap in stream chunk")
		}

		foundInGap = true

		if start == gap.Value.Start {
			if end == gap.Value.End {
				s.gaps.Remove(gap)
				break
			}
			if end < gap.Value.End {
				gap.Value.Start = end
				break
			}
		}

		if end == gap.Value.End {
			gap.Value.End = start
			break
		}

		if end < gap.Value.End {
			intv := utils.ByteInterval{Start: end, End: gap.Value.End}
			s.gaps.InsertAfter(intv, gap)
			gap.Value.End = start
			break
		}
	}

	if !foundInGap {
		return errDuplicateStreamData
	}

	if s.gaps.Len() > protocol.MaxStreamFrameSorterGaps {
		return errTooManyGapsInReceivedStreamData
	}

	s.queuedFrames[frame.Offset] = frame
	return nil
}

func (s *streamFrameSorter) Pop() *frames.StreamFrame {
	frame := s.Head()
	if frame != nil {
		s.readPosition += frame.DataLen()
		delete(s.queuedFrames, frame.Offset)
	}
	return frame
}

func (s *streamFrameSorter) Head() *frames.StreamFrame {
	frame, ok := s.queuedFrames[s.readPosition]
	if ok {
		return frame
	}
	return nil
}
