package quic

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpackedPacket struct {
	encryptionLevel protocol.EncryptionLevel
	frames          []wire.Frame
}

type quicAEAD interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
}

type packetUnpacker struct {
	version protocol.VersionNumber
	aead    quicAEAD
}

func (u *packetUnpacker) Unpack(headerBinary []byte, hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	buf := getPacketBuffer()
	defer putPacketBuffer(buf)
	decrypted, encryptionLevel, err := u.aead.Open(buf, data, hdr.PacketNumber, headerBinary)
	if err != nil {
		// Wrap err in quicError so that public reset is sent by session
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}
	r := bytes.NewReader(decrypted)

	if r.Len() == 0 {
		return nil, qerr.MissingPayload
	}

	fs := make([]wire.Frame, 0, 2)

	// Read all frames in the packet
	for r.Len() > 0 {
		typeByte, _ := r.ReadByte()
		if typeByte == 0x0 { // PADDING frame
			continue
		}
		r.UnreadByte()

		var frame wire.Frame
		if typeByte&0x80 == 0x80 {
			frame, err = wire.ParseStreamFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidStreamData, err.Error())
			} else {
				streamID := frame.(*wire.StreamFrame).StreamID
				if streamID != u.version.CryptoStreamID() && encryptionLevel <= protocol.EncryptionUnencrypted {
					err = qerr.Error(qerr.UnencryptedStreamData, fmt.Sprintf("received unencrypted stream data on stream %d", streamID))
				}
			}
		} else if typeByte&0xc0 == 0x40 {
			frame, err = wire.ParseAckFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidAckData, err.Error())
			}
		} else if typeByte == 0x01 {
			frame, err = wire.ParseRstStreamFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidRstStreamData, err.Error())
			}
		} else if typeByte == 0x02 {
			frame, err = wire.ParseConnectionCloseFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidConnectionCloseData, err.Error())
			}
		} else if typeByte == 0x3 {
			frame, err = wire.ParseGoawayFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidGoawayData, err.Error())
			}
		} else if u.version.UsesMaxDataFrame() && typeByte == 0x4 { // in IETF QUIC, 0x4 is a MAX_DATA frame
			frame, err = wire.ParseMaxDataFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
			}
		} else if typeByte == 0x4 { // in gQUIC, 0x4 is a WINDOW_UPDATE frame
			frame, err = wire.ParseWindowUpdateFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
			}
		} else if u.version.UsesMaxDataFrame() && typeByte == 0x5 { // in IETF QUIC, 0x5 is a MAX_STREAM_DATA frame
			frame, err = wire.ParseMaxStreamDataFrame(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidWindowUpdateData, err.Error())
			}
		} else if typeByte == 0x5 { // in gQUIC, 0x5  is a BLOCKED frame
			frame, err = wire.ParseBlockedFrameLegacy(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidBlockedData, err.Error())
			}
		} else if typeByte == 0x6 {
			frame, err = wire.ParseStopWaitingFrame(r, hdr.PacketNumber, hdr.PacketNumberLen, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidStopWaitingData, err.Error())
			}
		} else if typeByte == 0x7 {
			frame, err = wire.ParsePingFrame(r, u.version)
		} else if u.version.UsesMaxDataFrame() && typeByte == 0x8 { // in IETF QUIC, 0x4 is a BLOCKED frame
			frame, err = wire.ParseBlockedFrame(r, u.version)
		} else if u.version.UsesMaxDataFrame() && typeByte == 0x9 { // in IETF QUIC, 0x4 is a STREAM_BLOCKED frame
			frame, err = wire.ParseBlockedFrameLegacy(r, u.version)
			if err != nil {
				err = qerr.Error(qerr.InvalidBlockedData, err.Error())
			}
		} else {
			err = qerr.Error(qerr.InvalidFrameData, fmt.Sprintf("unknown type byte 0x%x", typeByte))
		}
		if err != nil {
			return nil, err
		}
		if frame != nil {
			fs = append(fs, frame)
		}
	}

	return &unpackedPacket{
		encryptionLevel: encryptionLevel,
		frames:          fs,
	}, nil
}
