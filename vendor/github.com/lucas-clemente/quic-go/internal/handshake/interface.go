package handshake

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// Sealer seals a packet
type Sealer interface {
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	Overhead() int
}

// CryptoSetup is a crypto setup
type CryptoSetup interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
	HandleCryptoStream() error
	// TODO: clean up this interface
	DiversificationNonce() []byte           // only needed for cryptoSetupServer
	SetDiversificationNonce([]byte)         // only needed for cryptoSetupClient
	GetNextPacketType() protocol.PacketType // only needed for cryptoSetupServer

	GetSealer() (protocol.EncryptionLevel, Sealer)
	GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (Sealer, error)
	GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer)
}
