package handshake

import (
	"github.com/bifurcation/mint"
)

type transportParameterID uint16

const quicTLSExtensionType = 26

const (
	initialMaxStreamDataParameterID transportParameterID = iota
	initialMaxDataParameterID
	initialMaxStreamIDParameterID
	idleTimeoutParameterID
	omitConnectionIDParameterID
	maxPacketSizeParameterID
	statelessResetTokenParameterID
)

type transportParameter struct {
	Parameter transportParameterID
	Value     []byte `tls:"head=2"`
}

type clientHelloTransportParameters struct {
	NegotiatedVersion uint32               // actually a protocol.VersionNumber
	InitialVersion    uint32               // actually a protocol.VersionNumber
	Parameters        []transportParameter `tls:"head=2"`
}

type encryptedExtensionsTransportParameters struct {
	SupportedVersions []uint32             `tls:"head=1"` // actually a protocol.VersionNumber
	Parameters        []transportParameter `tls:"head=2"`
}

type tlsExtensionBody struct {
	data []byte
}

var _ mint.ExtensionBody = &tlsExtensionBody{}

func (e *tlsExtensionBody) Type() mint.ExtensionType {
	return quicTLSExtensionType
}

func (e *tlsExtensionBody) Marshal() ([]byte, error) {
	return e.data, nil
}

func (e *tlsExtensionBody) Unmarshal(data []byte) (int, error) {
	e.data = data
	return len(data), nil
}
