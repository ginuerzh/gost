package protocol

import (
	"fmt"
)

// VersionNumber is a version number as int
type VersionNumber int

// gQUIC version range as defined in the wiki: https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
const (
	gquicVersion0   = 0x51303030
	maxGquicVersion = 0x51303439
)

// The version numbers, making grepping easier
const (
	Version39       VersionNumber = gquicVersion0 + 3*0x100 + 0x9 + iota
	VersionTLS      VersionNumber = 101
	VersionWhatever VersionNumber = 0 // for when the version doesn't matter
	VersionUnknown  VersionNumber = -1
)

// SupportedVersions lists the versions that the server supports
// must be in sorted descending order
var SupportedVersions = []VersionNumber{
	Version39,
}

// UsesTLS says if this QUIC version uses TLS 1.3 for the handshake
func (vn VersionNumber) UsesTLS() bool {
	return vn == VersionTLS
}

func (vn VersionNumber) String() string {
	switch vn {
	case VersionWhatever:
		return "whatever"
	case VersionUnknown:
		return "unknown"
	case VersionTLS:
		return "TLS dev version (WIP)"
	default:
		if vn.isGQUIC() {
			return fmt.Sprintf("gQUIC %d", vn.toGQUICVersion())
		}
		return fmt.Sprintf("%d", vn)
	}
}

// ToAltSvc returns the representation of the version for the H2 Alt-Svc parameters
func (vn VersionNumber) ToAltSvc() string {
	if vn.isGQUIC() {
		return fmt.Sprintf("%d", vn.toGQUICVersion())
	}
	return fmt.Sprintf("%d", vn)
}

// CryptoStreamID gets the Stream ID of the crypto stream
func (vn VersionNumber) CryptoStreamID() StreamID {
	if vn.isGQUIC() {
		return 1
	}
	return 0
}

// UsesMaxDataFrame tells if this version uses MAX_DATA, MAX_STREAM_DATA, BLOCKED and STREAM_BLOCKED instead of WINDOW_UDPATE and BLOCKED frames
func (vn VersionNumber) UsesMaxDataFrame() bool {
	return vn.CryptoStreamID() == 0
}

// StreamContributesToConnectionFlowControl says if a stream contributes to connection-level flow control
func (vn VersionNumber) StreamContributesToConnectionFlowControl(id StreamID) bool {
	if id == vn.CryptoStreamID() {
		return false
	}
	if vn.isGQUIC() && id == 3 {
		return false
	}
	return true
}

func (vn VersionNumber) isGQUIC() bool {
	return vn > gquicVersion0 && vn <= maxGquicVersion
}

func (vn VersionNumber) toGQUICVersion() int {
	return int(10*(vn-gquicVersion0)/0x100) + int(vn%0x10)
}

// IsSupportedVersion returns true if the server supports this version
func IsSupportedVersion(supported []VersionNumber, v VersionNumber) bool {
	for _, t := range supported {
		if t == v {
			return true
		}
	}
	return false
}

// ChooseSupportedVersion finds the best version in the overlap of ours and theirs
// ours is a slice of versions that we support, sorted by our preference (descending)
// theirs is a slice of versions offered by the peer. The order does not matter.
// The bool returned indicates if a matching version was found.
func ChooseSupportedVersion(ours, theirs []VersionNumber) (VersionNumber, bool) {
	for _, ourVer := range ours {
		for _, theirVer := range theirs {
			if ourVer == theirVer {
				return ourVer, true
			}
		}
	}
	return 0, false
}
