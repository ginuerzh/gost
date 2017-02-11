package protocol

import (
	"bytes"
	"encoding/binary"
	"strconv"
)

// VersionNumber is a version number as int
type VersionNumber int

// The version numbers, making grepping easier
const (
	Version34 VersionNumber = 34 + iota
	Version35
	Version36
	VersionWhatever    = 0 // for when the version doesn't matter
	VersionUnsupported = -1
)

// SupportedVersions lists the versions that the server supports
// must be in sorted order
var SupportedVersions = []VersionNumber{
	Version34, Version35, Version36,
}

// SupportedVersionsAsTags is needed for the SHLO crypto message
var SupportedVersionsAsTags []byte

// SupportedVersionsAsString is needed for the Alt-Scv HTTP header
var SupportedVersionsAsString string

// VersionNumberToTag maps version numbers ('32') to tags ('Q032')
func VersionNumberToTag(vn VersionNumber) uint32 {
	v := uint32(vn)
	return 'Q' + ((v/100%10)+'0')<<8 + ((v/10%10)+'0')<<16 + ((v%10)+'0')<<24
}

// VersionTagToNumber is built from VersionNumberToTag in init()
func VersionTagToNumber(v uint32) VersionNumber {
	return VersionNumber(((v>>8)&0xff-'0')*100 + ((v>>16)&0xff-'0')*10 + ((v>>24)&0xff - '0'))
}

// IsSupportedVersion returns true if the server supports this version
func IsSupportedVersion(v VersionNumber) bool {
	for _, t := range SupportedVersions {
		if t == v {
			return true
		}
	}
	return false
}

// HighestSupportedVersion finds the highest version number that is both present in other and in SupportedVersions
// the versions in other do not need to be ordered
// it returns true and the version number, if there is one, otherwise false
func HighestSupportedVersion(other []VersionNumber) (bool, VersionNumber) {
	var otherSupported []VersionNumber
	for _, ver := range other {
		if ver != VersionUnsupported {
			otherSupported = append(otherSupported, ver)
		}
	}

	for i := len(SupportedVersions) - 1; i >= 0; i-- {
		for _, ver := range otherSupported {
			if ver == SupportedVersions[i] {
				return true, ver
			}
		}
	}

	return false, 0
}

func init() {
	var b bytes.Buffer
	for _, v := range SupportedVersions {
		s := make([]byte, 4)
		binary.LittleEndian.PutUint32(s, VersionNumberToTag(v))
		b.Write(s)
	}
	SupportedVersionsAsTags = b.Bytes()

	for i := len(SupportedVersions) - 1; i >= 0; i-- {
		SupportedVersionsAsString += strconv.Itoa(int(SupportedVersions[i]))
		if i != 0 {
			SupportedVersionsAsString += ","
		}
	}
}
