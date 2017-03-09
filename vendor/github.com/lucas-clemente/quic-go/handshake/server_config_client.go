package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type serverConfigClient struct {
	raw    []byte
	ID     []byte
	obit   []byte
	expiry time.Time

	kex          crypto.KeyExchange
	sharedSecret []byte
}

var (
	errMessageNotServerConfig = errors.New("ServerConfig must have TagSCFG")
)

// parseServerConfig parses a server config
func parseServerConfig(data []byte) (*serverConfigClient, error) {
	tag, tagMap, err := ParseHandshakeMessage(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if tag != TagSCFG {
		return nil, errMessageNotServerConfig
	}

	scfg := &serverConfigClient{raw: data}
	err = scfg.parseValues(tagMap)
	if err != nil {
		return nil, err
	}

	return scfg, nil
}

func (s *serverConfigClient) parseValues(tagMap map[Tag][]byte) error {
	// SCID
	scfgID, ok := tagMap[TagSCID]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "SCID")
	}
	if len(scfgID) != 16 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "SCID")
	}
	s.ID = scfgID

	// KEXS
	// TODO: allow for P256 in the list
	// TODO: setup Key Exchange
	kexs, ok := tagMap[TagKEXS]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "KEXS")
	}
	if len(kexs)%4 != 0 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "KEXS")
	}
	if !bytes.Equal(kexs, []byte("C255")) {
		return qerr.Error(qerr.CryptoNoSupport, "KEXS")
	}

	// AEAD
	aead, ok := tagMap[TagAEAD]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "AEAD")
	}
	if len(aead)%4 != 0 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "AEAD")
	}
	var aesgFound bool
	for i := 0; i < len(aead)/4; i++ {
		if bytes.Equal(aead[4*i:4*i+4], []byte("AESG")) {
			aesgFound = true
			break
		}
	}
	if !aesgFound {
		return qerr.Error(qerr.CryptoNoSupport, "AEAD")
	}

	// PUBS
	// TODO: save this value
	pubs, ok := tagMap[TagPUBS]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "PUBS")
	}
	if len(pubs) != 35 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "PUBS")
	}

	var err error
	s.kex, err = crypto.NewCurve25519KEX()
	if err != nil {
		return err
	}

	// the PUBS value is always prepended by []byte{0x20, 0x00, 0x00}
	s.sharedSecret, err = s.kex.CalculateSharedKey(pubs[3:])
	if err != nil {
		return err
	}

	// OBIT
	obit, ok := tagMap[TagOBIT]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "OBIT")
	}
	if len(obit) != 8 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "OBIT")
	}
	s.obit = obit

	// EXPY
	expy, ok := tagMap[TagEXPY]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "EXPY")
	}
	if len(expy) != 8 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "EXPY")
	}
	// make sure that the value doesn't overflow an int64
	// furthermore, values close to MaxInt64 are not a valid input to time.Unix, thus set MaxInt64/2 as the maximum value here
	expyTimestamp := utils.MinUint64(binary.LittleEndian.Uint64(expy), math.MaxInt64/2)
	s.expiry = time.Unix(int64(expyTimestamp), 0)

	// TODO: implement VER

	return nil
}

func (s *serverConfigClient) IsExpired() bool {
	return s.expiry.Before(time.Now())
}

func (s *serverConfigClient) Get() []byte {
	return s.raw
}
