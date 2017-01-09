package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"

	"github.com/lucas-clemente/quic-go/utils"
)

type entryType uint8

const (
	entryCompressed entryType = 1
	entryCached     entryType = 2
	entryCommon     entryType = 3
)

type entry struct {
	t entryType
	h uint64
	i uint32
}

func compressChain(chain [][]byte, pCommonSetHashes, pCachedHashes []byte) ([]byte, error) {
	res := &bytes.Buffer{}

	cachedHashes, err := splitHashes(pCachedHashes)
	if err != nil {
		return nil, err
	}

	setHashes, err := splitHashes(pCommonSetHashes)
	if err != nil {
		return nil, err
	}

	chainHashes := make([]uint64, len(chain))
	for i := range chain {
		chainHashes[i] = hashCert(chain[i])
	}

	entries := buildEntries(chain, chainHashes, cachedHashes, setHashes)

	totalUncompressedLen := 0
	for i, e := range entries {
		res.WriteByte(uint8(e.t))
		switch e.t {
		case entryCached:
			utils.WriteUint64(res, e.h)
		case entryCommon:
			utils.WriteUint64(res, e.h)
			utils.WriteUint32(res, e.i)
		case entryCompressed:
			totalUncompressedLen += 4 + len(chain[i])
		}
	}
	res.WriteByte(0) // end of list

	if totalUncompressedLen > 0 {
		gz, err := zlib.NewWriterLevelDict(res, flate.BestCompression, buildZlibDictForEntries(entries, chain))
		if err != nil {
			return nil, fmt.Errorf("cert compression failed: %s", err.Error())
		}

		utils.WriteUint32(res, uint32(totalUncompressedLen))

		for i, e := range entries {
			if e.t != entryCompressed {
				continue
			}
			lenCert := len(chain[i])
			gz.Write([]byte{
				byte(lenCert & 0xff),
				byte((lenCert >> 8) & 0xff),
				byte((lenCert >> 16) & 0xff),
				byte((lenCert >> 24) & 0xff),
			})
			gz.Write(chain[i])
		}

		gz.Close()
	}

	return res.Bytes(), nil
}

func buildEntries(chain [][]byte, chainHashes, cachedHashes, setHashes []uint64) []entry {
	res := make([]entry, len(chain))
chainLoop:
	for i := range chain {
		// Check if hash is in cachedHashes
		for j := range cachedHashes {
			if chainHashes[i] == cachedHashes[j] {
				res[i] = entry{t: entryCached, h: chainHashes[i]}
				continue chainLoop
			}
		}

		// Go through common sets and check if it's in there
		for _, setHash := range setHashes {
			set, ok := certSets[setHash]
			if !ok {
				// We don't have this set
				continue
			}
			// We have this set, check if chain[i] is in the set
			pos := set.findCertInSet(chain[i])
			if pos >= 0 {
				// Found
				res[i] = entry{t: entryCommon, h: setHash, i: uint32(pos)}
				continue chainLoop
			}
		}

		res[i] = entry{t: entryCompressed}
	}
	return res
}

func buildZlibDictForEntries(entries []entry, chain [][]byte) []byte {
	var dict bytes.Buffer

	// First the cached and common in reverse order
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].t == entryCompressed {
			continue
		}
		dict.Write(chain[i])
	}

	dict.Write(certDictZlib)
	return dict.Bytes()
}

func splitHashes(hashes []byte) ([]uint64, error) {
	if len(hashes)%8 != 0 {
		return nil, errors.New("expected a multiple of 8 bytes for CCS / CCRT hashes")
	}
	n := len(hashes) / 8
	res := make([]uint64, n)
	for i := 0; i < n; i++ {
		res[i] = binary.LittleEndian.Uint64(hashes[i*8 : (i+1)*8])
	}
	return res, nil
}

func hashCert(cert []byte) uint64 {
	h := fnv.New64()
	h.Write(cert)
	return h.Sum64()
}
