### chacha20 - ChaCha20
#### Yawning Angel (yawning at schwanenlied dot me)

Yet another Go ChaCha20 implementation.  Everything else I found  was slow,
didn't support all the variants I need to use, or relied on cgo to go fast.

Features:

 * 20 round, 256 bit key only.  Everything else is pointless and stupid.
 * IETF 96 bit nonce variant.
 * XChaCha 24 byte nonce variant.
 * SSE2 and AVX2 support on amd64 targets.
 * Incremental encrypt/decrypt support, unlike golang.org/x/crypto/salsa20.

