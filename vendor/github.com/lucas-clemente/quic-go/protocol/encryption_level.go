package protocol

// EncryptionLevel is the encryption level
// Default value is Unencrypted
type EncryptionLevel int

const (
	// Unencrypted is not encrypted
	Unencrypted EncryptionLevel = iota
	// EncryptionSecure is encrypted, but not forward secure
	EncryptionSecure
	// EncryptionForwardSecure is forward secure
	EncryptionForwardSecure
)
