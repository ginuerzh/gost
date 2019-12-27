package water

// MacOSDriverProvider enumerates possible MacOS TUN/TAP implementations
type MacOSDriverProvider int

const (
	// MacOSDriverSystem refers to the default P2P driver
	MacOSDriverSystem MacOSDriverProvider = 0
	// MacOSDriverTunTapOSX refers to the third-party tuntaposx driver
	// see https://sourceforge.net/p/tuntaposx
	MacOSDriverTunTapOSX MacOSDriverProvider = 1
)

// PlatformSpecificParams defines parameters in Config that are specific to
// macOS. A zero-value of such type is valid, yielding an interface
// with OS defined name.
// Currently it is not possible to set the interface name in macOS.
type PlatformSpecificParams struct {
	// Name is the name for the interface to be used.
	// e.g. "tap0"
	// Only valid if using TunTapOSXDriver.
	Name string
	// Driver should be set if an alternative driver is desired
	// e.g. TunTapOSXDriver
	Driver MacOSDriverProvider
}

func defaultPlatformSpecificParams() PlatformSpecificParams {
	return PlatformSpecificParams{}
}
