package core

import "net"

func ListenPacket(network, address string, ciph PacketConnCipher) (net.PacketConn, error) {
	c, err := net.ListenPacket(network, address)
	return ciph.PacketConn(c), err
}
