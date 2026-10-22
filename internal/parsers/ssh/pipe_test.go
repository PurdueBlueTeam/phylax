package ssh

import "net"

func newPipe() (net.Conn, net.Conn) { return net.Pipe() }
