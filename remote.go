package sploit;

import(
	"net"
	"strconv"
)

// Remote is an interface for communicating over IP
type Remote struct {
	Host string
	Port uint16
}

// NewRemote connects to the specified remote host and returns an initialized Remote instance
func NewRemote(hostPort string) (*Remote, error) {
	host, portString, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}

	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, err
	}

	return &Remote{
		Host: host,
		Port: uint16(port),
	}, nil
}
