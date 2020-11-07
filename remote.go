package sploit;

import(
    "net"
    "strconv"
    "bufio"
    "io"
    "errors"
    "bytes"
)

// Remote is an interface for communicating over IP
type Remote struct {
    HostPort string
    Host string
    Port uint16
    C net.Conn
}

// NewRemote connects to the specified remote host and returns an initialized Remote instance
func NewRemote(protocol string, hostPort string) (*Remote, error) {
    host, portString, err := net.SplitHostPort(hostPort)
    if err != nil {
        return nil, err
    }

    port, err := strconv.ParseUint(portString, 10, 16)
    if err != nil {
        return nil, err
    }

    c, err := net.Dial(protocol, hostPort)
    if err != nil {
        return nil, err
    }

    return &Remote{
        HostPort: hostPort,
        Host: host,
        Port: uint16(port),
        C: c,
    }, nil
}

// Close is a Remote method for closing the connection if it's active
func (r *Remote)Close() {
    if r.C != nil {
        r.C.Close()
    }
}

// RecvUntil is a Remote method for receiving data until the specified sequence of bytes is detected
func (r *Remote)RecvUntil(needle []byte, drop bool)([]byte, error) {
    data := make([]byte, len(needle))
    b := bufio.NewReader(r.C)

    // Read needle-size
    n, err := io.ReadFull(b, data)
    if err != nil {
        return nil, err
    }

    // Make sure it read the entire size of the needle
    if n != len(needle) {
        return nil, errors.New("RecvUntil truncated")
    }

    // Compare needle and received data and continue to read a byte at a time
    idx := 0
    for {
        if bytes.Compare(data[idx:idx+len(needle)], needle) == 0 {
            if drop == true {
                return data[0:len(data)-len(needle)], nil
            } else {
                return data, nil
            }
        }

        byt, err := b.ReadByte()
        if err != nil {
            return nil, err
        }

        data = append(data, byt)
        idx++
    }
}

// RecvLine is a Remote method for receiving data until a newline delimiter is detected
func (r *Remote)RecvLine()([]byte, error) {
    return r.RecvUntil([]byte("\n"), true)
}
