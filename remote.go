package sploit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Remote is an interface for communicating over IP
type Remote struct {
	HostPort string
	Host     string
	Port     uint16
	C        net.Conn
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
		Host:     host,
		Port:     uint16(port),
		C:        c,
	}, nil
}

// Close is a Remote method for closing the connection if it's active
func (r *Remote) Close() {
	if r.C != nil {
		r.C.Close()
	}
}

// RecvUntil is a Remote method for receiving data over IP until the specified sequence of bytes is detected
func (r *Remote) RecvUntil(needle []byte, drop bool) ([]byte, error) {
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
				return data[0 : len(data)-len(needle)], nil
			}
			return data, nil
		}

		byt, err := b.ReadByte()
		if err != nil {
			return nil, err
		}

		data = append(data, byt)
		idx++
	}
}

// RecvLine is a Remote method for receiving data over IP until a newline delimiter is detected
func (r *Remote) RecvLine() ([]byte, error) {
	return r.RecvUntil([]byte("\n"), true)
}

// RecvN is a Remote method for receiving a specified number of bytes
func (r *Remote) RecvN(n int) ([]byte, error) {
	b := make([]byte, n)
	rn, err := r.C.Read(b)
	if err != nil {
		return nil, err
	}

	if rn != n {
		return nil, errors.New("RecvN truncated")
	}

	return b, nil
}

// Send is a Remote method for sending data over IP
func (r *Remote) Send(data []byte) (int, error) {
	return r.C.Write(data)
}

// SendLine is a Remote method for sending data with a trailing newline character
func (r *Remote) SendLine(line []byte) (int, error) {
	line = append(line, '\n')
	return r.C.Write(line)
}

// Interactive is a Remote method that allows the user to interact with a remote process manually
func (r *Remote) Interactive() error {
	go func() {
		for {
			data, err := r.RecvN(1)
			if err != nil {
				break
			}

			fmt.Printf("%c", data[0])
		}
	}()

	for {
		var line string
		fmt.Scanln(&line)
		if line == "_quit" {
			fmt.Println("Exiting...")
			return nil
		}

		_, err := r.SendLine([]byte(line))
		if err != nil {
			return err
		}
	}
}
