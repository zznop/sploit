package sploit;

import(
    "net"
    "time"
    "testing"
)

// TestNewRemote tests Remote initialization
func TestNewRemote(t *testing.T) {
    // Start a goroutine with the client logic under test
    go func() {
        r, err := NewRemote("tcp", "127.0.0.1:8000")
        if err != nil {
            t.Fatal(err)
        }
        defer r.Close()

        if r.Host != "127.0.0.1" {
            t.Fatal("Host != localhost")
        }

        if r.Port != 8000 {
            t.Fatal("Port != 8000")
        }

        if r.C == nil {
            t.Fatal("Connection failed")
        }
    }()

    // Start a listener server to handle incoming connection
    l, err := net.Listen("tcp", ":8000")
    if err != nil {
        t.Fatal(err)
    }
    defer l.Close()

    conn, err := l.Accept()
    if err != nil {
        return
    }
    defer conn.Close()
    time.Sleep(1 * time.Second)
}

// TestRecvLine tests receiving a line of data from a TCP server
func TestRecvLine(t *testing.T) {
    go func() {
        r, err := NewRemote("tcp", "127.0.0.1:8000")
        if err != nil {
            t.Fatal(err)
        }
        defer r.Close()

        data, err := r.RecvLine()
        if err != nil {
            t.Fatal(err)
        }

        if string(data) != "lolwut" {
            t.Fatal("Received line != lolwut")
        }
    }()

    l, err := net.Listen("tcp", ":8000")
    if err != nil {
        t.Fatal(err)
    }
    defer l.Close()

    conn, err := l.Accept()
    if err != nil {
        return
    }
    defer conn.Close()
    conn.Write([]byte("lolwut\n"))
    time.Sleep(1)
}

// TestRecvUntil tests receiving until a specified sequence of bytes
func TestRecvUntil(t *testing.T) {
    go func() {
        r, err := NewRemote("tcp", "127.0.0.1:8000")
        if err != nil {
            t.Fatal(err)
        }
        defer r.Close()

        data, err := r.RecvUntil([]byte("cmd>"), true)
        if err != nil {
            t.Fatal(err)
        }

        if string(data) != "lolwut\n" {
            t.Fatal("Received data != lolwut")
        }
    }()

    l, err := net.Listen("tcp", ":8000")
    if err != nil {
        t.Fatal(err)
    }
    defer l.Close()

    conn, err := l.Accept()
    if err != nil {
        return
    }
    defer conn.Close()
    conn.Write([]byte("lolwut\n"))
    conn.Write([]byte("cmd>"))
    time.Sleep(1)
}
