package sploit;

import(
    "net"
    "time"
    "testing"
)

func TestRecvLine(t *testing.T) {
    go func() {
        time.Sleep(500 * time.Millisecond)
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
}

func TestRecvUntil(t *testing.T) {
    go func() {
        time.Sleep(500 * time.Millisecond)
        r, err := NewRemote("tcp", ":8000")
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
}

func TestRecvN(t *testing.T) {
    go func() {
        time.Sleep(500 * time.Millisecond)
        r, err := NewRemote("tcp", ":8000")
        if err != nil {
            t.Fatal(err)
        }
        defer r.Close()

        data, err := r.RecvN(6)
        if err != nil {
            t.Fatal(err)
        }

        if string(data) != "lolwut" {
            t.Fatal("RecvN data != lolwut")
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
    conn.Write([]byte("lolwut"))
}

func TestSend(t *testing.T) {
    go func() {
        time.Sleep(500 * time.Millisecond)
        r, err := NewRemote("tcp", ":8000")
        if err != nil {
            t.Fatal(err)
        }
        defer r.Close()

        _, err = r.Send([]byte("Send test"))
        if err != nil {
            t.Fatal(err)
        }

        _, err = r.SendLine([]byte("SendLine test"))
        if err != nil {
            t.Fatal(err)
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


    b := make([]byte, 9)
    _, err = conn.Read(b)
    if err != nil {
        t.Fatal(err)
    }

    if string(b) != "Send test" {
        t.Fatal("Send test data != expected")
    }

    b = make([]byte, 14)
    _, err = conn.Read(b)
    if err != nil {
        t.Fatal(err)
    }

    if string(b) != "SendLine test\n" {
        t.Fatal("SendLine test data != expected")
    }
}
