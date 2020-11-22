package sploit;

import (
    "testing"
    "bytes"
)

func TestPackUint64LE(t *testing.T) {
    if bytes.Compare(PackUint64LE(0xf00bdeadbeeff00b), []byte{0x0b, 0xf0, 0xef, 0xbe, 0xad, 0xde, 0x0b, 0xf0}) != 0 {
        t.Fatal("Return bytes != expected")
    }
}

func TestPackUint32LE(t *testing.T) {
    if bytes.Compare(PackUint32LE(0xf00bdead), []byte{0xad, 0xde, 0x0b, 0xf0}) != 0 {
        t.Fatal("Return bytes != expected")
    }
}

func TestPackUint16LE(t *testing.T) {
    if bytes.Compare(PackUint16LE(0xf00b), []byte{0x0b, 0xf0}) != 0 {
        t.Fatal("Return bytes != expected")
    }
}

func TestPackUint64BE(t *testing.T) {
    if bytes.Compare(PackUint64BE(0xf00bdeadbeeff00b), []byte{0xf0, 0x0b, 0xde, 0xad, 0xbe, 0xef, 0xf0, 0x0b}) != 0 {
        t.Fatal("Return bytes != expected")
    }
}

func TestPackUint32BE(t *testing.T) {
    if bytes.Compare(PackUint32BE(0xf00bdead), []byte{0xf0, 0x0b, 0xde, 0xad}) != 0 {
        t.Fatal("Return bytes != expected")
    }
}

func TestPackUint16BE(t *testing.T) {
    if bytes.Compare(PackUint16BE(0xf00b), []byte{0xf0, 0x0b}) != 0 {
        t.Fatal("Return bytes != expected")
    }
}

func TestUnpackUint64LE(t *testing.T) {
    if UnpackUint64LE([]byte{0x0b, 0xf0, 0xef, 0xbe, 0xad, 0xde, 0x0b, 0xf0}) != 0xf00bdeadbeeff00b {
        t.Fatal("Return value != expected")
    }
}

func TestUnpackUint32LE(t *testing.T) {
    if UnpackUint32LE([]byte{0x0b, 0xf0, 0xef, 0xbe}) != 0xbeeff00b {
        t.Fatal("Return value != expected")
    }
}

func TestUnpackUint16LE(t *testing.T) {
    if UnpackUint16LE([]byte{0x0b, 0xf0}) != 0xf00b {
        t.Fatal("Return value != expected")
    }
}

func TestUnpackUint64BE(t *testing.T) {
    if UnpackUint64BE([]byte{0xf0, 0x0b, 0xde, 0xad, 0xbe, 0xef, 0xf0, 0x0b}) != 0xf00bdeadbeeff00b {
        t.Fatal("Return value != expected")
    }
}

func TestUnpackUint32BE(t *testing.T) {
    if UnpackUint32BE([]byte{0xf0, 0x0b, 0xde, 0xad}) != 0xf00bdead {
        t.Fatal("Return value != expected")
    }
}

func TestUnpackUint16BE(t *testing.T) {
    if UnpackUint16BE([]byte{0xf0, 0x0b}) != 0xf00b {
        t.Fatal("Return value != expected")
    }
}
