package sploit;

import(
    "encoding/binary"
)

// PackUint64LE packs a uint64 into a byte slice in little endian format
func PackUint64LE(i uint64) []byte {
    b := make([]byte, 8)
    binary.LittleEndian.PutUint64(b, i)
    return b
}

// PackUint32LE packs a uint32 into a byte slice in little endian format
func PackUint32LE(i uint32) []byte {
    b := make([]byte, 4)
    binary.LittleEndian.PutUint32(b, i)
    return b
}

// PackUint16LE packs a uint16 into a byte slice in little endian format
func PackUint16LE(i uint16) []byte {
    b := make([]byte, 2)
    binary.LittleEndian.PutUint16(b, i)
    return b
}

// PackUint64BE packs a uint64 into a byte slice in big endian format
func PackUint64BE(i uint64) []byte {
    b := make([]byte, 8)
    binary.BigEndian.PutUint64(b, i)
    return b
}

// PackUint32BE packs a uint32 into a byte slice in big endian format
func PackUint32BE(i uint32) []byte {
    b := make([]byte, 4)
    binary.BigEndian.PutUint32(b, i)
    return b
}

// PackUint16BE packs a uint16 into a byte slice in big endian format
func PackUint16BE(i uint16) []byte {
    b := make([]byte, 2)
    binary.BigEndian.PutUint16(b, i)
    return b
}

// UnpackUint64LE unpacks a byte slice in little endian format into a uint64
func UnpackUint64LE(b []byte) uint64 {
    return binary.LittleEndian.Uint64(b)
}

// UnpackUint32LE unpacks a byte slice in little endian format into a uint32
func UnpackUint32LE(b []byte) uint32 {
    return binary.LittleEndian.Uint32(b)
}

// UnpackUint16LE unpacks a byte slice in little endian format into a uint16
func UnpackUint16LE(b []byte) uint16 {
    return binary.LittleEndian.Uint16(b)
}

// UnpackUint64BE unpacks a byte slice in big endian format into a uint64
func UnpackUint64BE(b []byte) uint64 {
    return binary.BigEndian.Uint64(b)
}

// UnpackUint32BE unpacks a byte slice in big endian format into a uint32
func UnpackUint32BE(b []byte) uint32 {
    return binary.BigEndian.Uint32(b)
}

// UnpackUint16BE unpacks a byte slice in big endian format into a uint16
func UnpackUint16BE(b []byte) uint16 {
    return binary.BigEndian.Uint16(b)
}
