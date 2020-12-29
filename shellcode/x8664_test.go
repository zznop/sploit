package shellcode

import (
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
