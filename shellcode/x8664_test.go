package shellcode

import (
	"encoding/hex"
	"testing"
)

func TestX8664MemFdExec(t *testing.T) {
	x8664 := NewX8664()
	shellcode, err := x8664.LinuxMemFdExec()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(hex.Dump(shellcode))
}
