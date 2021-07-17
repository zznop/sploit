package sploit

import (
	"bytes"
	"testing"
)

func TestROPDumpX8664(t *testing.T) {
	e, _ := NewELF(elfFile)
	r, err := e.ROP()
	if err != nil {
		t.Fatal(err)
	}
	r.Dump()
}

func TestROPInstrSearchX8664(t *testing.T) {
	e, _ := NewELF(elfFile)
	r, _ := e.ROP()
	gadgets, err := r.InstrSearch(".*")
	if err != nil {
		t.Fatal(err)
	}

	if len(gadgets) != 72 {
		t.Fatal("Number of gadgets for wildcard match != 72")
	}

	gadgets, err = r.InstrSearch("add rsp, 8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret")
	if err != nil {
		t.Fatal(err)
	}

	if len(gadgets) != 1 || gadgets[0].Address != 0x11ae {
		t.Fatal("Single gadget search did not return gadget at 0x11ae")
	}

	if bytes.Compare(gadgets[0].Opcode, []byte{0x48, 0x83, 0xc4, 0x08, 0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3}) != 0 {
		t.Fatal("Gadget machine code does not match expected")
	}
}

func TestROPDumpARM(t *testing.T) {
	e, _ := NewELF("test/prog1.arm")
	r, err := e.ROP()
	if err != nil {
		t.Fatal(err)
	}
	r.Dump()
}
