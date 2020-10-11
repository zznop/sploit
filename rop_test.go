package sploit;

import (
    "testing"
)

// TestELFDumpROPGadgets tests ROP gadget dumping functionality
func TestROPDump(t *testing.T) {
    t.Logf("Testing ROP gadget dump (%s)...", elfFile)
    e, _ := NewELF(elfFile)
    r, err := e.ROP()
    if err != nil {
        t.Fatal(err)
    }
    r.Dump()
}

// TestROPInstrSearch tests searching for ROP gadgets by regex
func TestROPInstrSearch(t *testing.T) {
    t.Logf("Testing ROP gadget search (%s)...", elfFile)
    e, _ := NewELF(elfFile)
    r, _ := e.ROP()
    gadgets, err := r.InstrSearch(".*")
    if err != nil {
        t.Fatal(err)
    }

    if len(gadgets) != 63 {
        t.Fatal("Number of gadgets for wildcard match != 63")
    }

    gadgets, err = r.InstrSearch("add rsp, 8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret")
    if err != nil {
        t.Fatal(err)
    }

    if len(gadgets) != 1 || gadgets[0].Address != 0x11ae {
        t.Fatal("Single gadget search did not return gadget at 0x11ae")
    }
}
