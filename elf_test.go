package sploit;

import (
    "testing"
    "strconv"
    "encoding/hex"
)

var elfFile = "test/prog1.x86_64"

// TestNewELF tests instantiation of the ELF object and detection of mitigations
func TestNewELF(t *testing.T) {
    t.Logf("Testing ELF processing (%s)...", elfFile)
    e, err := NewELF(elfFile)
    if err != nil {
        t.Fatalf("NewElf returned error: %s", err)
    }

    if e.Processor.Architecture != ArchX8664 {
        t.Fatal("Machine type != x86-64")
    }
    t.Log("Processor: X86_64")

    if e.Processor.Endian != LittleEndian {
        t.Fatal("Endian != little")
    }
    t.Log("Endianess: little")

    if e.PIE != true {
        t.Fatal("PIE != true")
    }
    t.Log("PIE: " + strconv.FormatBool(e.PIE))

    if e.Mitigations.NX != true {
        t.Fatal("NX != true")
    }
    t.Log("NX: " + strconv.FormatBool(e.Mitigations.NX))

    if e.Mitigations.Canary != false {
        t.Fatal("Canary != false")
    }
    t.Log("Canary: " + strconv.FormatBool(e.Mitigations.Canary))
}

// TestBSS tests relative addressing in the BSS section
func TestBSS(t *testing.T) {
    t.Logf("Testing .bss section addressing (%s)...", elfFile)
    e, _ := NewELF(elfFile)
    addr, err := e.BSS(4)
    if err != nil {
        t.Fatal("Error computing bss offset addr")
    }

    if addr != 0x4034 {
        t.Fatal("BSS offset addr != 0x4034")
    }
    t.Logf(".bss+4 == 0x%08x", addr)
}

// TestRead tests reading data from an ELF at a specified virtual address
func TestRead(t *testing.T) {
    t.Logf("Testing ELF vaddr reads (%s)...", elfFile)
    e, _ := NewELF(elfFile)
    readSize := uint64(6)
    addr := uint64(0x2004)
    data, err := e.Read(addr, readSize)
    if err != nil {
        t.Fatal(err)
    }

    if string(data) != "lolwut" {
        t.Fatal("Read data does not match expected")
    }
    t.Logf("Read %v bytes from vaddr:0x%08x:\n%s", readSize, addr, hex.Dump(data))
}

// TestDumpROPGadgets tests ROP gadget dumping functionality
func TestDumpROPGadgets(t *testing.T) {
    t.Logf("Testing ROP gadget dump (%s)...", elfFile)
    e, _ := NewELF(elfFile)
    err := e.DumpROPGadgets()
    if err != nil {
        t.Fatal(err)
    }
}
