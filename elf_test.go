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

// TestELFBSS tests relative addressing in the BSS section
func TestELFBSS(t *testing.T) {
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

// TestELFRead tests reading data from an ELF at a specified virtual address
func TestELFRead(t *testing.T) {
    t.Logf("Testing ELF vaddr reads (%s)...", elfFile)
    e, _ := NewELF(elfFile)
    readSize := 6
    addr := uint64(0x2004)
    data, err := e.Read(addr, 6)
    if err != nil {
        t.Fatal(err)
    }

    if string(data) != "lolwut" {
        t.Fatal("Read data does not match expected")
    }
    t.Logf("Read %v bytes from vaddr:0x%08x:\n%s", readSize, addr, hex.Dump(data))
}

// TestELFGetSignatureVAddrs test searching for bytes in all segments
func TestELFGetSignatureVAddrs(t *testing.T) {
    t.Logf("Testing ELF binary signature search")
    e, _ := NewELF(elfFile)
    vaddrs, err := e.GetSignatureVAddrs([]byte("lolwut"))
    if err != nil {
        t.Fatal(err)
    }

    if vaddrs[0] != 0x2004 {
        t.Fatal("Signature vaddr != 0x2004")
    }
}

// TestELFGetOpcodeVAddrs tests searching for bytes in executable segments
func TestELFGetOpcodeVAddrs(t *testing.T) {
    leaRDI := []byte{0x48, 0x8d, 0x3d, 0xb9, 0x0e, 0x00, 0x00}
    e, _ := NewELF(elfFile)
    vaddrs, err := e.GetOpcodeVAddrs(leaRDI)
    if err != nil {
        t.Fatal(err)
    }

    if vaddrs[0] != 0x1144 {
        t.Fatal("Opcode vaddr != 0x1144")
    }
}

// TestELFDumpROPGadgets tests ROP gadget dumping functionality
func TestELFDumpROPGadgets(t *testing.T) {
    t.Logf("Testing ROP gadget dump (%s)...", elfFile)
    e, _ := NewELF(elfFile)
    err := e.DumpROPGadgets()
    if err != nil {
        t.Fatal(err)
    }
}
