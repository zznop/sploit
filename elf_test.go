package sploit

import (
	"encoding/hex"
	"os"
	"strconv"
	"testing"
)

var elfFile = "test/prog1.x86_64"

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

func TestRead8(t *testing.T) {
	e, _ := NewELF(elfFile)
	i8, err := e.Read16LE(0x2c4)
	if err != nil {
		t.Fatal(err)
	}

	if i8 != 0x04 {
		t.Fatal("Uint8 != 0x04")
	}
}

func TestRead16(t *testing.T) {
	t.Logf("Testing 16-bit integer reads (%s)...", elfFile)
	e, _ := NewELF(elfFile)
	i16, err := e.Read16LE(0x2c4)
	if err != nil {
		t.Fatal(err)
	}

	if i16 != 0x0004 {
		t.Fatal("Little endian uint16 != 0x0004")
	}

	i16, err = e.Read16BE(0x2c4)
	if err != nil {
		t.Fatal(err)
	}

	if i16 != 0x0400 {
		t.Fatal("Big endian uint16 != 0x0400")
	}
}

func TestRead32(t *testing.T) {
	t.Logf("Testing 32-bit integer reads (%s)...", elfFile)
	e, _ := NewELF(elfFile)
	i32, err := e.Read32LE(0x2d0)
	if err != nil {
		t.Fatal(err)
	}

	if i32 != 0x00554e47 {
		t.Fatal("Little endian uint32 != 0x00554e47")
	}

	i32, err = e.Read32BE(0x2d0)
	if err != nil {
		t.Fatal(err)
	}

	if i32 != 0x474e5500 {
		t.Fatal("Big endian uint32 != 0x474e5500")
	}
}

func TestRead64(t *testing.T) {
	t.Logf("Testing 64-bit integer reads (%s)...", elfFile)
	e, _ := NewELF(elfFile)
	i64, err := e.Read64LE(0x2f0)
	if err != nil {
		t.Fatal(err)
	}

	if i64 != 0x3e95a14400554e47 {
		t.Fatal("Little endian uint64 != 0x3e95a14400554e47")
	}

	i64, err = e.Read64BE(0x2f0)
	if err != nil {
		t.Fatal(err)
	}

	if i64 != 0x474e550044a1953e {
		t.Fatal("Big endian uint64 != 0x474e550044a1953e")
	}
}

func TestELFSave(t *testing.T) {
	t.Log("Testing ELF save/export...")
	filePath := "/tmp/test_save"
	e, _ := NewELF(elfFile)
	err := e.Save(filePath, 0777)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filePath)
}

func TestELFRawPatch(t *testing.T) {
	t.Log("Testing ELF raw patch...")
	e1, _ := NewELF(elfFile)
	err := e1.RawPatch([]byte{0x41, 0x41, 0x41, 0x41}, 0x2f0)
	if err != nil {
		t.Fatal(err)
	}

	filePath := "/tmp/test_raw_patch"
	err = e1.Save(filePath, 0777)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filePath)

	e2, _ := NewELF(filePath)
	i32, err := e2.Read32LE(0x2f0)
	if err != nil {
		t.Fatal(err)
	}

	if i32 != 0x41414141 {
		t.Fatal(err)
	}
}

func TestELFAsmPatch(t *testing.T) {
	t.Log("Testing ELF assembly patch...")
	e1, _ := NewELF(elfFile)
	err := e1.AsmPatch("nop\nnop\nnop\nnop\n", 0x1135)
	if err != nil {
		t.Fatal(err)
	}

	filePath := "/tmp/test_asm_patch"
	err = e1.Save(filePath, 0777)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filePath)

	e2, _ := NewELF(filePath)
	i32, err := e2.Read32LE(0x1135)
	if err != nil {
		t.Fatal(err)
	}

	if i32 != 0x90909090 {
		t.Fatal(err)
	}
}
