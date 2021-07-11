package sploit

import (
	"os"
	"testing"
)

var elfFile = "test/prog1.x86_64"

func TestNewELF(t *testing.T) {
	e, err := NewELF(elfFile)
	if err != nil {
		t.Fatal(err)
	}

	if e.Processor.Architecture != ArchX8664 {
		t.Fatal("Machine type != x86-64")
	}

	if e.Processor.Endian != LittleEndian {
		t.Fatal("Endian != little")
	}

	if e.PIE != true {
		t.Fatal("PIE != true")
	}

	if e.Mitigations.NX != true {
		t.Fatal("NX != true")
	}

	if e.Mitigations.Canary != false {
		t.Fatal("Canary != false")
	}
}

func TestELFBSS(t *testing.T) {
	e, _ := NewELF(elfFile)
	addr, err := e.BSS(4)
	if err != nil {
		t.Fatal(err)
	}

	if addr != 0x4034 {
		t.Fatal("BSS offset addr != 0x4034")
	}
}

func TestELFRead(t *testing.T) {
	e, _ := NewELF(elfFile)
	addr := uint64(0x2004)
	data, err := e.Read(addr, 6)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != "lolwut" {
		t.Fatal("Read data does not match expected")
	}
}

func TestELFGetSignatureVAddrs(t *testing.T) {
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

func TestRead16LE(t *testing.T) {
	e, _ := NewELF(elfFile)
	i16, err := e.Read16LE(0x2c4)
	if err != nil {
		t.Fatal(err)
	}

	if i16 != 0x0004 {
		t.Fatal("Little endian uint16 != 0x0004")
	}
}

func TestRead16BE(t *testing.T) {
	e, _ := NewELF(elfFile)
	i16, err := e.Read16BE(0x2c4)
	if err != nil {
		t.Fatal(err)
	}

	if i16 != 0x0400 {
		t.Fatal("Big endian uint16 != 0x0400")
	}
}

func TestRead32LE(t *testing.T) {
	e, _ := NewELF(elfFile)
	i32, err := e.Read32LE(0x2d0)
	if err != nil {
		t.Fatal(err)
	}

	if i32 != 0x00554e47 {
		t.Fatal("Little endian uint32 != 0x00554e47")
	}

}

func TestRead32BE(t *testing.T) {
	e, _ := NewELF(elfFile)
	i32, err := e.Read32BE(0x2d0)
	if err != nil {
		t.Fatal(err)
	}

	if i32 != 0x474e5500 {
		t.Fatal("Big endian uint32 != 0x474e5500")
	}
}

func TestRead64LE(t *testing.T) {
	e, _ := NewELF(elfFile)
	i64, err := e.Read64LE(0x2f0)
	if err != nil {
		t.Fatal(err)
	}

	if i64 != 0x3e95a14400554e47 {
		t.Fatal("Little endian uint64 != 0x3e95a14400554e47")
	}
}

func TestRead64BE(t *testing.T) {
	e, _ := NewELF(elfFile)
	i64, err := e.Read64BE(0x2f0)
	if err != nil {
		t.Fatal(err)
	}

	if i64 != 0x474e550044a1953e {
		t.Fatal("Big endian uint64 != 0x474e550044a1953e")
	}
}

func TestELFSave(t *testing.T) {
	filePath := "/tmp/test_save"
	e, _ := NewELF(elfFile)
	err := e.Save(filePath, 0777)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filePath)
}

func TestELFWrite(t *testing.T) {
	e1, _ := NewELF(elfFile)
	e1.Write([]byte{0x41, 0x41, 0x41, 0x41}, 0x2f0)
	e1.Write8(0x42, 0x2f4)
	e1.Write16LE(0xf00b, 0x2f5)
	e1.Write16BE(0xf00b, 0x2f7)
	e1.Write32LE(0xfeedface, 0x2f9)
	e1.Write32BE(0xfeedface, 0x2fd)
	e1.Write64LE(0xdeadbeefdeadbeef, 0x301)
	e1.Write64BE(0xdeadbeefdeadbeef, 0x309)

	filePath := "/tmp/test_raw_patch"
	err := e1.Save(filePath, 0777)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filePath)

	e2, _ := NewELF(filePath)
	data, _ := e2.Read32LE(0x2f0)
	i8, _ := e2.Read8(0x2f4)
	i16, _ := e2.Read16LE(0x2f5)
	i16BE, _ := e2.Read16BE(0x2f7)
	i32, _ := e2.Read32LE(0x2f9)
	i32BE, _ := e2.Read32BE(0x2fd)
	i64, _ := e2.Read64LE(0x301)
	i64BE, _ := e2.Read64BE(0x309)
	if data != 0x41414141 || i8 != 0x42 || i16 != 0xf00b || i16BE != 0xf00b || i32 != 0xfeedface || i32BE != 0xfeedface || i64 != 0xdeadbeefdeadbeef || i64BE != 0xdeadbeefdeadbeef {
		t.Fatal("read data != expected")
	}
}

func TestELFAsmPatch(t *testing.T) {
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
