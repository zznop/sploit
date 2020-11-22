package sploit;

import (
    "testing"
    "encoding/hex"
)

func TestDisasm(t *testing.T) {
    t.Logf("Testing disassembly (%s)...", elfFile)
    addr := uint64(0x1135)
    n := 32
    e, _ := NewELF(elfFile)
    disasm, err := e.Disasm(addr, n)
    if err != nil {
        t.Fatal(err)
    }

    expected := "00001135: push rbp\n" +
        "00001136: mov rbp, rsp\n" +
        "00001139: sub rsp, 0x10\n" +
        "0000113d: mov dword ptr [rbp - 4], edi\n" +
        "00001140: mov qword ptr [rbp - 0x10], rsi\n" +
        "00001144: lea rdi, [rip + 0xeb9]\n" +
        "0000114b: call 0x1030\n" +
        "00001150: mov eax, 0\n"

    if disasm != expected {
        t.Fatal("Disassembly does not match expected")
    }
    t.Logf("Successfully disassembled %v bytes at vaddr:0x%08x:", n, addr)
    t.Log("\n" + disasm)
}

func TestAsmX8664(t *testing.T) {
    code := "mov rdi, 1337\nmov rsi, 1337\nmov rdx, 1337\nmov rcx, 1337\nnop\n"
    t.Logf("Testing assembly of following x86-64 instructions:\n%s", code)
    processor := &Processor {
        Architecture: ArchX8664,
        Endian: LittleEndian,
    }

    opcodes, err := Asm(processor, code)
    if err != nil {
        t.Fatal(err)
    }

    t.Logf("Assembly code compiled to %v bytes:\n%s", len(opcodes), hex.Dump(opcodes))
}

func TestAsmARM(t *testing.T) {
    code := "mov r2, r1\nmov r3, r4\nmov r5, r6\n"
    t.Logf("Testing assembly of following ARM instructions:\n%s", code)
    processor := &Processor {
        Architecture: ArchARM,
        Endian: LittleEndian,
    }

    opcodes, err := Asm(processor, code)
    if err != nil {
        t.Fatal(err)
    }

    t.Logf("Assembly code compiled to %v bytes:\n%s", len(opcodes), hex.Dump(opcodes))
}
