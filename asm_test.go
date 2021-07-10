package sploit

import (
	"bytes"
	"os"
	"testing"
)

func TestDisasm(t *testing.T) {
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
}

func TestAsmX8664(t *testing.T) {
	code := "mov rdi, 1337\nmov rsi, 1337\nmov rdx, 1337\nmov rcx, 1337\nnop\n"
	processor := &Processor{
		Architecture: ArchX8664,
		Endian:       LittleEndian,
	}

	opcode, err := Asm(processor, code)
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{0x48, 0xc7, 0xc7, 0x39, 0x05, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0x39, 0x05, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0x39, 0x05, 0x00, 0x00, 0x48, 0xc7, 0xc1, 0x39, 0x05, 0x00, 0x00, 0x90}
	if bytes.Compare(opcode, expected) != 0 {
		t.Fatal("Opcode bytes does not match expected")
	}
}

func TestMakeELF(t *testing.T) {
	code := `
jmp past

message:
    .ascii "See, I am drow, and I'd like to say hello,\n"
    .ascii "To the black, to the white, the red and the brown,\n"
    .ascii "The purple and yellow. But first, I gotta\n"
    .ascii "Bang bang, the boogie to the boogie,\n"
    .ascii "Say up jump the boogie to the bang bang boogie,\n"
    .ascii "Let's rock, you don't stop ...\n\n"

past:
    mov rdi, 1                    /* STDOUT file descriptor */
    lea rsi, [rip + message]      /* Pointer to message string */
    mov rdx, 253                  /* Message size */
    mov rax, 1                    /* Write syscall number */
    syscall                       /* Execute system call */
    mov rdi, 0                    /* Success */
    mov rax, 60                   /* Exit syscall number */
    syscall                       /* Execute system call */`

	processor := &Processor{
		Architecture: ArchX8664,
		Endian:       LittleEndian,
	}

	err := MakeELF(processor, code, "/tmp/test.elf")
	defer os.Remove("/tmp/test.elf")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAsmARM(t *testing.T) {
	code := "mov r2, r1\nmov r3, r4\nmov r5, r6\n"
	processor := &Processor{
		Architecture: ArchARM,
		Endian:       LittleEndian,
	}

	opcode, err := Asm(processor, code)
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{0x01, 0x20, 0xa0, 0xe1, 0x04, 0x30, 0xa0, 0xe1, 0x06, 0x50, 0xa0, 0xe1}
	if bytes.Compare(opcode, expected) != 0 {
		t.Fatal("Opcode bytes does not match expected")
	}
}
