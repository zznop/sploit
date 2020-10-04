package main;

import(
    "github.com/zznop/sploit"
    "encoding/hex"
    "fmt"
)

func main() {
    instrs := "mov rcx, r12\n"              +
              "mov rdx, r13\n"              +
              "mov r8, 0x1f\n"              +
              "xor r9, r9\n"                +
              "sub rsp, 0x8\n"              +
              "mov qword [rsp+0x20], rax\n"

    arch := &sploit.Processor {
        Architecture: sploit.ArchX8664,
        Endian: sploit.LittleEndian,
    }

    opcode, _ := sploit.Asm(arch, instrs)
    fmt.Printf("Opcode bytes:\n%s\n", hex.Dump(opcode))
}
