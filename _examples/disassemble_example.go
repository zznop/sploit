package main;

import(
    "github.com/zznop/sploit"
    "fmt"
)

var program = "../test/prog1.x86_64"

func main() {
    elf, _ := sploit.NewELF(program)
    vaddr := uint64(0x1135)
    count := 34
    fmt.Printf("Disassembling %v bytes at vaddr:%08x\n", count, vaddr)
    disasm, _ := elf.Disasm(vaddr, count)
    fmt.Print(disasm)
}
