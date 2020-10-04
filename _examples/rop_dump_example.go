package main;

import(
    "github.com/zznop/sploit"
)

var program = "../test/prog1.x86_64"

func main() {
    elf, _ := sploit.NewELF(program)
    elf.DumpROPGadgets()
}
