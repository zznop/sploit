package main

import (
	"fmt"
	sp "github.com/zznop/sploit"
)

var origProgram = "../test/prog1.x86_64"
var patchedProgram = "./patched"

var patchInstrs = `
jmp past

message:
    .ascii "This is an example patch payload\n"

past:
    mov rdi, 1                    /* STDOUT file descriptor */
    lea rsi, [rip + message]      /* Pointer to message string */
    mov rdx, 33                   /* Message size */
    mov rax, 1                    /* __NR_write */
    syscall                       /* Execute system call */
self:
    jmp self                      /* Hang forever */
`

func main() {
	e, _ := sp.NewELF(origProgram)

	fmt.Printf("Patching _start of %v\n", origProgram)
	e.AsmPatch(patchInstrs, 0x1050)

	fmt.Printf("Exporting patched ELF to %v\n", patchedProgram)
	e.Save(patchedProgram, 0777)
}
