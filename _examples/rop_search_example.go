package main;

import(
    "github.com/zznop/sploit"
    "os"
    "fmt"
)

var program = "../test/prog1.x86_64"

func main() {
    if len(os.Args) != 2 {
        fmt.Println("./rop_example <regex>")
        os.Exit(1)
    }

    elf, _ := sploit.NewELF(program)
    rop, _ := elf.ROP()

    matched, err := rop.InstrSearch(os.Args[1])
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    matched.Dump()
}

/*
$ ./rop_example "pop rbp"
0000111f: pop rbp ; ret
0000111d: add byte ptr [rcx], al ; pop rbp ; ret
00001118: mov byte ptr [rip + 0x2f11], 1 ; pop rbp ; ret
00001113: call 0x1080 ; mov byte ptr [rip + 0x2f11], 1 ; pop rbp ; ret
000011b7: pop rbp ; pop r14 ; pop r15 ; ret
000011b3: pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
000011b2: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
000011af: add esp, 8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
000011ae: add rsp, 8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
*/
