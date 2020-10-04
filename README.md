# sploit

## Description

Sploit is a Go package that aids in binary analysis and exploitation. The motivating factor behind the development of
sploit is to be able to have a well designed API with functionality that rivals some of the more common Python exploit
development frameworks while taking advantage of the Go programming language. Excellent cross-compiler support,
goroutines, powerful crypto libraries, and static typing are just a few of the reasons for choosing Go.

This project is inspired by pwntools and other awesome projects. It is still early in development. Expect for this
project to be focused heavily on shellcoding, binary patching, ROP stack construction, and general binary analysis. It
will focus less heavily on socket communication and server/client development.

#### Example 1 - Compiling assembly code to bytes

```go
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
```

```
$ ./assemble_example
Opcode bytes:
00000000  4c 89 e1 4c 89 ea 49 c7  c0 1f 00 00 00 4d 31 c9  |L..L..I......M1.|
00000010  48 83 ec 08 48 89 44 24  28                       |H...H.D$(|
```

#### Example 2 - Disassembling code in an ELF executable

```go
package main;

import(
    "github.com/zznop/sploit"
    "fmt"
)

var program = "../test/prog1.x86_64"

func main() {
    elf, _ := sploit.NewELF(program)
    vaddr := uint64(0x1135)
    count := uint64(34)
    fmt.Printf("Disassembling %v bytes at vaddr:%08x\n", count, vaddr)
    disasm, _ := elf.Disasm(vaddr, count)
    fmt.Print(disasm)
}
```

```
$ ./disassemble_example
Disassembling 34 bytes at vaddr:00001135
00001135: push rbp
00001136: mov rbp, rsp
00001139: sub rsp, 0x10
0000113d: mov dword ptr [rbp - 4], edi
00001140: mov qword ptr [rbp - 0x10], rsi
00001144: lea rdi, [rip + 0xeb9]
0000114b: call 0x1030
00001150: mov eax, 0
00001155: leave
00001156: ret
```

#### Example 3 - Dump/display ROP gadgets in a ELF executable

```go
package main;

import(
    "github.com/zznop/sploit"
)

var program = "../test/prog1.x86_64"

func main() {
    elf, _ := sploit.NewELF(program)
    elf.DumpROPGadgets()
}
```

```
$ ./rop_dump_example
00001013: add esp, 8 ; ret
00001012: add rsp, 8 ; ret
00001010: call rax ; add rsp, 8 ; ret
0000100e: je 0x1012 ; call rax ; add rsp, 8 ; ret
0000100d: sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0000100c: test eax, eax ; je 0x1012 ; call rax ; add rsp, 8 ; ret
...
```

## Dependencies

Some of Sploit's functionality relies on external dependencies. For instance, Sploit uses GCC's GAS assembler to
compile assembly code and capstone to disassemble compiled code as part of the API exposed by `asm.go`.

Install capstone:

```
git clone https://github.com/aquynh/capstone.git --branch 4.0.2 --single-branch
cd capstone
make
sudo make install
```

Install GCC cross-compilers. The following commands assume you are running Debian or Ubuntu on a Intel workstation
and may need changed if running another Linux distro:

```
sudo apt install gcc gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu gcc-mips-linux-gnu \
  gcc-mipsel-linux-gnu gcc-powerpc-linux-gnu
```
