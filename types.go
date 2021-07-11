package sploit

import (
	"fmt"
)

// FileFormat represents the type of file under analysis
type FileFormat uint16

// Architecture represents processor architecture
type Architecture uint16

// Endian is a integer type that represents the byte order of a binary
type Endian int

const (
	// PEFile represents Microsoft PE file format
	PEFile = iota
	// ELFFile represents Unix ELF file format
	ELFFile
	// UnknownFile indicates that the file format is unsupported
	UnknownFile
)

const (
	// ArchX8664 indicates Intel x86-64 ISA
	ArchX8664 = iota
	// ArchI386 - Intel x86
	ArchI386
	// ArchARM - ARM (32-bit)
	ArchARM
	// ArchAARCH64 - ARM (64-bit)
	ArchAARCH64
	// ArchPPC - PowerPC
	ArchPPC
	// ArchMIPS - MIPS
	ArchMIPS
	// ArchIA64 - Intel Itanium
	ArchIA64
)

// Processor is a struct that represents a binary's machine type
type Processor struct {
	Architecture Architecture
	Endian       Endian
}

const (
	// LittleEndian - little endian byte order
	LittleEndian Endian = iota
	// BigEndian - big endian byte order
	BigEndian Endian = iota
)

func (e Endian) String() string {
	switch e {
	case LittleEndian:
		return "little"
	case BigEndian:
		return "big"
	default:
		return fmt.Sprintf("%d", int(e))
	}
}

// Mitigations is used to store information on exploit mitigations detected while loading the binary
type Mitigations struct {
	Canary bool
	NX     bool
}
