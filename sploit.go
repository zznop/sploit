package sploit;

import(
    "fmt"
)

// FileFormat represents the type of file under analysis
type FileFormat uint16

// PEFile represents Microsoft PE file format
const PEFile      = 0
// ELFFile represents Unix ELF file format
const ELFFile     = 1
// UnknownFile indicates that the file format is unsupported
const UnknownFile = 2

// Architecture represents processor architecture
type Architecture uint16

// ArchX8664 indicates Intel x86-64 ISA
const ArchX8664 = 0
// ArchI386 - Intel x86
const ArchI386 = 1
// ArchARM - ARM (32-bit)
const ArchARM = 2
// ArchAARCH64 - ARM (64-bit)
const ArchAARCH64 = 3
// ArchPPC - PowerPC
const ArchPPC = 4
// ArchMIPS - MIPS
const ArchMIPS = 5
// ArchIA64 - Intel Itanium
const ArchIA64 = 6

// Processor is a struct that represents a binary's machine type
type Processor struct {
    Architecture Architecture
    Endian Endian
}

// Endian is a integer type that represents the byte order of a binary
type Endian int

// LittleEndian - little endian byte order
const LittleEndian Endian = 0
// BigEndian - big endian byte order
const BigEndian Endian = 1

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
    NX bool
}

