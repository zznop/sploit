package sploit;

import (
    log "github.com/sirupsen/logrus"
    "debug/elf"
    "errors"
    "fmt"
)

// ELFType is a struct that represents the ELF type
type ELFType struct {
    ID int
    Description string
    PIE bool
}

// Mitigations is a struct that stores information on ELF mitigations
type Mitigations struct {
    Canary bool
    NX bool
}

// ELF is a struct that contains methods for operating on an ELF file
type ELF struct {
    E *elf.File
    Processor *Processor
    PIE bool
    Mitigations *Mitigations
}

// NewELF returns an initialized Elf structure
func NewELF(filename string) (*ELF, error) {
    e, err := elf.Open(filename)
    if err != nil {
        return nil, err
    }

    processor, err := getArchInfo(e)
    if err != nil {
        return nil, err
    }

    isPIE := (e.Type == elf.ET_DYN)
    mitigations, err := checkMitigations(e)
    if err != nil {
        return nil, err
    }

    log.Debugf(
        "Machine Type : %s\n" +
        "Endian       : %s\n" +
        "PIE          : %v\n" +
        "Stack Canary : %v\n" +
        "NX           : %v\n",
        e.Machine, processor.Endian, isPIE, mitigations.Canary, mitigations.NX,
    )

    return &ELF{
        E: e,
        Processor: processor,
        PIE: isPIE,
        Mitigations: mitigations,
    }, nil
}

// BSS returns the address of the BSS section plus the specified offset
func (e *ELF)BSS(offset uint64)(uint64, error) {
    section := e.E.Section(".bss")
    if section == nil {
        return 0, errors.New("No .bss section")
    }

    if offset >= section.Size {
        return 0, errors.New("Offset exceeds end of .bss")
    }

    return section.Addr+offset, nil
}

// Read is a method for reading bytes from the specified virtual address of an ELF
func (e *ELF)Read(address uint64, nBytes uint64)([]byte, error) {
    s, err := getVaddrSegment(e.E, address)
    if err != nil {
        return nil, err
    }

    offset := address - s.Vaddr
    if s.Filesz - offset < nBytes {
        nBytes = s.Filesz - offset
    }

    buf := make([]byte, nBytes)
    _, err  = s.ReadAt(buf, int64(offset))
    if err != nil {
        return nil, err
    }

    return buf, nil
}

// Disasm returns a string of disassembled instructions
func (e *ELF)Disasm(address uint64, nBytes uint64)(string, error) {
    data, err := e.Read(address, nBytes)
    if err != nil {
        return "", err
    }

    arch := getCapstoneArch(e.Processor)
    mode := getCapstoneMode(e.Processor)
    return disasm(data, address, arch, mode, false)
}

// DumpROPGadgets computes and displays ROP gadgets
func (e *ELF)DumpROPGadgets() error {
    file := e.E
    for i := 0; i < len(file.Progs); i++ {
        // Check if segment is executable
        if file.Progs[i].Flags & elf.PF_X == 0 {
            continue
        }

        // Segment is executable, read segment data
        start := file.Progs[i].Vaddr
        size := uint64(file.Progs[i].Filesz)
        data, err := e.Read(start, size)
        if err != nil {
            return err
        }

        // Search for gadgets in data
        gadgets, err := findGadgets(e.Processor, data, file.Progs[i].Vaddr)
        if err != nil {
            return err
        }

        fmt.Print(gadgets)
    }
    return nil
}

func getVaddrSegment(e *elf.File, address uint64)(*elf.Prog, error) {
    for i := 0; i < len(e.Progs); i++ {
        s := e.Progs[i]
        start := s.Vaddr
        end := s.Vaddr + s.Filesz

        if address >= start && address < end {
            return s, nil
        }
    }

    return  nil, errors.New("Address is not in range of a ELF section")
}

func getArchInfo(e *elf.File) (*Processor, error) {
    supported := map[elf.Machine]Architecture {
        elf.EM_X86_64 : ArchX8664,
        elf.EM_386 : ArchI386,
        elf.EM_ARM : ArchARM,
        elf.EM_AARCH64 : ArchAARCH64,
        elf.EM_PPC : ArchPPC,
        elf.EM_MIPS : ArchMIPS,
        elf.EM_IA_64 : ArchIA64,
    }

    endian := LittleEndian
    if e.Data == elf.ELFDATA2MSB {
        endian = BigEndian
    }

    if arch, ok := supported[e.Machine]; ok {
        return &Processor {
            Architecture: arch,
            Endian: endian,
        }, nil
    }
    return nil, errors.New("Unsupported machine type")
}

func checkMitigations(e *elf.File) (*Mitigations, error) {
    // Check if there's a stack canary
    symbols, err := e.Symbols()
    if err != nil {
        return nil, err
    }

    canary := false
    for _, symbol := range symbols {
        if symbol.Name == "__stack_chk_fail" {
            canary = true
            break
        }
    }

    // Check for executable stack (NX)
    nx := false
    for _, prog := range e.Progs {
        if uint32(prog.Type) == uint32(0x6474e551) { // PT_GNU_STACK
            if (uint32(prog.Flags) & uint32(elf.PF_X)) == 0 {
                nx = true
                break
            }
        }
    }

    return &Mitigations {
        Canary: canary,
        NX: nx,
    }, nil
}
