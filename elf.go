package sploit

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

// ELF is a struct that contains methods for operating on an ELF file
type ELF struct {
	E           *elf.File
	Processor   *Processor
	PIE         bool
	Mitigations *Mitigations
	raw         []byte
}

// NewELF loads an ELF file from disk and initializes the ELF struct
func NewELF(filename string) (*ELF, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rawData, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

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
		"Machine Type : %s\n"+
			"Endian       : %s\n"+
			"PIE          : %v\n"+
			"Stack Canary : %v\n"+
			"NX           : %v\n",
		e.Machine, processor.Endian, isPIE, mitigations.Canary, mitigations.NX,
	)

	return &ELF{
		E:           e,
		Processor:   processor,
		PIE:         isPIE,
		Mitigations: mitigations,
		raw:         rawData,
	}, nil
}

// OffsetToVA determines the virtual address for the specified file offset
func (e *ELF) OffsetToAddr(offset uint64) (uint64, error) {
	for i := 0; i < len(e.E.Progs); i++ {
		s := e.E.Progs[i]
		start := s.Off
		end := s.Off + s.Filesz

		if offset >= start && offset < end {
			return offset - s.Off + s.Vaddr, nil
		}
	}

	return 0, errors.New("Offset is not in range of an ELF segment")
}

// AddrToOffset determines the offset for the specified virtual address
func (e *ELF) AddrToOffset(address uint64) (uint64, error) {
	for i := 0; i < len(e.E.Progs); i++ {
		s := e.E.Progs[i]
		start := s.Vaddr
		end := s.Vaddr + s.Filesz

		if address >= start && address < end {
			return address - s.Vaddr + s.Off, nil
		}
	}

	return 0, errors.New("Address is not in range of an ELF segment")
}

// BSS returns the virtual address of the specified offset into the .bss section
func (e *ELF) BSS(offset uint64) (uint64, error) {
	section := e.E.Section(".bss")
	if section == nil {
		return 0, errors.New("No .bss section")
	}

	if offset >= section.Size {
		return 0, errors.New("Offset exceeds end of .bss")
	}

	return section.Addr + offset, nil
}

// Read returns a slice of bytes read from the ELF at the specified virtual address
func (e *ELF) Read(address uint64, nBytes int) ([]byte, error) {
	s, err := getVASegment(e.E, address)
	if err != nil {
		return nil, err
	}

	offset := address - s.Vaddr
	if s.Filesz-offset < uint64(nBytes) {
		nBytes = int(s.Filesz - offset)
	}

	buf := make([]byte, nBytes)
	_, err = s.ReadAt(buf, int64(offset))
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// Write copies data to the in-memory raw ELF data at the specified virtual address
func (e *ELF) Write(data []byte, address uint64) error {
	offset, err := e.AddrToOffset(address)
	if err != nil {
		return err
	}

	copy(e.raw[offset:offset+uint64(len(data))], data)
	return nil
}

// Write8 copies a uint8 to the in-memory ELF data at the specified address
func (e *ELF) Write8(i uint8, address uint64) error {
	return e.Write([]byte{i}, address)
}

// Write16LE copies a uint16 (little endian) to the in-memory ELF data at the specified address
func (e *ELF) Write16LE(i uint16, address uint64) error {
	return e.Write(PackUint16LE(i), address)
}

// Write16BE copies a uint16 (big endian) to the in-memory ELF data at the specified address
func (e *ELF) Write16BE(i uint16, address uint64) error {
	return e.Write(PackUint16BE(i), address)
}

// Write32LE copies a uint32 (little endian) to the in-memory ELF data at the specified address
func (e *ELF) Write32LE(i uint32, address uint64) error {
	return e.Write(PackUint32LE(i), address)
}

// Write32BE copies a uint32 (big endian) to the in-memory ELF data at the specified address
func (e *ELF) Write32BE(i uint32, address uint64) error {
	return e.Write(PackUint32BE(i), address)
}

// Write64LE copies a uint64 (little endian) to the in-memory ELF data at the specified address
func (e *ELF) Write64LE(i uint64, address uint64) error {
	return e.Write(PackUint64LE(i), address)
}

// Write64BE copies a uint64 (big endian) to the in-memory ELF data at the specified address
func (e *ELF) Write64BE(i uint64, address uint64) error {
	return e.Write(PackUint64BE(i), address)
}

// Read8 reads 8 bits from the ELF at the specified address and returns the data as a uint8
func (e *ELF) Read8(address uint64) (uint8, error) {
	b, err := e.readIntBytes(address, 1)
	if err != nil {
		return 0, err
	}

	return b[0], nil
}

// Read16LE reads 16 bits from the ELF at the specified address and returns a Uint16 in little endian byte order
func (e *ELF) Read16LE(address uint64) (uint16, error) {
	b, err := e.readIntBytes(address, 2)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint16(b), nil
}

// Read16BE reads 16 bits from the ELF at the specified address and returns a Uint16 in big endian byte order
func (e *ELF) Read16BE(address uint64) (uint16, error) {
	b, err := e.readIntBytes(address, 2)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint16(b), nil
}

// Read32LE reads 32 bits from the ELF at the specified address and returns a Uint32 in little endian byte order
func (e *ELF) Read32LE(address uint64) (uint32, error) {
	b, err := e.readIntBytes(address, 4)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(b), nil
}

// Read32BE reads 32 bits from the ELF at the specified address and returns a Uint32 in big endian byte order
func (e *ELF) Read32BE(address uint64) (uint32, error) {
	b, err := e.readIntBytes(address, 4)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b), nil
}

// Read64LE reads 64 bits from the ELF at the specified address and returns a Uint64 in little endian byte order
func (e *ELF) Read64LE(address uint64) (uint64, error) {
	b, err := e.readIntBytes(address, 8)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(b), nil
}

// Read64BE reads 64 bits from the ELF at the specified address and returns a Uint64 in big endian byte order
func (e *ELF) Read64BE(address uint64) (uint64, error) {
	b, err := e.readIntBytes(address, 8)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(b), nil
}

// Disasm disassembles code at the specified virtual address and returns a string containing assembly instructions
func (e *ELF) Disasm(address uint64, nBytes int) (string, error) {
	data, err := e.Read(address, nBytes)
	if err != nil {
		return "", err
	}

	arch := getCapstoneArch(e.Processor)
	mode := getCapstoneMode(e.Processor)
	return disasm(data, address, arch, mode, false)
}

// ROP locates all ROP gadgets in the ELF's executable segments and returns a ROP object
func (e *ELF) ROP() (*ROP, error) {
	file := e.E
	gadgets := ROP{}
	for i := 0; i < len(file.Progs); i++ {
		// Check if segment is executable
		if file.Progs[i].Flags&elf.PF_X == 0 {
			continue
		}

		// Segment is executable, read segment data
		data, err := e.Read(file.Progs[i].Vaddr, int(file.Progs[i].Filesz))
		if err != nil {
			return nil, err
		}

		// Search for gadgets in data
		gadgetsSeg, err := findGadgets(e.Processor, data, file.Progs[i].Vaddr)
		if err != nil {
			return nil, err
		}

		gadgets = append(gadgets, gadgetsSeg...)
	}

	return &gadgets, nil
}

// GetSignatureVAddrs searches for the specified sequence of bytes in all segments
func (e *ELF) GetSignatureVAddrs(signature []byte) ([]uint64, error) {
	return e.getSignatureVAddrs(signature, false)
}

// GetOpcodeVAddrs searches for the specified sequence of bytes in executable segments only
func (e *ELF) GetOpcodeVAddrs(signature []byte) ([]uint64, error) {
	return e.getSignatureVAddrs(signature, true)
}

// Save saves the raw ELF content to a specified file path
func (e *ELF) Save(filePath string, fileMode os.FileMode) error {
	return ioutil.WriteFile(filePath, e.raw, fileMode)
}

// AsmPatch compiles an assembly patch and writes it to the in-memory raw ELF data at the specified virtual address
func (e *ELF) AsmPatch(code string, address uint64) error {
	opcode, err := Asm(e.Processor, code)
	if err != nil {
		return err
	}

	return e.Write(opcode, address)
}

func (e *ELF) getSignatureVAddrs(signature []byte, exeOnly bool) ([]uint64, error) {
	file := e.E
	vaddrs := []uint64{}
	for i := 0; i < len(file.Progs); i++ {
		if exeOnly {
			if file.Progs[i].Flags&elf.PF_X == 0 {
				continue
			}
		}

		data, err := e.Read(file.Progs[i].Vaddr, int(file.Progs[i].Filesz))
		if err != nil {
			return nil, errors.New("Failed to read from segment")
		}

		// Search for byte signature in segment
		n := 0
		for {
			idx := bytes.Index(data[n:], signature)
			if idx == -1 {
				break
			}

			vaddrs = append(vaddrs, file.Progs[i].Vaddr+uint64(n)+uint64(idx))
			n += idx + 1
		}
	}

	return vaddrs, nil
}

func getVASegment(e *elf.File, address uint64) (*elf.Prog, error) {
	for i := 0; i < len(e.Progs); i++ {
		s := e.Progs[i]
		start := s.Vaddr
		end := s.Vaddr + s.Filesz

		if address >= start && address < end {
			return s, nil
		}
	}

	return nil, errors.New("Address is not in range of an ELF section")
}

func getArchInfo(e *elf.File) (*Processor, error) {
	supported := map[elf.Machine]Architecture{
		elf.EM_X86_64:  ArchX8664,
		elf.EM_386:     ArchI386,
		elf.EM_ARM:     ArchARM,
		elf.EM_AARCH64: ArchAARCH64,
		elf.EM_PPC:     ArchPPC,
		elf.EM_MIPS:    ArchMIPS,
		elf.EM_IA_64:   ArchIA64,
	}

	endian := LittleEndian
	if e.Data == elf.ELFDATA2MSB {
		endian = BigEndian
	}

	if arch, ok := supported[e.Machine]; ok {
		return &Processor{
			Architecture: arch,
			Endian:       endian,
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

	return &Mitigations{
		Canary: canary,
		NX:     nx,
	}, nil
}

func (e *ELF) readIntBytes(address uint64, width int) ([]byte, error) {
	b, err := e.Read(address, width)
	if err != nil {
		return nil, err
	}

	if len(b) != width {
		return nil, errors.New("Read truncated do to end of segment")
	}

	return b, nil
}
