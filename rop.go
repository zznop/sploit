package sploit

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// GadgetExpr is a structure used to match gadget opcodes
type GadgetExpr struct {
	Operation []byte
	RegStart  uint8
	RegEnd    uint8
}

// Gadget stores information about a ROP gadgets including the address, instructions, and opcode bytes
type Gadget struct {
	Address uint64
	Instrs  string
	Opcode  []byte
}

// ROP is a interface for working with ROP gadgets
type ROP []*Gadget

// Dump is a ROP method that locates and prints ROP gadgets contained in the ELF file to stdout
func (r *ROP) Dump() {
	for _, gadget := range []*Gadget(*r) {
		fmt.Printf("0x%08x: %v\n", gadget.Address, gadget.Instrs)
	}
}

// InstrSearch is a ROP method that returns a ROP object containing gadgets with a sub-string match to the user-defined regex
func (r *ROP) InstrSearch(regex string) (ROP, error) {
	re, err := regexp.Compile(regex)
	if err != nil {
		return nil, err
	}

	matchGadgets := ROP{}
	for _, gadget := range []*Gadget(*r) {
		if re.FindAllString(gadget.Instrs, 1) != nil {
			matchGadgets = append(matchGadgets, gadget)
		}
	}

	return matchGadgets, nil
}

func filterGadgetsIntel(gadgets []*Gadget) []*Gadget {
	filtered := []*Gadget{}
	for i := 0; i < len(gadgets); i++ {
		if !strings.HasSuffix(strings.TrimSpace(gadgets[i].Instrs), "ret") || strings.Count(gadgets[i].Instrs, "ret") > 1 {
			continue
		}

		filtered = append(filtered, gadgets[i])
	}

	return filtered
}

func findGadgetsIntel(processor *Processor, data []byte, address uint64) ([]*Gadget, error) {
	gadgets := []*Gadget{}
	for i := 0; i < len(data); i++ {
		if data[i] == 0xc3 || data[i] == 0xcb {
			gadgetsRet, err := disasmInstrsFromRet(processor, data, i, address, 16, 1)
			if err != nil {
				return nil, err
			}

			gadgets = append(gadgets, gadgetsRet...)
		}
	}

	return filterGadgetsIntel(gadgets), nil
}

func reverseSlice(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}

func disasmInstrsFromRet(processor *Processor, data []byte, index int, address uint64, maxOpcodes int, instrSize int) ([]*Gadget, error) {
	stop := index - maxOpcodes
	if stop < 0 {
		stop = 0
	}

	gadgets := []*Gadget{}
	for i := index - instrSize; i > stop; i -= instrSize {
		instr, err := disasmGadget(address+uint64(i), data[i:index+instrSize], processor)
		if err != nil {
			continue
		}

		gadgets = append(
			gadgets,
			&Gadget{
				Address: address + uint64(i),
				Instrs:  instr,
				Opcode:  data[i : index+instrSize],
			},
		)
	}

	return gadgets, nil
}

func generateBranchOpcodesARM(processor *Processor) [][]byte {
	gadgetExprs := []GadgetExpr{
		GadgetExpr{[]byte{0xe1, 0x2f, 0xff}, 0x10, 0x1e}, // bx reg
		GadgetExpr{[]byte{0xe1, 0x2f, 0xff}, 0x30, 0x3e}, // blx reg
	}

	var opcodes [][]byte
	for i := 0; i < len(gadgetExprs); i++ {
		for j := gadgetExprs[i].RegStart; j < gadgetExprs[i].RegEnd; j++ {
			opcode := make([]byte, len(gadgetExprs[i].Operation)+1)
			copy(opcode, gadgetExprs[i].Operation)
			opcode[len(opcode)-1] = byte(j)
			if processor.Endian == LittleEndian {
				opcode = reverseSlice(opcode)
			}
			opcodes = append(opcodes, opcode)
		}
	}

	return opcodes
}

func findGadgetsARM(processor *Processor, data []byte, address uint64) ([]*Gadget, error) {
	branches := generateBranchOpcodesARM(processor)
	gadgets := []*Gadget{}
	for i := 0; i < len(data); i += 4 {
		for j := 0; j < len(branches); j++ {
			if i+len(branches[j]) > len(data) {
				break
			}

			if bytes.Compare(data[i:i+len(branches[j])], branches[j]) == 0 {
				gadgetsRet, err := disasmInstrsFromRet(processor, data, i, address, 20, 4)
				if err != nil {
					return nil, err
				}
				gadgets = append(gadgets, gadgetsRet...)
			}
		}
	}

	return gadgets, nil
}

func findGadgets(processor *Processor, data []byte, address uint64) ([]*Gadget, error) {
	switch processor.Architecture {
	case ArchX8664:
		return findGadgetsIntel(processor, data, address)
	case ArchIA64:
		return findGadgetsIntel(processor, data, address)
	case ArchI386:
		return findGadgetsIntel(processor, data, address)
	case ArchARM:
		return findGadgetsARM(processor, data, address)
	default:
		return nil, errors.New("ROP interface currently only supports Intel and ARM binaries")
	}
}
