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

func disasmInstrsFromRetIntel(processor *Processor, data []byte, index int, address uint64) ([]*Gadget, error) {
	stop := index - 15
	if stop < 0 {
		stop = 0
	}

	gadgets := []*Gadget{}
	for i := index - 1; i > stop; i-- {
		instr, err := disasmGadget(address+uint64(i), data[i:index+1], processor)
		if err != nil {
			continue
		}

		if strings.Contains(instr, "leave") ||
			!strings.HasSuffix(strings.TrimSpace(instr), "ret") ||
			strings.Count(instr, "ret") > 1 {
			continue
		}

		gadgets = append(
			gadgets,
			&Gadget{
				Address: address + uint64(i),
				Instrs:  instr,
				Opcode:  data[i : index+1],
			},
		)
	}

	return gadgets, nil
}

func findGadgetsIntel(processor *Processor, data []byte, address uint64) ([]*Gadget, error) {
	gadgets := []*Gadget{}
	for i := 0; i < len(data); i++ {
		if data[i] == 0xc3 || data[i] == 0xcb {
			gadgetsRet, err := disasmInstrsFromRetIntel(processor, data, i, address)
			if err != nil {
				return nil, err
			}

			gadgets = append(gadgets, gadgetsRet...)
		}
	}

	return gadgets, nil
}

func reverseSlice(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}

// TODO: this can be combined with the intel version
func disasmInstrsFromRetARM(processor *Processor, data []byte, index int, address uint64) ([]*Gadget, error) {
	stop := index - 16
	if stop < 0 {
		stop = 0
	}

	gadgets := []*Gadget{}
	for i := index - 4; i > stop; i -= 4 {
		instr, err := disasmGadget(address+uint64(i), data[i:index+4], processor)
		if err != nil {
			continue
		}

		gadgets = append(
			gadgets,
			&Gadget{
				Address: address + uint64(i),
				Instrs:  instr,
				Opcode:  data[i : index+4],
			},
		)
	}

	return gadgets, nil
}

func findGadgetsARM(processor *Processor, data []byte, address uint64) ([]*Gadget, error) {
	gadgetExprs := []GadgetExpr{
		GadgetExpr{[]byte{0xe1, 0x2f, 0xff}, 0x10, 0x1e}, // bx reg
		GadgetExpr{[]byte{0xe1, 0x2f, 0xff}, 0x30, 0x3e}, // blx reg
	}

	var gadgets [][]byte
	for i := 0; i < len(gadgetExprs); i++ {
		for j := gadgetExprs[i].RegStart; j < gadgetExprs[i].RegEnd; j++ {
			gadget := make([]byte, len(gadgetExprs[i].Operation)+1)
			copy(gadget, gadgetExprs[i].Operation)
			gadget[len(gadget)-1] = byte(j)
			if processor.Endian == LittleEndian {
				gadget = reverseSlice(gadget)
			}
			gadgets = append(gadgets, gadget)
		}
	}

	fullGadgets := []*Gadget{}
	for i := 0; i < len(data); i += 4 {
		for j := 0; j < len(gadgets); j++ {
			if i+len(gadgets[j]) > len(data) {
				break
			}

			if bytes.Compare(data[i:i+len(gadgets[j])], gadgets[j]) == 0 {
				gadgetsRet, err := disasmInstrsFromRetARM(processor, data, i, address)
				if err != nil {
					return nil, err
				}
				fullGadgets = append(fullGadgets, gadgetsRet...)
			}
		}
	}

	return fullGadgets, nil
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
