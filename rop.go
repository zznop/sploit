package sploit;

import(
    "errors"
    "strings"
    "regexp"
    "fmt"
)

// Gadget stores information about a ROP gadgets including the address, instructions, and opcode bytes
type Gadget struct {
    Address uint64
    Instrs string
    Opcode []byte
}

// ROP is a interface for working with ROP gadgets
type ROP []*Gadget

// Dump locates and prints ROP gadgets contained in the ELF file to stdout
func (r *ROP)Dump() {
    for _, gadget := range []*Gadget(*r) {
        fmt.Printf("0x%08x: %v\n", gadget.Address, gadget.Instrs)
    }
}

// InstrSearch returns ROP object containing ROP gadgets with a sub-string match to the user-defined regex
func (r *ROP)InstrSearch(regex string)(ROP, error) {
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

func disasmInstrsFromRet(processor *Processor, data []byte, index int, address uint64) ([]*Gadget, error) {
    stop := index - 15
    if stop < 0 {
        stop = 0
    }

    gadgets := []*Gadget{}
    for i := index-1; i > stop; i-- {
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
            &Gadget {
                Address: address+uint64(i),
                Instrs: instr,
                Opcode: data[i:index+1],
            },
        )
    }

    return gadgets, nil
}

func findGadgetsIntel(processor *Processor, data []byte, address uint64) ([]*Gadget, error) {
    gadgets := []*Gadget{}
    for i := 0; i < len(data); i++ {
        if data[i] == 0xc3 || data[i] == 0xcb {
            gadgetsRet, err := disasmInstrsFromRet(processor, data, i, address)
            if err != nil {
                return nil, err
            }

            gadgets = append(gadgets, gadgetsRet...)
        }
    }

    return gadgets, nil
}

func findGadgets(processor *Processor, data []byte, address uint64) ([]*Gadget, error) {
    switch (processor.Architecture) {
    case ArchX8664:
        return findGadgetsIntel(processor, data, address)
    case ArchIA64:
        return findGadgetsIntel(processor, data, address)
    case ArchI386:
        return findGadgetsIntel(processor, data, address)
    default:
        return nil, errors.New("ROP interface currently only supports Intel binaries")
    }
}
