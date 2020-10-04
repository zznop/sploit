package sploit;

import(
    "errors"
    "strings"
)

func disasmInstrsFromRet(processor *Processor, data []byte, index int, address uint64) (string, error) {
    stop := index - 15
    if stop < 0 {
        stop = 0
    }

    allGadgets := ""
    for i := index-1; i > stop; i-- {
        gadget, _ := DisasmROP(address+uint64(i), data[i:index+1], processor)
        if strings.Contains(gadget, "leave") ||
            !strings.HasSuffix(strings.TrimSpace(gadget), "ret") ||
            strings.Count(gadget, "ret") > 1 {
            continue
        }

        allGadgets += gadget
    }

    return allGadgets, nil
}

func findGadgetsIntel(processor *Processor, data []byte, address uint64) (string, error) {
    gadgets := ""
    for i := 0; i < len(data); i++ {
        if data[i] == 0xc3 || data[i] == 0xcb {
            gadgetsSeg, err := disasmInstrsFromRet(processor, data, i, address)
            if err != nil {
                return "", err
            }
            gadgets += gadgetsSeg
        }
    }
    return gadgets, nil
}

func findGadgets(processor *Processor, data []byte, address uint64) (string, error) {
    switch (processor.Architecture) {
    case ArchX8664:
        return findGadgetsIntel(processor, data, address)
    case ArchIA64:
        return findGadgetsIntel(processor, data, address)
    case ArchI386:
        return findGadgetsIntel(processor, data, address)
    default:
        return "", errors.New("ROP interface currently only supports Intel binaries")
    }
}
