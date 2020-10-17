package sploit;

import (
    "errors"
    "github.com/knightsc/gapstone"
    "fmt"
    "io/ioutil"
    "os/exec"
    "os"
    log "github.com/sirupsen/logrus"
)

var sourcePath = "/tmp/prog.S"
var objectPath = "/tmp/prog.o"
var blobPath = "/tmp/prog.bin"

// Asm complies assembly instructions to a byte slice containing machine code
func Asm(processor *Processor, code string) ([]byte, error) {
    prefix, err := getToolchainPrefix(processor)
    if err != nil {
        return nil, err
    }

    err = createSourceFile(processor, code)
    if err != nil {
        return nil, err
    }

    err = buildProgram(processor, prefix)
    if err != nil {
        return nil, err
    }

    opcodes, err := dumpText(prefix)
    os.Remove(sourcePath)
    os.Remove(objectPath)
    os.Remove(blobPath)
    return opcodes, err
}

// Disasm disassembles a supplied byte slice and returns a string containing the assembly instructions
func Disasm(address uint64, code []byte, processor *Processor) (string, error) {
    arch := getCapstoneArch(processor)
    mode := getCapstoneMode(processor)
    return disasm(code, address, arch, mode, false)
}

func createSourceFile(processor *Processor, code string) error {
    srcCode := ".section .text\n.global _start\n"
    if processor.Architecture == ArchI386 || processor.Architecture == ArchX8664 || processor.Architecture == ArchIA64 {
        srcCode += ".intel_syntax noprefix"
    }
    srcCode += "\n\n_start:\n" + code
    err := ioutil.WriteFile(sourcePath, []byte(srcCode), 0644)
    if err != nil {
        return err
    }

    return nil
}

func buildProgram(processor *Processor, prefix string) (error) {
    compilerExe, err := exec.LookPath(prefix + "gcc")
    if err != nil {
        return err
    }

    // Construct compile command arguments
    args := []string{compilerExe, "-c", "-fpic"}
    if processor.Architecture == ArchI386 {
        args = append(args, "-m32")
    }

    args = append(args, sourcePath)
    args = append(args, "-o")
    args = append(args, objectPath)

    cmdCompile := &exec.Cmd {
        Path: compilerExe,
        Args: args,
        Stdout: os.Stdout,
        Stderr: os.Stdout,
    }

    return cmdCompile.Run()
}

func dumpText(prefix string) ([]byte, error) {
    objcopyExe, err := exec.LookPath(prefix + "objcopy")
    if err != nil {
        return nil, err
    }

    args := []string{objcopyExe, "-O", "binary", "--only-section=.text", objectPath, blobPath}
    cmdObjcopy := &exec.Cmd {
        Path: objcopyExe,
        Args: args,
        Stdout: os.Stdout,
        Stderr: os.Stdout,
    }

    // Objcopy the .text section to a binary file
    err = cmdObjcopy.Run()
    if err != nil {
        return nil, err
    }

    // Open the objcopy'd blob
    f, err := os.Open(blobPath)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    // Read the entire thing
    opcodes, err := ioutil.ReadAll(f)
    if err != nil {
        return nil, err
    }

    return opcodes, nil
}

func getToolchainPrefix(processor *Processor) (string, error) {
    switch processor.Architecture {
    case ArchX8664:
        return "x86_64-linux-gnu-", nil
    case ArchI386:
        return "x86_64-linux-gnu-", nil
    case ArchARM:
        if processor.Endian == LittleEndian {
            return "arm-linux-gnueabi-", nil
        }
        return "arm-linux-gnueabihf-", nil
    case ArchAARCH64:
        return "aarch64-linux-gnu-", nil
    case ArchPPC:
        return "powerpc-linux-gnu-", nil
    case ArchMIPS:
        if processor.Endian == LittleEndian {
            return "mipsel-linux-gnu-", nil
        }
        return "mips-linux-gnu-", nil
    case ArchIA64:
        return "x86_64-linux-gnu-", nil
    default:
        return "", errors.New("Unsupported architecture")
    }
}

func disasm(data []byte, address uint64, arch int, mode int, isROP bool)(string, error) {
    engine, err := gapstone.New(arch, mode)
    if err != nil {
        return "", err
    }

    insns, err := engine.Disasm(data, address, 0)
    if err != nil {
        return "", err
    }

    insnsStr := ""
    for i := 0; i < len(insns); i++ {
        if isROP {
            insnsStr += fmt.Sprintf("%s %s", insns[i].Mnemonic, insns[i].OpStr)
            if i+1 != len(insns) {
                insnsStr += " ; "
            }
        } else {
            insnsStr += fmt.Sprintf("%08x: %s %s\n", insns[i].Address, insns[i].Mnemonic, insns[i].OpStr)
        }
    }

    log.Debugf(insnsStr)
    return insnsStr, nil
}

func getCapstoneArch(processor *Processor) int {
    archs := map[Architecture]int {
        ArchX8664 : gapstone.CS_ARCH_X86,
        ArchI386 : gapstone.CS_ARCH_X86,
        ArchARM : gapstone.CS_ARCH_ARM,
        ArchAARCH64 : gapstone.CS_ARCH_ARM64,
        ArchPPC : gapstone.CS_ARCH_PPC,
        ArchMIPS : gapstone.CS_ARCH_MIPS,
        ArchIA64 : gapstone.CS_ARCH_X86,
    }

    return archs[processor.Architecture]
}

func getCapstoneMode(processor *Processor) int {
    modes := map[Architecture]int {
        ArchX8664 : gapstone.CS_MODE_64,
        ArchI386 : gapstone.CS_MODE_32,
        ArchARM : gapstone.CS_MODE_32,
        ArchAARCH64 : gapstone.CS_MODE_64,
        ArchPPC : gapstone.CS_MODE_32,
        ArchMIPS : gapstone.CS_MODE_32,
        ArchIA64 : gapstone.CS_MODE_64,
    }
    mode := modes[processor.Architecture]
    if processor.Endian == BigEndian {
        mode |= gapstone.CS_MODE_BIG_ENDIAN
    } else {
        mode |= gapstone.CS_MODE_LITTLE_ENDIAN
    }

    return mode
}

func disasmGadget(address uint64, code []byte, processor *Processor) (string, error) {
    arch := getCapstoneArch(processor)
    mode := getCapstoneMode(processor)
    return disasm(code, address, arch, mode, true)
}
