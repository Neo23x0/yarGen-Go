package extractor

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"fmt"
)

var nullPattern = []byte{0x00, 0x00, 0x00}

func ExtractOpcodes(data []byte, numOpcodes int) ([]string, error) {
	if IsPEFile(data) {
		return extractPEOpcodes(data, numOpcodes)
	}

	if IsELFFile(data) {
		return extractELFOpcodes(data, numOpcodes)
	}

	return nil, nil
}

func extractPEOpcodes(data []byte, numOpcodes int) ([]string, error) {
	peFile, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE: %w", err)
	}
	defer peFile.Close()

	var textSection *pe.Section
	for _, section := range peFile.Sections {
		if section.Name == ".text" {
			textSection = section
			break
		}
	}

	if textSection == nil {
		for _, section := range peFile.Sections {
			if section.Characteristics&pe.IMAGE_SCN_CNT_CODE != 0 {
				textSection = section
				break
			}
		}
	}

	if textSection == nil {
		return nil, nil
	}

	textData, err := textSection.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .text section: %w", err)
	}

	return extractOpcodesFromData(textData, numOpcodes), nil
}

func extractELFOpcodes(data []byte, numOpcodes int) ([]string, error) {
	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF: %w", err)
	}
	defer elfFile.Close()

	textSection := elfFile.Section(".text")
	if textSection == nil {
		return nil, nil
	}

	textData, err := textSection.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .text section: %w", err)
	}

	return extractOpcodesFromData(textData, numOpcodes), nil
}

func extractOpcodesFromData(data []byte, numOpcodes int) []string {
	parts := bytes.Split(data, nullPattern)

	var opcodes []string
	for _, part := range parts {
		part = bytes.TrimLeft(part, "\x00")

		if len(part) < 8 {
			continue
		}

		opcodeLen := 16
		if len(part) < opcodeLen {
			opcodeLen = len(part)
		}

		opcode := hex.EncodeToString(part[:opcodeLen])
		opcodes = append(opcodes, opcode)

		if len(opcodes) >= numOpcodes*3 {
			break
		}
	}

	return opcodes
}

func FormatOpcode(opcode string) string {
	var formatted []string
	for i := 0; i < len(opcode); i += 2 {
		if i+2 <= len(opcode) {
			formatted = append(formatted, opcode[i:i+2])
		}
	}
	return joinStrings(formatted, " ")
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
