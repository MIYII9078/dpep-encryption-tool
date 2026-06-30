package protocol

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var allowedOpcodes = map[byte]bool{
	0x00: true, 0x08: true, 0x09: true, 0x0A: true,
	0x0C: true, 0x0E: true, 0x0F: true, 0x10: true,
	0x11: true, 0x12: true, 0x13: true,
}

var opcodeParamSizes = map[byte]int{
	0x00: 0,
	0x08: 1,
	0x09: 0,
	0x0A: 0,
	0x0C: 1,
	0x0E: 1,
	0x0F: 0,
	0x10: 1,
	0x11: 0,
	0x12: -1,
	0x13: 2,
}

func ParseHexChain(hexStr string) ([]byte, error) {
	parts := strings.Fields(hexStr)
	chain := make([]byte, 0, len(parts))
	for _, p := range parts {
		if len(p) != 2 {
			return nil, fmt.Errorf("invalid hex byte: %s", p)
		}
		b, err := hex.DecodeString(p)
		if err != nil {
			return nil, err
		}
		chain = append(chain, b...)
	}
	if err := ValidateChain(chain); err != nil {
		return nil, err
	}
	return chain, nil
}

func ValidateChain(chain []byte) error {
	if len(chain) == 0 {
		return fmt.Errorf("chain empty")
	}
	if len(chain) > 255 {
		return fmt.Errorf("chain too long (%d bytes, max 255)", len(chain))
	}
	i := 0
	hasKeyDeriv := false
	hasAESGCM := false
	for i < len(chain) {
		op := chain[i]
		if !allowedOpcodes[op] {
			return fmt.Errorf("unknown opcode 0x%02X at position %d", op, i)
		}
		if op == 0x00 {
			if i != len(chain)-1 {
				return fmt.Errorf("terminator 0x00 not at end")
			}
			break
		}
		paramLen, ok := opcodeParamSizes[op]
		if !ok {
			return fmt.Errorf("internal error: no param size for 0x%02X", op)
		}
		switch op {
		case 0x0E:
			algo := chain[i+1]
			if algo == 0x01 || algo == 0x02 || algo == 0x04 {
				hasKeyDeriv = true
			}
		case 0x11:
			hasKeyDeriv = true
		case 0x0F:
			hasAESGCM = true
		case 0x12:
			if i+2 >= len(chain) {
				return fmt.Errorf("truncated Chaos params")
			}
			seedLen := int(chain[i+2])
			if seedLen < 32 {
				return fmt.Errorf("chaos seed length too short: %d", seedLen)
			}
			paramLen = 2 + seedLen
		}
		i += 1 + paramLen
		if i > len(chain) {
			return fmt.Errorf("chain truncated at opcode 0x%02X", op)
		}
	}
	if chain[len(chain)-1] != 0x00 {
		return fmt.Errorf("chain must end with 0x00")
	}
	if !hasKeyDeriv {
		return fmt.Errorf("chain missing key derivation (0x0E or 0x11)")
	}
	if !hasAESGCM {
		return fmt.Errorf("chain missing AES-256-GCM (0x0F)")
	}
	return nil
}
