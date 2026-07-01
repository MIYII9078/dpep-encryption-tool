package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func applyForwardOps(data []byte, chain []byte, masterKey []byte) ([]byte, error) {
	current := make([]byte, len(data))
	copy(current, data)
	i := 0
	for i < len(chain) {
		op := chain[i]
		i++
		switch op {
		case 0x00:
			return current, nil
		case 0x08:
			if i >= len(chain) {
				return nil, fmt.Errorf("truncated deflate")
			}
			level := int(chain[i])
			i++
			var err error
			current, err = DeflateCompress(current, level)
			if err != nil {
				return nil, err
			}
		case 0x09:
			// raw
		case 0x0A:
			// varint (placeholder)
		case 0x0E, 0x11:
			if op == 0x0E {
				i++
			}
		case 0x0F:
			return current, nil
		case 0x10:
			if i >= len(chain) {
				return nil, fmt.Errorf("truncated baseN")
			}
			base := int(chain[i])
			i++
			encoded := BaseEncode(current, base)
			current = []byte(encoded)
		case 0x12:
			if i+2 > len(chain) {
				return nil, fmt.Errorf("truncated scrambler")
			}
			_ = int(chain[i]) // rounds
			i++
			seedLen := int(chain[i])
			i++
			if i+seedLen > len(chain) {
				return nil, fmt.Errorf("truncated scrambler seed")
			}
			_ = chain[i : i+seedLen] // seed
			i += seedLen

			scramblerKey := deriveOpKey(masterKey, "scrambler", 32)
			current = ScrambleXOREncrypt(current, scramblerKey, 3)
		case 0x13:
			if i+2 > len(chain) {
				return nil, fmt.Errorf("truncated AESCipher")
			}
			_ = int(chain[i]) // rounds
			i++
			_ = chain[i] // sbox selector
			i++

			cipherKey := deriveOpKey(masterKey, "aescipher-v2", 16)
			for j := 0; j+16 <= len(current); j += 16 {
				block := make([]byte, 16)
				copy(block, current[j:j+16])
				encBlock := AESCipherEncrypt(block, cipherKey)
				copy(current[j:j+16], encBlock)
			}
		default:
			return nil, fmt.Errorf("unknown opcode 0x%02X", op)
		}
	}
	return current, nil
}

func applyReverseOps(data []byte, chain []byte, masterKey []byte) ([]byte, error) {
	type opEntry struct {
		code byte
		args []byte
	}
	var ops []opEntry
	i := 0
	for i < len(chain) {
		op := chain[i]
		i++
		switch op {
		case 0x00:
			ops = append(ops, opEntry{code: 0x00})
			break
		case 0x08:
			ops = append(ops, opEntry{code: 0x08, args: chain[i : i+1]})
			i++
		case 0x09:
			ops = append(ops, opEntry{code: 0x09})
		case 0x0A:
			ops = append(ops, opEntry{code: 0x0A})
		case 0x0E:
			ops = append(ops, opEntry{code: 0x0E, args: chain[i : i+1]})
			i++
		case 0x0F:
			ops = append(ops, opEntry{code: 0x0F})
		case 0x10:
			ops = append(ops, opEntry{code: 0x10, args: chain[i : i+1]})
			i++
		case 0x11:
			ops = append(ops, opEntry{code: 0x11})
		case 0x12:
			rounds := chain[i]
			i++
			seedLen := chain[i]
			i++
			seed := chain[i : i+int(seedLen)]
			i += int(seedLen)
			args := append([]byte{rounds, byte(seedLen)}, seed...)
			ops = append(ops, opEntry{code: 0x12, args: args})
		case 0x13:
			rounds := chain[i]
			i++
			sbox := chain[i]
			i++
			ops = append(ops, opEntry{code: 0x13, args: []byte{rounds, sbox}})
		}
	}

	current := make([]byte, len(data))
	copy(current, data)
	for j := len(ops) - 1; j >= 0; j-- {
		op := ops[j]
		switch op.code {
		case 0x00:
			continue
		case 0x08:
			var err error
			current, err = DeflateDecompress(current)
			if err != nil {
				return nil, err
			}
		case 0x09:
		case 0x0A:
		case 0x10:
			base := int(op.args[0])
			decoded, err := BaseDecode(string(current), base)
			if err != nil {
				return nil, err
			}
			current = decoded
		case 0x12:
			_ = int(op.args[0]) // rounds
			_ = int(op.args[1]) // seedLen
			_ = op.args[2:]     // seed

			scramblerKey := deriveOpKey(masterKey, "scrambler", 32)
			current = ScrambleXORDecrypt(current, scramblerKey, 3)
		case 0x13:
			_ = op.args[0] // rounds
			_ = op.args[1] // sbox

			cipherKey := deriveOpKey(masterKey, "aescipher-v2", 16)
			for k := 0; k+16 <= len(current); k += 16 {
				block := make([]byte, 16)
				copy(block, current[k:k+16])
				decBlock := AESCipherDecrypt(block, cipherKey)
				copy(current[k:k+16], decBlock)
			}
		}
	}
	return current, nil
}

func deriveOpKey(masterKey []byte, info string, length int) []byte {
	reader := hkdf.Expand(sha256.New, masterKey, []byte(info))
	key := make([]byte, length)
	_, err := io.ReadFull(reader, key)
	if err != nil {
		panic(err)
	}
	return key
}
