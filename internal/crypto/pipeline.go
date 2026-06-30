package crypto

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"

	"dpep/internal/protocol"
)

type EncryptOptions struct {
	Plaintext []byte
	Password  string
	KeyFile   []byte
	Chain     []byte
	Split     bool
	HdrPath   string
	DatPath   string
}

type EncryptResult struct {
	SingleFile []byte
}

func Encrypt(opts EncryptOptions) (*EncryptResult, error) {
	var masterKey []byte
	var salt []byte
	var mode byte

	if opts.Password != "" {
		var err error
		salt, err = GenerateSalt()
		if err != nil {
			return nil, fmt.Errorf("salt: %w", err)
		}
		masterKey, err = DeriveKeyFromPassword(opts.Password, salt)
		if err != nil {
			return nil, err
		}
		mode = protocol.ModePassword
	} else {
		if len(opts.KeyFile) != 32 {
			return nil, fmt.Errorf("key file must be 32 bytes")
		}
		masterKey = make([]byte, 32)
		copy(masterKey, opts.KeyFile)
		mode = protocol.ModeKeyFile
	}

	intermediate, err := applyForwardOps(opts.Plaintext, opts.Chain, masterKey)
	if err != nil {
		return nil, err
	}

	aesKey := deriveOpKey(masterKey, "aes-gcm", 32)
	nonce, ciphertext, tag, err := AESGCMEncrypt(intermediate, aesKey)
	if err != nil {
		return nil, err
	}

	header := &protocol.Header{
		Version: 0x03,
		Mode:    mode,
		Salt:    salt,
		Nonce:   nonce,
		Tag:     tag,
		OpChain: opts.Chain,
	}

	if opts.Split {
		datContent := append([]byte{0x03}, ciphertext...)
		if err := os.WriteFile(opts.DatPath, datContent, 0644); err != nil {
			return nil, fmt.Errorf("write dat: %w", err)
		}
		hdrBytes, err := header.EncodeSplit(opts.DatPath)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(opts.HdrPath, hdrBytes, 0644); err != nil {
			return nil, err
		}
		return &EncryptResult{}, nil
	}

	hdrBytes, err := header.EncodeSingle()
	if err != nil {
		return nil, err
	}
	single := make([]byte, len(hdrBytes)+len(ciphertext))
	copy(single, hdrBytes)
	copy(single[len(hdrBytes):], ciphertext)
	return &EncryptResult{SingleFile: single}, nil
}

func Decrypt(cipherdata []byte, password string, keyfile []byte, splitHdr string, splitDat string) ([]byte, error) {
	var header *protocol.Header
	var ciphertext []byte

	if splitHdr != "" {
		hdrRaw, err := os.ReadFile(splitHdr)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		header, err = protocol.DecodeSplit(hdrRaw)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		datRaw, err := os.ReadFile(splitDat)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		if len(datRaw) < 1 || datRaw[0] != 0x03 {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		datHash := sha256.Sum256(datRaw)
		if !bytes.Equal(datHash[:], header.SHA256Dat) {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		ciphertext = datRaw[1:]
	} else {
		h, offset, err := protocol.DecodeSingle(cipherdata)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		header = h
		ciphertext = cipherdata[offset:]
	}

	var masterKey []byte
	if header.Mode&protocol.ModePassword != 0 {
		if password == "" {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		key, err := DeriveKeyFromPassword(password, header.Salt)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		masterKey = key
	} else if header.Mode&protocol.ModeKeyFile != 0 {
		if len(keyfile) != 32 {
			return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
		}
		masterKey = make([]byte, 32)
		copy(masterKey, keyfile)
	} else {
		return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
	}

	aesKey := deriveOpKey(masterKey, "aes-gcm", 32)
	intermediate, err := AESGCMDecrypt(header.Nonce, ciphertext, header.Tag, aesKey)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
	}

	plaintext, err := applyReverseOps(intermediate, header.OpChain, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
	}
	return plaintext, nil
}
