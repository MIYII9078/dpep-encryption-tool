package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const PBKDF2Iterations = 600_000

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

func DeriveKeyFromPassword(password string, salt []byte) ([]byte, error) {
	if len(salt) != 32 {
		return nil, fmt.Errorf("salt must be 32 bytes")
	}
	return pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, 32, sha256.New), nil
}

func DeriveKeyFromKeyFile(keyfile []byte) ([]byte, error) {
	if len(keyfile) != 32 {
		return nil, fmt.Errorf("key file must be 32 bytes")
	}
	key := make([]byte, 32)
	copy(key, keyfile)
	return key, nil
}
