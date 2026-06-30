package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func AESGCMEncrypt(plaintext, key []byte) (nonce, ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	tag = sealed[len(sealed)-16:]
	ciphertext = sealed[:len(sealed)-16]
	return nonce, ciphertext, tag, nil
}

func AESGCMDecrypt(nonce, ciphertext, tag, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := append(ciphertext, tag...)
	return gcm.Open(nil, nonce, sealed, nil)
}
