package crypto

import (
	"fmt"
	"math/big"
)

func BaseEncode(data []byte, base int) string {
	if base != 10 && base != 36 && base != 62 {
		return ""
	}
	bigInt := new(big.Int).SetBytes(data)
	return bigInt.Text(base)
}

func BaseDecode(encoded string, base int) ([]byte, error) {
	bigInt, ok := new(big.Int).SetString(encoded, base)
	if !ok {
		return nil, fmt.Errorf("invalid base-%d string", base)
	}
	return bigInt.Bytes(), nil
}
