package crypto

import "encoding/binary"

func VarintEncode(val uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, val)
	return buf[:n]
}

func VarintDecode(data []byte) (uint64, int) {
	return binary.Uvarint(data)
}
