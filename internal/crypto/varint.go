package crypto

import "encoding/binary"

// VarintEncode 用于 Base-128 编码，由 opcode 0x0A 调用（暂未实现）。
func VarintEncode(val uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, val)
	return buf[:n]
}

// VarintDecode 解码 Base-128 编码，由 opcode 0x0A 调用（暂未实现）。
func VarintDecode(data []byte) (uint64, int) {
	return binary.Uvarint(data)
}
