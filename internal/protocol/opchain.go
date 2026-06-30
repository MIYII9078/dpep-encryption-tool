package protocol

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// 允许的操作码白名单
var allowedOpcodes = map[byte]bool{
	0x00: true, // 终结符
	0x08: true, // Deflate 压缩
	0x09: true, // Raw 直通
	0x0A: true, // Varint 变长整数
	0x0C: true, // 模板展开 (仅展开用，最终链不应出现)
	0x0E: true, // 密钥派生 (多因素)
	0x0F: true, // AES-256-GCM 认证加密
	0x10: true, // BaseN 基数打包
	0x11: true, // 密钥文件加密
	0x12: true, // 混沌混淆 v2
	0x13: true, // 波塞冬加密 v2
	0x14: true, // 流式分帧 (预留)
	0x15: true, // 反调试混淆 (预留)
	0x16: true, // 环境绑定 (预留)
}

// 操作码所需的参数字节数（不含操作码自身），-1 表示动态
var opcodeParamSizes = map[byte]int{
	0x00: 0, // 终结符无参数
	0x08: 1, // 压缩级别
	0x09: 0,
	0x0A: 0,
	0x0C: 1,  // 模板 ID（仅供模板系统使用，校验时拒绝）
	0x0E: 1,  // 算法 ID
	0x0F: 0,  // AES-GCM 无参数
	0x10: 1,  // 基数
	0x11: 0,  // 密钥文件无参数
	0x12: -1, // 混沌混淆：1(轮数)+1(种子长度)+种子
	0x13: 2,  // 波塞冬：1(轮数)+1(S盒选择)
	0x14: 3,  // 流式分帧：2(最大载荷)+1(标志)
	0x15: 1,  // 反调试：动作码
	0x16: -1, // 环境绑定：类型+长度+数据
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
		if op == 0x0C {
			return fmt.Errorf("template opcode 0x0C not allowed in final chain")
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
				return fmt.Errorf("Chaos seed length too short: %d", seedLen)
			}
			paramLen = 2 + seedLen
		case 0x16:
			if i+2 >= len(chain) {
				return fmt.Errorf("truncated EnvBind params")
			}
			dataLen := int(chain[i+2])
			paramLen = 2 + dataLen
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
