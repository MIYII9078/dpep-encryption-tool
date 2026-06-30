package i18n

import (
	_ "embed"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed zh_cn.lang
var zhCN string

//go:embed en_us.lang
var enUS string

var current map[string]string

func init() {
	lang := detectLanguage()
	// 如果设置了 DPEP_DEBUG_LANG 环境变量，则打印检测到的语言（调试用）
	if os.Getenv("DPEP_DEBUG_LANG") != "" {
		println("DPEP detected language:", lang)
	}
	loadLang(lang)
}

func detectLanguage() string {
	// 1. 用户强制指定
	if l := os.Getenv("DPEP_LANG"); l != "" {
		return l
	}
	// 2. 标准环境变量 (Linux/macOS)
	if l := os.Getenv("LANG"); l != "" {
		return l
	}
	if l := os.Getenv("LC_ALL"); l != "" {
		return l
	}
	// 3. Windows 系统 API
	if runtime.GOOS == "windows" {
		locale, err := getWindowsLocale()
		if err == nil && locale != "" {
			return locale
		}
	}
	// 4. 默认英文
	return "en_US"
}

func getWindowsLocale() (string, error) {
	// 使用 syscall.NewLazyDLL 加载 kernel32.dll 并获取函数
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetUserDefaultLocaleName")

	// 缓冲区大小：LOCALE_NAME_MAX_LENGTH = 85
	buf := make([]uint16, 85)
	ret, _, err := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		if err != nil {
			return "", err
		}
		return "", syscall.EINVAL
	}
	return syscall.UTF16ToString(buf), nil
}

func loadLang(lang string) {
	normalized := strings.ToLower(lang)
	if len(normalized) >= 5 {
		normalized = normalized[:5]
	}
	switch normalized {
	case "zh_cn", "zh-cn", "zh_ha", "zh-ha":
		current = parseLangFile(zhCN)
	default:
		current = parseLangFile(enUS)
	}
}

func parseLangFile(raw string) map[string]string {
	m := make(map[string]string)
	var curKey, curVal strings.Builder
	inKey := true
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if inKey {
			eqIdx := strings.Index(line, "=")
			if eqIdx == -1 {
				continue
			}
			curKey.Reset()
			curKey.WriteString(strings.TrimSpace(line[:eqIdx]))
			rest := line[eqIdx+1:]
			if strings.TrimSpace(rest) == "" {
				curVal.Reset()
				inKey = false
			} else {
				curVal.Reset()
				curVal.WriteString(strings.TrimSpace(rest))
				m[curKey.String()] = curVal.String()
			}
		} else {
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				if curVal.Len() > 0 {
					curVal.WriteString("\n")
				}
				curVal.WriteString(strings.TrimLeft(line, " \t"))
			} else {
				m[curKey.String()] = curVal.String()
				inKey = true
				eqIdx := strings.Index(line, "=")
				if eqIdx != -1 {
					curKey.Reset()
					curKey.WriteString(strings.TrimSpace(line[:eqIdx]))
					rest := line[eqIdx+1:]
					if strings.TrimSpace(rest) == "" {
						curVal.Reset()
						inKey = false
					} else {
						curVal.Reset()
						curVal.WriteString(strings.TrimSpace(rest))
						m[curKey.String()] = curVal.String()
					}
				}
			}
		}
	}
	if !inKey && curKey.Len() > 0 {
		m[curKey.String()] = curVal.String()
	}
	return m
}

func T(key string, args ...map[string]string) string {
	val, ok := current[key]
	if !ok {
		return key
	}
	if len(args) > 0 && args[0] != nil {
		for k, v := range args[0] {
			placeholder := "{" + k + "}"
			val = strings.ReplaceAll(val, placeholder, v)
		}
	}
	if appName, ok := current["APP_NAME"]; ok {
		val = strings.ReplaceAll(val, "{app_name}", appName)
	}
	if appFullName, ok := current["APP_FULL_NAME"]; ok {
		val = strings.ReplaceAll(val, "{app_full_name}", appFullName)
	}
	if appVersion, ok := current["APP_VERSION"]; ok {
		val = strings.ReplaceAll(val, "{version}", appVersion)
	}
	return val
}
