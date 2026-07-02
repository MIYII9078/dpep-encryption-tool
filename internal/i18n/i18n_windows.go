//go:build windows

package i18n

import (
	"syscall"
	"unsafe"
)

func getWindowsLocale() (string, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetUserDefaultLocaleName")
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
