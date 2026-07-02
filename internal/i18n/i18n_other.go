//go:build !windows

package i18n

func getWindowsLocale() (string, error) {
	return "", nil
}
