package console

import "fmt"

// ANSI 控制码
const (
	Reset       = "\033[0m"
	Red         = "\033[31m"
	Green       = "\033[32m"
	Yellow      = "\033[33m"
	Cyan        = "\033[36m"
	White       = "\033[37m"
	Bold        = "\033[1m"
	ClearScreen = "\033[H\033[2J"
)

// PrintColored 输出彩色文本（不换行）。
func PrintColored(color string, format string, args ...interface{}) {
	fmt.Print(color)
	fmt.Printf(format, args...)
	fmt.Print(Reset)
}

// PrintlnColored 输出彩色文本并换行。
func PrintlnColored(color string, format string, args ...interface{}) {
	fmt.Print(color)
	fmt.Printf(format, args...)
	fmt.Println(Reset)
}

// Clear 清空终端屏幕。
func Clear() {
	fmt.Print(ClearScreen)
}

// ShowStep 显示当前步骤进度，格式为 [current/total] description。
func ShowStep(current, total int, description string) {
	PrintColored(Cyan, "[%d/%d] ", current, total)
	fmt.Println(description)
}

// OK 显示绿色的成功标记和消息。
func OK(message string) {
	PrintlnColored(Green, "  [  OK  ] %s", message)
}

// Fail 显示红色的失败标记和消息。
func Fail(message string) {
	PrintlnColored(Red, "  [ FAIL ] %s", message)
}

// PressAnyKey 提示用户按任意键返回主菜单，并等待输入。
func PressAnyKey() {
	PrintColored(White, "按任意键返回主菜单...")
	var input string
	_, _ = fmt.Scanln(&input) // 忽略可能的输入错误
}
