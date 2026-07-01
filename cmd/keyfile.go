package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"dpep/internal/i18n"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	keyfileOutput string
)

var keyfileCmd = &cobra.Command{
	Use:   "keyfile",
	Short: "生成密钥文件（通过键盘输入收集随机熵）",
	Long:  "通过让用户随机敲击键盘收集随机数据，混合系统真随机数生成一个32字节的密钥文件。",
	RunE:  runKeyfile,
}

func init() {
	rootCmd.AddCommand(keyfileCmd)
	keyfileCmd.Flags().StringVarP(&keyfileOutput, "output", "o", "", "输出文件路径（默认自动命名到当前目录）")
}

func runKeyfile(cmd *cobra.Command, args []string) error {
	fmt.Println(i18n.T("KEYFILE_COLLECT_ENTROPY"))
	fmt.Println(i18n.T("KEYFILE_INSTRUCTIONS"))
	fmt.Println()

	// 收集用户键盘输入
	reader := bufio.NewReader(os.Stdin)
	var userEntropy string
	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		// 用户输入空行表示结束
		if input == "\r\n" || input == "\n" {
			break
		}
		userEntropy += input
	}

	if len(userEntropy) < 10 {
		fmt.Println(i18n.T("KEYFILE_ENTROPY_TOO_SHORT"))
		return fmt.Errorf("收集的随机数据过少")
	}

	// 生成系统真随机基础密钥
	baseKey := make([]byte, 32)
	if _, err := rand.Read(baseKey); err != nil {
		return fmt.Errorf("随机数生成失败: %w", err)
	}

	// 混合用户熵
	hasher := sha256.New()
	hasher.Write(baseKey)
	hasher.Write([]byte(userEntropy))
	finalKey := hasher.Sum(nil)

	// 保存文件
	if keyfileOutput == "" {
		keyfileOutput = fmt.Sprintf("key_%s.bin", hex.EncodeToString(finalKey[:4]))
	}
	if err := os.WriteFile(keyfileOutput, finalKey, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	fmt.Printf(i18n.T("KEYFILE_SUCCESS")+"\n", keyfileOutput)
	return nil
}
