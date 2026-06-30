package cmd

import (
	"fmt"
	"os"

	"dpep/internal/i18n"

	"github.com/spf13/cobra"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:   i18n.T("ROOT_USAGE"),
	Short: i18n.T("ROOT_SHORT_DESC"),
	Long:  i18n.T("ROOT_LONG_DESC"),
	Run: func(cmd *cobra.Command, args []string) {
		interactiveMain()
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, i18n.T("MSG_VERBOSE_HELP"))
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(templatesCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err) // 忽略两个返回值
		os.Exit(1)
	}
}
