package cmd

import (
	"fmt"
	"os"
	"strings"

	"dpep/internal/crypto"
	"dpep/internal/i18n"

	"github.com/spf13/cobra"
)

var (
	decFile    string
	decOutput  string
	decKey     string
	decKeyFile string
	decSplit   bool
	decHeader  string
	decData    string
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: i18n.T("DECRYPT_SHORT_DESC"),
	Long:  i18n.T("DECRYPT_LONG_DESC"),
	RunE:  runDecrypt,
}

func init() {
	decryptCmd.Flags().StringVarP(&decFile, "file", "f", "", "Input file path")
	decryptCmd.Flags().StringVarP(&decOutput, "output", "o", "", "Output file path")
	decryptCmd.Flags().StringVarP(&decKey, "key", "k", "", "Password")
	decryptCmd.Flags().StringVarP(&decKeyFile, "keyfile", "K", "", "32-byte key file path")
	decryptCmd.Flags().BoolVarP(&decSplit, "split", "s", false, "Split mode")
	decryptCmd.Flags().StringVarP(&decHeader, "header", "H", "header.hdr", "Header file path")
	decryptCmd.Flags().StringVarP(&decData, "data", "D", "data.dat", "Data file path")
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	if decSplit {
		if decHeader == "" || decData == "" {
			return fmt.Errorf("split mode requires -H and -D")
		}
	} else {
		if decFile == "" {
			return fmt.Errorf("input file required (-f)")
		}
	}

	var keyFileData []byte
	if decKeyFile != "" {
		var err error
		keyFileData, err = os.ReadFile(decKeyFile)
		if err != nil {
			return fmt.Errorf(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": decKeyFile}))
		}
		if len(keyFileData) != 32 {
			return fmt.Errorf("key file must be 32 bytes")
		}
	}

	var (
		plaintext []byte
		err       error
	)
	if decSplit {
		plaintext, err = crypto.Decrypt(nil, decKey, keyFileData, decHeader, decData)
	} else {
		cipherData, readErr := os.ReadFile(decFile)
		if readErr != nil {
			return fmt.Errorf(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": decFile}))
		}
		plaintext, err = crypto.Decrypt(cipherData, decKey, keyFileData, "", "")
	}
	if err != nil {
		// Unified error to prevent oracle
		return fmt.Errorf(i18n.T("DECRYPT_FAILED", map[string]string{"reason": i18n.T("DECRYPT_BAD_TAG")}))
	}

	outPath := decOutput
	if outPath == "" {
		if !decSplit && strings.HasSuffix(decFile, ".dpep") {
			outPath = strings.TrimSuffix(decFile, ".dpep")
		} else {
			outPath = decFile + ".decrypted"
		}
	}
	if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if verbose {
		fmt.Println(i18n.T("DECRYPT_SUCCESS", map[string]string{"output": outPath}))
	}
	return nil
}
