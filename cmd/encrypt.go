package cmd

import (
	"fmt"
	"os"

	"dpep/internal/crypto"
	"dpep/internal/i18n"
	"dpep/internal/protocol"
	"dpep/internal/template"

	"github.com/spf13/cobra"
)

var (
	encFile     string
	encOutput   string
	encKey      string
	encKeyFile  string
	encProcess  string
	encTemplate string
	encSplit    bool
	encHeader   string
	encData     string
	tmplFile    string
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: i18n.T("ENCRYPT_SHORT_DESC"),
	Long:  i18n.T("ENCRYPT_LONG_DESC"),
	RunE:  runEncrypt,
}

func init() {
	encryptCmd.Flags().StringVarP(&encFile, "file", "f", "", "Input file path")
	encryptCmd.Flags().StringVarP(&encOutput, "output", "o", "", "Output file path")
	encryptCmd.Flags().StringVarP(&encKey, "key", "k", "", "Password")
	encryptCmd.Flags().StringVarP(&encKeyFile, "keyfile", "K", "", "32-byte key file path")
	encryptCmd.Flags().StringVarP(&encProcess, "process", "p", "", "Opcode chain (hex)")
	encryptCmd.Flags().StringVarP(&encTemplate, "template", "t", "", "Template ID")
	encryptCmd.Flags().BoolVarP(&encSplit, "split", "s", false, "Split header mode")
	encryptCmd.Flags().StringVarP(&encHeader, "header", "H", "header.hdr", "Header file path")
	encryptCmd.Flags().StringVarP(&encData, "data", "D", "data.dat", "Data file path")
	encryptCmd.Flags().StringVar(&tmplFile, "template-file", "", "Custom template JSON file")
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	if encFile == "" {
		return fmt.Errorf(i18n.T("MSG_INPUT_EMPTY"))
	}
	if encKey == "" && encKeyFile == "" {
		return fmt.Errorf("password or keyfile required")
	}
	if encProcess == "" && encTemplate == "" {
		return fmt.Errorf("opcode chain or template required")
	}

	plaintext, err := os.ReadFile(encFile)
	if err != nil {
		return fmt.Errorf(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": encFile}))
	}

	if tmplFile != "" {
		if err := template.LoadCustomFile(tmplFile); err != nil {
			return fmt.Errorf("custom template load error: %w", err)
		}
	}

	var chain []byte
	if encProcess != "" {
		chain, err = protocol.ParseHexChain(encProcess)
	} else {
		chain, err = template.Load(encTemplate)
	}
	if err != nil {
		return fmt.Errorf("invalid chain: %w", err)
	}

	var keyFileData []byte
	if encKeyFile != "" {
		keyFileData, err = os.ReadFile(encKeyFile)
		if err != nil {
			return fmt.Errorf(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": encKeyFile}))
		}
		if len(keyFileData) != 32 {
			return fmt.Errorf("key file must be 32 bytes")
		}
	}

	opts := crypto.EncryptOptions{
		Plaintext: plaintext,
		Password:  encKey,
		KeyFile:   keyFileData,
		Chain:     chain,
		Split:     encSplit,
		HdrPath:   encHeader,
		DatPath:   encData,
	}
	result, err := crypto.Encrypt(opts)
	if err != nil {
		return fmt.Errorf(i18n.T("ENCRYPT_FAILED", map[string]string{"reason": err.Error()}))
	}

	if encSplit {
		fmt.Println("[Success] Split files written:", encHeader, encData)
		return nil
	}
	outPath := encOutput
	if outPath == "" {
		outPath = encFile + ".dpep"
	}
	if err := os.WriteFile(outPath, result.SingleFile, 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if verbose {
		fmt.Println(i18n.T("ENCRYPT_SUCCESS", map[string]string{"output": outPath}))
	}
	return nil
}
