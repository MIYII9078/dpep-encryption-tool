package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"dpep/internal/crypto"
	"dpep/internal/i18n"
	"dpep/internal/protocol"
)

func interactiveMain() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(i18n.T("MENU_TITLE"))
	fmt.Println(i18n.T("MENU_OPTION_ENCRYPT"))
	fmt.Println(i18n.T("MENU_OPTION_DECRYPT"))
	fmt.Println(i18n.T("MENU_OPTION_EXIT"))
	fmt.Print(i18n.T("MENU_PROMPT") + " ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	switch choice {
	case "1":
		interactiveEncrypt()
	case "2":
		interactiveDecrypt()
	default:
		fmt.Println(i18n.T("MENU_EXIT_MSG"))
	}
}

func interactiveEncrypt() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print(i18n.T("ENCRYPT_PROMPT_INPUT") + " ")
	inFile, _ := reader.ReadString('\n')
	inFile = strings.TrimSpace(inFile)
	if inFile == "" {
		fmt.Println(i18n.T("MSG_INPUT_EMPTY"))
		return
	}
	if _, err := os.Stat(inFile); os.IsNotExist(err) {
		fmt.Println(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": inFile}))
		return
	}

	fmt.Print(i18n.T("ENCRYPT_PROMPT_OUTPUT") + " ")
	outFile, _ := reader.ReadString('\n')
	outFile = strings.TrimSpace(outFile)

	fmt.Print(i18n.T("ENCRYPT_PROMPT_PASSWORD") + " ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	var keyFileData []byte
	if password == "" {
		fmt.Print(i18n.T("ENCRYPT_PROMPT_KEYFILE") + " ")
		kfPath, _ := reader.ReadString('\n')
		kfPath = strings.TrimSpace(kfPath)
		if kfPath == "" {
			fmt.Println(i18n.T("MSG_INPUT_EMPTY"))
			return
		}
		data, err := os.ReadFile(kfPath)
		if err != nil {
			fmt.Println(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": kfPath}))
			return
		}
		if len(data) != 32 {
			fmt.Println("[Error] Key file must be 32 bytes")
			return
		}
		keyFileData = data
	}

	fmt.Print(i18n.T("ENCRYPT_PROMPT_CHAIN") + " ")
	chainStr, _ := reader.ReadString('\n')
	chainStr = strings.TrimSpace(chainStr)
	if chainStr == "" {
		chainStr = "08 06 0E 01 0F 00"
	}
	chain, err := protocol.ParseHexChain(chainStr)
	if err != nil {
		fmt.Println("[Error] Invalid chain:", err)
		return
	}

	fmt.Print(i18n.T("ENCRYPT_PROMPT_SPLIT") + " ")
	splitStr, _ := reader.ReadString('\n')
	splitStr = strings.TrimSpace(splitStr)
	split := strings.ToLower(splitStr) == "y"

	var hdrPath, datPath string
	if split {
		fmt.Print(i18n.T("ENCRYPT_PROMPT_HEADER") + " ")
		hdrPath, _ = reader.ReadString('\n')
		hdrPath = strings.TrimSpace(hdrPath)
		if hdrPath == "" {
			hdrPath = "header.hdr"
		}
		fmt.Print(i18n.T("ENCRYPT_PROMPT_DATA") + " ")
		datPath, _ = reader.ReadString('\n')
		datPath = strings.TrimSpace(datPath)
		if datPath == "" {
			datPath = "data.dat"
		}
	}

	plaintext, err := os.ReadFile(inFile)
	if err != nil {
		fmt.Println(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": inFile}))
		return
	}

	opts := crypto.EncryptOptions{
		Plaintext: plaintext,
		Password:  password,
		KeyFile:   keyFileData,
		Chain:     chain,
		Split:     split,
		HdrPath:   hdrPath,
		DatPath:   datPath,
	}
	result, err := crypto.Encrypt(opts)
	if err != nil {
		fmt.Println(i18n.T("ENCRYPT_FAILED", map[string]string{"reason": err.Error()}))
		return
	}

	if split {
		fmt.Println("[Success] Split files written:", hdrPath, datPath)
	} else {
		if outFile == "" {
			outFile = inFile + ".dpep"
		}
		err = os.WriteFile(outFile, result.SingleFile, 0644)
		if err != nil {
			fmt.Println("[Error] Write failed:", err)
			return
		}
		fmt.Println(i18n.T("ENCRYPT_SUCCESS", map[string]string{"output": outFile}))
	}
}

func interactiveDecrypt() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print(i18n.T("DECRYPT_PROMPT_INPUT") + " ")
	inFile, _ := reader.ReadString('\n')
	inFile = strings.TrimSpace(inFile)

	fmt.Print("Split mode? (y/n): ")
	splitStr, _ := reader.ReadString('\n')
	split := strings.TrimSpace(strings.ToLower(splitStr)) == "y"

	var hdrPath, datPath string
	if split {
		fmt.Print(i18n.T("DECRYPT_PROMPT_HEADER") + " ")
		hdrPath, _ = reader.ReadString('\n')
		hdrPath = strings.TrimSpace(hdrPath)
		fmt.Print(i18n.T("DECRYPT_PROMPT_DATA") + " ")
		datPath, _ = reader.ReadString('\n')
		datPath = strings.TrimSpace(datPath)
	}

	fmt.Print(i18n.T("DECRYPT_PROMPT_PASSWORD") + " ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	var keyFileData []byte
	if password == "" {
		fmt.Print(i18n.T("ENCRYPT_PROMPT_KEYFILE") + " ")
		kfPath, _ := reader.ReadString('\n')
		kfPath = strings.TrimSpace(kfPath)
		if kfPath != "" {
			data, err := os.ReadFile(kfPath)
			if err != nil {
				fmt.Println(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": kfPath}))
				return
			}
			if len(data) != 32 {
				fmt.Println("[Error] Key file must be 32 bytes")
				return
			}
			keyFileData = data
		}
	}

	var plaintext []byte
	var err error
	if split {
		plaintext, err = crypto.Decrypt(nil, password, keyFileData, hdrPath, datPath)
	} else {
		cipherData, readErr := os.ReadFile(inFile)
		if readErr != nil {
			fmt.Println(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": inFile}))
			return
		}
		plaintext, err = crypto.Decrypt(cipherData, password, keyFileData, "", "")
	}
	if err != nil {
		fmt.Println(i18n.T("DECRYPT_FAILED", map[string]string{"reason": i18n.T("DECRYPT_BAD_TAG")}))
		return
	}

	fmt.Print(i18n.T("DECRYPT_PROMPT_OUTPUT") + " ")
	outFile, _ := reader.ReadString('\n')
	outFile = strings.TrimSpace(outFile)
	if outFile == "" {
		if !split && strings.HasSuffix(inFile, ".dpep") {
			outFile = strings.TrimSuffix(inFile, ".dpep")
		} else {
			outFile = inFile + ".decrypted"
		}
	}
	err = os.WriteFile(outFile, plaintext, 0644)
	if err != nil {
		fmt.Println("[Error] Write failed:", err)
		return
	}
	fmt.Println(i18n.T("DECRYPT_SUCCESS", map[string]string{"output": outFile}))
}
