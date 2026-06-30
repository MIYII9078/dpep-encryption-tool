package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"dpep/internal/console"
	"dpep/internal/crypto"
	"dpep/internal/i18n"
	"dpep/internal/protocol"
)

func interactiveMain() {
	for {
		console.Clear()
		// 标题
		console.PrintlnColored(console.Bold+console.Cyan, i18n.T("APP_FULL_NAME"))
		fmt.Println(strings.Repeat("─", 40))
		// 菜单选项
		console.PrintlnColored(console.Yellow, "1. "+i18n.T("MENU_OPTION_ENCRYPT"))
		console.PrintlnColored(console.Yellow, "2. "+i18n.T("MENU_OPTION_DECRYPT"))
		console.PrintlnColored(console.Yellow, "3. "+i18n.T("MENU_OPTION_EXIT"))
		fmt.Print(i18n.T("MENU_PROMPT") + " ")
		reader := bufio.NewReader(os.Stdin)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		switch choice {
		case "1":
			interactiveEncrypt()
		case "2":
			interactiveDecrypt()
		default:
			console.Clear()
			console.PrintlnColored(console.Green, i18n.T("MENU_EXIT_MSG"))
			return
		}
	}
}

func interactiveEncrypt() {
	console.Clear()
	reader := bufio.NewReader(os.Stdin)
	totalSteps := 5
	step := 0

	// 步骤1：选择输入源
	step++
	console.ShowStep(step, totalSteps, i18n.T("ENCRYPT_SOURCE_CHOICE"))
	fmt.Println("  1. " + i18n.T("ENCRYPT_SOURCE_FILE"))
	fmt.Println("  2. " + i18n.T("ENCRYPT_SOURCE_TEXT"))
	fmt.Print("  > ")
	srcChoice, _ := reader.ReadString('\n')
	srcChoice = strings.TrimSpace(srcChoice)

	var plaintext []byte
	if srcChoice == "2" {
		// 直接输入文本
		console.PrintlnColored(console.Cyan, "  "+i18n.T("ENCRYPT_TEXT_INPUT"))
		fmt.Println("  " + i18n.T("ENCRYPT_TEXT_INPUT_END"))
		var lines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			lines = append(lines, line)
		}
		if len(lines) == 0 {
			console.Fail(i18n.T("MSG_INPUT_EMPTY"))
			console.PressAnyKey()
			return
		}
		plaintext = []byte(strings.Join(lines, "\n"))
	} else {
		// 从文件读取
		fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_INPUT") + " ")
		inFile, _ := reader.ReadString('\n')
		inFile = strings.TrimSpace(inFile)
		if inFile == "" {
			console.Fail(i18n.T("MSG_INPUT_EMPTY"))
			console.PressAnyKey()
			return
		}
		if _, err := os.Stat(inFile); os.IsNotExist(err) {
			console.Fail(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": inFile}))
			console.PressAnyKey()
			return
		}
		data, err := os.ReadFile(inFile)
		if err != nil {
			console.Fail(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": inFile}))
			console.PressAnyKey()
			return
		}
		plaintext = data
	}
	console.OK(i18n.T("ENCRYPT_SOURCE_OK"))

	// 步骤2：输出文件
	step++
	console.ShowStep(step, totalSteps, i18n.T("ENCRYPT_OUTPUT_FILE"))
	fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_OUTPUT") + " ")
	outFile, _ := reader.ReadString('\n')
	outFile = strings.TrimSpace(outFile)
	if outFile == "" {
		outFile = "encrypted.dpep"
	}

	// 步骤3：密码/密钥文件
	step++
	console.ShowStep(step, totalSteps, i18n.T("ENCRYPT_KEY_METHOD"))
	fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_PASSWORD") + " ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	var keyFileData []byte
	if password == "" {
		fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_KEYFILE") + " ")
		kfPath, _ := reader.ReadString('\n')
		kfPath = strings.TrimSpace(kfPath)
		if kfPath == "" {
			console.Fail(i18n.T("MSG_INPUT_EMPTY"))
			console.PressAnyKey()
			return
		}
		data, err := os.ReadFile(kfPath)
		if err != nil {
			console.Fail(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": kfPath}))
			console.PressAnyKey()
			return
		}
		if len(data) != 32 {
			console.Fail("[Error] Key file must be 32 bytes")
			console.PressAnyKey()
			return
		}
		keyFileData = data
	}
	console.OK(i18n.T("ENCRYPT_KEY_OK"))

	// 步骤4：操作链
	step++
	console.ShowStep(step, totalSteps, i18n.T("ENCRYPT_CHAIN_CONFIG"))
	fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_CHAIN") + " ")
	chainStr, _ := reader.ReadString('\n')
	chainStr = strings.TrimSpace(chainStr)
	if chainStr == "" {
		chainStr = "08 06 0E 01 0F 00"
	}
	chain, err := protocol.ParseHexChain(chainStr)
	if err != nil {
		console.Fail(err.Error())
		console.PressAnyKey()
		return
	}
	console.OK(i18n.T("ENCRYPT_CHAIN_OK"))

	// 步骤5：分离模式
	step++
	console.ShowStep(step, totalSteps, i18n.T("ENCRYPT_SPLIT_MODE"))
	fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_SPLIT") + " ")
	splitStr, _ := reader.ReadString('\n')
	splitStr = strings.TrimSpace(splitStr)
	split := strings.ToLower(splitStr) == "y"

	var hdrPath, datPath string
	if split {
		fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_HEADER") + " ")
		hdrPath, _ = reader.ReadString('\n')
		hdrPath = strings.TrimSpace(hdrPath)
		if hdrPath == "" {
			hdrPath = "header.hdr"
		}
		fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_DATA") + " ")
		datPath, _ = reader.ReadString('\n')
		datPath = strings.TrimSpace(datPath)
		if datPath == "" {
			datPath = "data.dat"
		}
	}

	// 执行加密
	console.Clear()
	fmt.Println("正在加密，请稍候...")
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
		console.Fail(i18n.T("ENCRYPT_FAILED", map[string]string{"reason": err.Error()}))
		console.PressAnyKey()
		return
	}

	// 显示结果
	console.Clear()
	if split {
		_ = result // 分离模式下 result 为空结构体，文件已在内部写入
		console.OK(i18n.T("ENCRYPT_SUCCESS_SPLIT", map[string]string{"header": hdrPath, "data": datPath}))
	} else {
		err = os.WriteFile(outFile, result.SingleFile, 0644)
		if err != nil {
			console.Fail("[Error] Write failed: " + err.Error())
			console.PressAnyKey()
			return
		}
		console.OK(i18n.T("ENCRYPT_SUCCESS", map[string]string{"output": outFile}))
	}
	console.PressAnyKey()
}

func interactiveDecrypt() {
	console.Clear()
	reader := bufio.NewReader(os.Stdin)
	totalSteps := 4
	step := 0

	// 步骤1：是否分离模式
	step++
	console.ShowStep(step, totalSteps, i18n.T("DECRYPT_SPLIT_QUERY"))
	fmt.Print("  " + i18n.T("DECRYPT_SPLIT_PROMPT") + " ")
	splitStr, _ := reader.ReadString('\n')
	split := strings.TrimSpace(strings.ToLower(splitStr)) == "y"

	var inFile, hdrPath, datPath string
	var cipherdata []byte
	if split {
		fmt.Print("  " + i18n.T("DECRYPT_PROMPT_HEADER") + " ")
		hdrPath, _ = reader.ReadString('\n')
		hdrPath = strings.TrimSpace(hdrPath)
		fmt.Print("  " + i18n.T("DECRYPT_PROMPT_DATA") + " ")
		datPath, _ = reader.ReadString('\n')
		datPath = strings.TrimSpace(datPath)
	} else {
		fmt.Print("  " + i18n.T("DECRYPT_PROMPT_INPUT") + " ")
		inFile, _ = reader.ReadString('\n')
		inFile = strings.TrimSpace(inFile)
		if inFile == "" {
			console.Fail(i18n.T("MSG_INPUT_EMPTY"))
			console.PressAnyKey()
			return
		}
		data, err := os.ReadFile(inFile)
		if err != nil {
			console.Fail(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": inFile}))
			console.PressAnyKey()
			return
		}
		cipherdata = data
	}
	console.OK(i18n.T("DECRYPT_INPUT_OK"))

	// 步骤2：密码/密钥文件
	step++
	console.ShowStep(step, totalSteps, i18n.T("ENCRYPT_KEY_METHOD"))
	fmt.Print("  " + i18n.T("DECRYPT_PROMPT_PASSWORD") + " ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	var keyFileData []byte
	if password == "" {
		fmt.Print("  " + i18n.T("ENCRYPT_PROMPT_KEYFILE") + " ")
		kfPath, _ := reader.ReadString('\n')
		kfPath = strings.TrimSpace(kfPath)
		if kfPath != "" {
			data, err := os.ReadFile(kfPath)
			if err != nil {
				console.Fail(i18n.T("MSG_FILE_NOT_FOUND", map[string]string{"path": kfPath}))
				console.PressAnyKey()
				return
			}
			if len(data) != 32 {
				console.Fail("[Error] Key file must be 32 bytes")
				console.PressAnyKey()
				return
			}
			keyFileData = data
		}
	}
	console.OK(i18n.T("ENCRYPT_KEY_OK"))

	// 步骤3：输出方式
	step++
	console.ShowStep(step, totalSteps, i18n.T("DECRYPT_OUTPUT_CHOICE"))
	fmt.Println("  1. " + i18n.T("DECRYPT_OUTPUT_FILE"))
	fmt.Println("  2. " + i18n.T("DECRYPT_OUTPUT_SCREEN"))
	fmt.Print("  > ")
	outChoice, _ := reader.ReadString('\n')
	outChoice = strings.TrimSpace(outChoice)

	// 步骤4：输出路径（如果保存到文件）
	var outFile string
	if outChoice != "2" {
		fmt.Print("  " + i18n.T("DECRYPT_PROMPT_OUTPUT") + " ")
		outFile, _ = reader.ReadString('\n')
		outFile = strings.TrimSpace(outFile)
		if outFile == "" {
			outFile = "decrypted.txt"
		}
	}

	// 执行解密
	console.Clear()
	fmt.Println("正在解密，请稍候...")
	var plaintext []byte
	var err error
	if split {
		plaintext, err = crypto.Decrypt(nil, password, keyFileData, hdrPath, datPath)
	} else {
		plaintext, err = crypto.Decrypt(cipherdata, password, keyFileData, "", "")
	}
	if err != nil {
		console.Fail(i18n.T("DECRYPT_FAILED", map[string]string{"reason": i18n.T("DECRYPT_BAD_TAG")}))
		console.PressAnyKey()
		return
	}

	// 显示结果
	console.Clear()
	if outChoice == "2" {
		console.OK(i18n.T("DECRYPT_SCREEN_PREVIEW"))
		fmt.Println(strings.Repeat("─", 40))
		fmt.Println(string(plaintext))
		fmt.Println(strings.Repeat("─", 40))
	} else {
		err = os.WriteFile(outFile, plaintext, 0644)
		if err != nil {
			console.Fail("[Error] Write failed: " + err.Error())
			console.PressAnyKey()
			return
		}
		console.OK(i18n.T("DECRYPT_SUCCESS", map[string]string{"output": outFile}))
	}
	console.PressAnyKey()
}
