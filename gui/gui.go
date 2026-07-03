package gui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed" // 新增
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"dpep/internal/crypto"
	"dpep/internal/protocol"
)

// 嵌入 HTML 文件（与 gui.go 同目录）
//
//go:embed gui.html
var htmlTemplate string

const port = "18080"

var tempDir string

// Start 启动图形界面（HTTP 服务 + 浏览器）
func Start() {
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	tempDir = filepath.Join(execDir, "temp")
	os.MkdirAll(tempDir, 0755)

	http.HandleFunc("/api/upload", handleUpload)
	http.HandleFunc("/api/generate-keyfile", handleGenerateKeyFile)
	http.HandleFunc("/api/encrypt", handleEncrypt)
	http.HandleFunc("/api/decrypt", handleDecrypt)
	http.HandleFunc("/", serveGUI)

	server := &http.Server{Addr: ":" + port}
	go func() {
		fmt.Printf("GUI 服务启动在 http://localhost:%s\n", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println("服务器启动失败:", err)
			os.Exit(1)
		}
	}()

	openBrowser("http://localhost:" + port)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	fmt.Println("正在关闭 GUI 服务...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func serveGUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlTemplate))
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}
	exec.Command(cmd, args...).Start()
}

// ---------- 上传 ----------
func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeJSON(w, map[string]string{"error": "文件过大"})
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, map[string]string{"error": "未找到文件"})
		return
	}
	defer file.Close()

	savePath := filepath.Join(tempDir, header.Filename)
	out, err := os.Create(savePath)
	if err != nil {
		writeJSON(w, map[string]string{"error": "创建文件失败"})
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		writeJSON(w, map[string]string{"error": "写入文件失败"})
		return
	}
	writeJSON(w, map[string]string{"path": savePath})
}

// ---------- 生成密钥文件（混合用户熵） ----------
func handleGenerateKeyFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return
	}

	baseKey := make([]byte, 32)
	if _, err := rand.Read(baseKey); err != nil {
		writeJSON(w, map[string]string{"error": "随机数生成失败"})
		return
	}

	var request struct {
		Entropy string `json:"entropy"`
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) > 0 {
		json.Unmarshal(body, &request)
	}

	finalKey := baseKey
	if request.Entropy != "" {
		hasher := sha256.New()
		hasher.Write(baseKey)
		hasher.Write([]byte(request.Entropy))
		finalKey = hasher.Sum(nil)
	}

	filename := fmt.Sprintf("key_%s.bin", hex.EncodeToString(finalKey[:4]))
	savePath := filepath.Join(tempDir, filename)
	if err := os.WriteFile(savePath, finalKey, 0644); err != nil {
		writeJSON(w, map[string]string{"error": "写入密钥文件失败"})
		return
	}

	writeJSON(w, map[string]string{"path": savePath})
}

// ---------- API 通用 ----------
type encryptRequest struct {
	InputPath   string `json:"input"`
	OutputPath  string `json:"output"`
	Password    string `json:"password"`
	KeyFilePath string `json:"keyfile"`
	Chain       string `json:"chain"`
	Split       bool   `json:"split"`
	HeaderPath  string `json:"header"`
	DataPath    string `json:"data"`
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req encryptRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, map[string]string{"error": "请求格式错误"})
		return
	}

	plaintext, err := os.ReadFile(req.InputPath)
	if err != nil {
		writeJSON(w, map[string]string{"error": "无法读取输入文件"})
		return
	}

	var keyFile []byte
	if req.KeyFilePath != "" {
		keyFile, err = os.ReadFile(req.KeyFilePath)
		if err != nil || len(keyFile) != 32 {
			writeJSON(w, map[string]string{"error": "密钥文件无效（需32字节）"})
			return
		}
	}

	chain, err := protocol.ParseHexChain(req.Chain)
	if err != nil {
		writeJSON(w, map[string]string{"error": "操作链无效: " + err.Error()})
		return
	}

	opts := crypto.EncryptOptions{
		Plaintext: plaintext,
		Password:  req.Password,
		KeyFile:   keyFile,
		Chain:     chain,
		Split:     req.Split,
		HdrPath:   req.HeaderPath,
		DatPath:   req.DataPath,
	}

	result, err := crypto.Encrypt(opts)
	if err != nil {
		writeJSON(w, map[string]string{"error": "加密失败: " + err.Error()})
		return
	}

	if req.Split {
		writeJSON(w, map[string]string{"message": "分离模式加密完成！"})
		return
	}

	if err := os.WriteFile(req.OutputPath, result.SingleFile, 0644); err != nil {
		writeJSON(w, map[string]string{"error": "写入输出文件失败"})
		return
	}
	writeJSON(w, map[string]string{"message": "加密成功！"})
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req encryptRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, map[string]string{"error": "请求格式错误"})
		return
	}

	var cipherData []byte
	var err error
	if !req.Split {
		cipherData, err = os.ReadFile(req.InputPath)
		if err != nil {
			writeJSON(w, map[string]string{"error": "无法读取输入文件"})
			return
		}
	}

	var keyFile []byte
	if req.KeyFilePath != "" {
		keyFile, err = os.ReadFile(req.KeyFilePath)
		if err != nil || len(keyFile) != 32 {
			writeJSON(w, map[string]string{"error": "密钥文件无效"})
			return
		}
	}

	var plaintext []byte
	if req.Split {
		plaintext, err = crypto.Decrypt(nil, req.Password, keyFile, req.HeaderPath, req.DataPath)
	} else {
		plaintext, err = crypto.Decrypt(cipherData, req.Password, keyFile, "", "")
	}
	if err != nil {
		writeJSON(w, map[string]string{"error": "解密失败"})
		return
	}

	if err := os.WriteFile(req.OutputPath, plaintext, 0644); err != nil {
		writeJSON(w, map[string]string{"error": "写入输出文件失败"})
		return
	}
	writeJSON(w, map[string]string{"message": "解密成功！"})
}
