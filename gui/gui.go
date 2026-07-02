package gui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"strings"
	"time"

	"dpep/internal/crypto"
	"dpep/internal/protocol"
)

const port = "18080"

var tempDir string

const htmlTemplate = `<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>DPEP 加密工具</title>
    <style>
        :root {
            --bg: #1e1e2e; --surface: #313244; --primary: #89b4fa;
            --text: #cdd6f4; --subtext: #a6adc8; --success: #a6e3a1;
            --error: #f38ba8; --border: #45475a; --radius: 8px;
        }
        body { margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); display:flex; }
        .sidebar { width:200px; background:var(--surface); padding:20px 0; border-right:1px solid var(--border); }
        .sidebar button { display:block; width:100%; padding:12px 20px; background:none; border:none; color:var(--subtext); font-size:16px; text-align:left; cursor:pointer; transition:0.2s; }
        .sidebar button.active, .sidebar button:hover { background:var(--primary); color:var(--bg); }
        .content { flex:1; padding:30px; overflow-y:auto; }
        .tab { display:none; }
        .tab.active { display:block; }
        h2 { margin-top:0; color:var(--primary); }
        .form-group { margin-bottom:16px; }
        label { display:block; margin-bottom:4px; font-weight:600; color:var(--subtext); }
        input[type="text"], input[type="password"], select { width:100%; padding:8px; border:1px solid var(--border); border-radius:var(--radius); background:var(--surface); color:var(--text); box-sizing:border-box; }
        button { background:var(--primary); color:var(--bg); border:none; padding:8px 16px; border-radius:var(--radius); cursor:pointer; font-weight:bold; transition:0.2s; }
        button:hover { opacity:0.9; }
        .file-row { display:flex; gap:8px; align-items:center; }
        .file-row input[type="text"] { flex:1; }
        .file-row input[type="file"] { display:none; }
        .chain-builder { background:var(--surface); padding:16px; border-radius:var(--radius); margin-bottom:16px; }
        .chain-builder select { width:auto; margin-right:10px; margin-bottom:8px; }
        .result { margin-top:16px; padding:12px; border-radius:var(--radius); white-space:pre-wrap; }
        .result.success { background:#1e3a2f; border:1px solid var(--success); color:var(--success); }
        .result.error { background:#3a1e2f; border:1px solid var(--error); color:var(--error); }
        .progress-bar { height:6px; background:var(--border); border-radius:3px; margin:8px 0; overflow:hidden; }
        .progress-fill { height:100%; width:0%; transition:width 0.2s ease; }
    </style>
</head>
<body>
<div class="sidebar">
    <button class="active" onclick="switchTab('encrypt')">🔒 加密</button>
    <button onclick="switchTab('decrypt')">🔓 解密</button>
</div>
<div class="content">
    <!-- 加密选项卡 -->
    <div id="encrypt-tab" class="tab active">
        <h2>文件加密</h2>
        <div class="form-group">
            <label>输入文件</label>
            <div class="file-row">
                <input id="enc-input" type="text" placeholder="上传或输入路径" readonly>
                <input id="enc-file" type="file" onchange="uploadFile('enc')">
                <button onclick="document.getElementById('enc-file').click()">上传文件</button>
            </div>
        </div>
        <div class="form-group"><label>输出文件</label><input id="enc-output" type="text" placeholder="留空自动生成"></div>
        <div class="form-group"><label>密码</label><input id="enc-password" type="password" placeholder="推荐使用密码"></div>
        <div class="form-group">
            <label>或使用密钥文件</label>
            <div class="file-row">
                <input id="enc-keyfile" type="text" placeholder="点击生成密钥" readonly>
                <button onclick="openEntropyPanel()">生成密钥文件</button>
            </div>
        </div>

        <div class="chain-builder">
            <h3>操作链配置</h3>
            <div class="form-group"><label>密钥方式</label><select id="chain-key" disabled><option value="0E 01">密码 PBKDF2</option><option value="11">密钥文件</option></select></div>
            <div class="form-group"><label>压缩</label><select id="chain-compress"><option value="">不压缩</option><option value="08 06">Deflate 6</option><option value="08 09">Deflate 9</option></select></div>
            <div class="form-group"><label>ScrambleXOR</label><select id="chain-chaos"><option value="">不添加</option><option value="12 03 20">3轮</option><option value="12 05 20">5轮</option></select></div>
            <div class="form-group"><label>AESCipher</label><select id="chain-poseidon"><option value="">不添加</option><option value="13 0A 00">10轮</option></select></div>
            <div class="form-group"><label>数字编码</label><select id="chain-encode"><option value="">无</option><option value="10 0A">Base10</option><option value="10 24">Base36</option><option value="10 3E">Base62</option></select></div>
            <div class="form-group"><label>分离模式</label><input type="checkbox" id="enc-split"><span>生成 .hdr + .dat</span></div>
            <button onclick="buildChain()">生成链</button> <span id="chain-preview"></span>
        </div>

        <button id="enc-start" onclick="startEncrypt()">开始加密</button>
        <div id="enc-result" class="result" style="display:none;"></div>
    </div>

    <!-- 解密选项卡 -->
    <div id="decrypt-tab" class="tab">
        <h2>文件解密</h2>
        <div class="form-group">
            <label>密文文件</label>
            <div class="file-row">
                <input id="dec-input" type="text" placeholder="上传或输入路径" readonly>
                <input id="dec-file" type="file" onchange="uploadFile('dec')">
                <button onclick="document.getElementById('dec-file').click()">上传文件</button>
            </div>
        </div>
        <div class="form-group"><label>输出文件</label><input id="dec-output" type="text" placeholder="留空自动生成"></div>
        <div class="form-group"><label>密码</label><input id="dec-password" type="password" placeholder="密码（密钥模式留空）"></div>
        <div class="form-group">
            <label>密钥文件</label>
            <div class="file-row">
                <input id="dec-keyfile" type="text" placeholder="上传或留空" readonly>
                <input id="dec-keyfile-file" type="file" onchange="uploadKeyFile('dec')">
                <button onclick="document.getElementById('dec-keyfile-file').click()">上传密钥</button>
            </div>
        </div>
        <div class="form-group"><label>分离模式</label><input type="checkbox" id="dec-split"><span>使用 .hdr + .dat</span></div>
        <button id="dec-start" onclick="startDecrypt()">开始解密</button>
        <div id="dec-result" class="result" style="display:none;"></div>
    </div>

    <!-- 熵收集模态框 -->
    <div id="entropy-panel" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.7); z-index:1000; justify-content:center; align-items:center;">
        <div style="background:var(--surface); padding:24px; border-radius:var(--radius); max-width:500px; width:90%;">
            <h3 style="color:var(--primary);">生成随机密钥</h3>
            <p>在方块图上移动鼠标并敲击键盘，进度满后生成。</p>
            <canvas id="entropy-canvas" width="400" height="150" style="border:2px dashed var(--border); cursor:crosshair; width:100%; border-radius:var(--radius);"></canvas>
            <div class="progress-bar"><div id="entropy-progress" class="progress-fill"></div></div>
            <input type="text" id="entropy-keyboard" placeholder="随意敲击键盘..." onkeydown="collectKeyboardEntropy()" autocomplete="off" style="width:100%; margin-top:8px;">
            <div style="margin-top:16px; display:flex; gap:8px; justify-content:flex-end;">
                <button onclick="closeEntropyPanel()">取消</button>
                <button id="generate-key-btn" disabled onclick="generateKeyWithEntropy()">生成密钥</button>
            </div>
        </div>
    </div>
</div>

<script>
    let currentChain = "0E 01 08 06 0F 00";
    let entropyData = "";
    const entropyThreshold = 200;
    let collectActive = false;
    let lastMouseTime = 0;

    function switchTab(tab) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.sidebar button').forEach(b => b.classList.remove('active'));
        document.getElementById(tab + '-tab').classList.add('active');
        event.target.classList.add('active');
    }
    function autoSelectKeyMode(mode) {
        const keyfile = document.getElementById(mode + '-keyfile').value.trim();
        document.getElementById('chain-key').value = keyfile ? '11' : '0E 01';
        buildChain();
    }
    function buildChain() {
        const parts = [];
        parts.push(document.getElementById('chain-key').value);
        const comp = document.getElementById('chain-compress').value;
        if (comp) parts.push(comp);
        const chaos = document.getElementById('chain-chaos').value;
        if (chaos) {
            const [a,b] = chaos.split(' ');
            const seed = Array.from({length:32}, () => Math.floor(Math.random()*256).toString(16).padStart(2,'0')).join(' ');
            parts.push(a, b, '20', seed);
        }
        const pos = document.getElementById('chain-poseidon').value;
        if (pos) parts.push(pos);
        const enc = document.getElementById('chain-encode').value;
        if (enc) parts.push(enc);
        parts.push('0F', '00');
        currentChain = parts.join(' ');
        document.getElementById('chain-preview').textContent = '链: ' + currentChain;
    }
    function showResult(mode, msg, isError) {
        const el = document.getElementById(mode + '-result');
        el.style.display = 'block';
        el.textContent = msg;
        el.className = 'result ' + (isError ? 'error' : 'success');
    }
    async function uploadFile(mode) {
        const file = document.getElementById(mode + '-file').files[0];
        if (!file) return;
        const fd = new FormData(); fd.append('file', file);
        try {
            const resp = await fetch('/api/upload', {method:'POST', body:fd});
            const data = await resp.json();
            if (data.path) {
                document.getElementById(mode + '-input').value = data.path;
                showResult(mode, '已上传: ' + file.name, false);
            } else showResult(mode, '上传失败', true);
        } catch(e) { showResult(mode, '异常', true); }
    }
    async function uploadKeyFile(mode) {
        const file = document.getElementById(mode + '-keyfile-file').files[0];
        if (!file) return;
        const fd = new FormData(); fd.append('file', file);
        try {
            const resp = await fetch('/api/upload', {method:'POST', body:fd});
            const data = await resp.json();
            if (data.path) {
                document.getElementById(mode + '-keyfile').value = data.path;
                autoSelectKeyMode(mode);
                showResult(mode, '密钥已上传', false);
            } else showResult(mode, '上传失败', true);
        } catch(e) { showResult(mode, '异常', true); }
    }
    async function startEncrypt() {
        const input = document.getElementById('enc-input').value;
        const output = document.getElementById('enc-output').value || input + '.dpep';
        const password = document.getElementById('enc-password').value;
        const keyfile = document.getElementById('enc-keyfile').value;
        const split = document.getElementById('enc-split').checked;
        autoSelectKeyMode('enc');
        const body = {input, output, password, keyfile, chain:currentChain, split, header:output+'.hdr', data:output+'.dat'};
        const btn = document.getElementById('enc-start'); btn.disabled = true;
        try {
            const resp = await fetch('/api/encrypt', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
            const res = await resp.json();
            showResult('enc', res.message || res.error, !!res.error);
        } catch(e) { showResult('enc', '请求失败', true); }
        btn.disabled = false;
    }
    async function startDecrypt() {
        const input = document.getElementById('dec-input').value;
        const output = document.getElementById('dec-output').value || input.replace('.dpep','.decrypted');
        const password = document.getElementById('dec-password').value;
        const keyfile = document.getElementById('dec-keyfile').value;
        const split = document.getElementById('dec-split').checked;
        const body = {input, output, password, keyfile, chain:"", split, header:input+'.hdr', data:input+'.dat'};
        const btn = document.getElementById('dec-start'); btn.disabled = true;
        try {
            const resp = await fetch('/api/decrypt', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
            const res = await resp.json();
            showResult('dec', res.message || res.error, !!res.error);
        } catch(e) { showResult('dec', '请求失败', true); }
        btn.disabled = false;
    }

    // 熵收集
    function openEntropyPanel() {
        document.getElementById('entropy-panel').style.display = 'flex';
        entropyData = ""; collectActive = true; lastMouseTime = 0;
        updateEntropyProgress();
        drawRandomCanvas();
        document.getElementById('entropy-keyboard').value = '';
        document.getElementById('generate-key-btn').disabled = true;
        document.getElementById('entropy-canvas').addEventListener('mousemove', onMouseEntropy);
        window.entropyInterval = setInterval(drawRandomCanvas, 3000);
    }
    function closeEntropyPanel() {
        document.getElementById('entropy-panel').style.display = 'none';
        collectActive = false;
        document.getElementById('entropy-canvas').removeEventListener('mousemove', onMouseEntropy);
        clearInterval(window.entropyInterval);
    }
    function drawRandomCanvas() {
        const canvas = document.getElementById('entropy-canvas');
        const ctx = canvas.getContext('2d');
        const imgData = ctx.createImageData(canvas.width, canvas.height);
        for (let i=0; i<imgData.data.length; i+=4) {
            const v = Math.random() > 0.5 ? 255 : 0;
            imgData.data[i]=v; imgData.data[i+1]=v; imgData.data[i+2]=v; imgData.data[i+3]=255;
        }
        ctx.putImageData(imgData,0,0);
    }
    function onMouseEntropy(e) {
        if (!collectActive) return;
        const now = Date.now();
        if (now - lastMouseTime < 100) return;
        lastMouseTime = now;
        const rect = e.target.getBoundingClientRect();
        entropyData += e.clientX-rect.left + ',' + (e.clientY-rect.top) + ';';
        if (entropyData.length > entropyThreshold*2) entropyData = entropyData.slice(-entropyThreshold*2);
        updateEntropyProgress();
    }
    function collectKeyboardEntropy() {
        if (!collectActive) return;
        const inp = document.getElementById('entropy-keyboard');
        if (inp.value.length > 0) {
            entropyData += inp.value[inp.value.length-1] + ';';
            if (entropyData.length > entropyThreshold*2) entropyData = entropyData.slice(-entropyThreshold*2);
            inp.value = '';
            updateEntropyProgress();
        }
    }
    function updateEntropyProgress() {
        const progress = Math.min(100, Math.floor((entropyData.length / entropyThreshold) * 100));
        const fill = document.getElementById('entropy-progress');
        fill.style.width = progress + '%';
        // 红→绿渐变
        const r = Math.floor(255 * (1 - progress/100));
        const g = Math.floor(255 * (progress/100));
        fill.style.background = 'rgb(' + r + ',' + g + ',0)';
        document.getElementById('generate-key-btn').disabled = entropyData.length < entropyThreshold;
    }
    async function generateKeyWithEntropy() {
        const btn = document.getElementById('generate-key-btn'); btn.disabled = true;
        try {
            const resp = await fetch('/api/generate-keyfile', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({entropy: entropyData})
            });
            const data = await resp.json();
            if (data.path) {
                document.getElementById('enc-keyfile').value = data.path;
                autoSelectKeyMode('enc');
                showResult('enc', '密钥已生成: ' + data.path, false);
                closeEntropyPanel();
            } else alert('生成失败');
        } catch(e) { alert('异常'); }
    }
    drawRandomCanvas();
    buildChain();
</script>
</body>
</html>`

// Start 启动图形界面
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
	// 加密成功后，若输入文件在 temp 目录下，自动删除
	if strings.HasPrefix(req.InputPath, tempDir) {
		os.Remove(req.InputPath)
	}
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
	// 解密成功后，若输入文件在 temp 目录下，自动删除
	if strings.HasPrefix(req.InputPath, tempDir) {
		os.Remove(req.InputPath)
	}
}
