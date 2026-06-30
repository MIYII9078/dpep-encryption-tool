# DPEP 自动化测试脚本（最终修正版）
$dpep = ".\dpep.exe"
$testDir = ".\text"
$passed = 0
$failed = 0

function Write-TestResult {
    param([string]$Message, [switch]$Pass, [switch]$Fail)
    if ($Pass) {
        Write-Host "[PASS] $Message" -ForegroundColor Green
        $script:passed++
    } elseif ($Fail) {
        Write-Host "[FAIL] $Message" -ForegroundColor Red
        $script:failed++
    } else {
        Write-Host "[INFO] $Message" -ForegroundColor Cyan
    }
}

Write-TestResult "开始 DPEP 测试"
if (-not (Test-Path $dpep)) { Write-TestResult "找不到 $dpep" -Fail; exit 1 }
if (-not (Test-Path $testDir)) { New-Item -ItemType Directory -Path $testDir | Out-Null }

# 1. 准备测试文件
Write-TestResult "---------- 准备测试文件 ----------"
"Hello DPEP! 这是一个测试文件。" | Out-File -Encoding UTF8 "$testDir\normal.txt"
"这是第二行内容，用于测试压缩效果。" | Out-File -Encoding UTF8 "$testDir\big.txt"
"1234567890" | Out-File -Encoding UTF8 "$testDir\numbers.txt"
Write-TestResult "测试文件创建完毕"

# 2. 密码模式 + 模板 01
Write-TestResult "---------- 密码模式 + 模板 01 ----------"
& $dpep encrypt -f "$testDir\normal.txt" -k "123456" -t "01" *>$null
if (Test-Path "$testDir\normal.txt.dpep") {
    Write-TestResult "加密成功" -Pass
} else {
    Write-TestResult "加密失败" -Fail; exit 1
}
& $dpep decrypt -f "$testDir\normal.txt.dpep" -k "123456" -o "$testDir\decrypted.txt" *>$null
if (Test-Path "$testDir\decrypted.txt") {
    $diff = Compare-Object (Get-Content "$testDir\normal.txt") (Get-Content "$testDir\decrypted.txt")
    if (-not $diff) { Write-TestResult "解密正确，原文匹配" -Pass } else { Write-TestResult "解密内容不一致" -Fail }
} else {
    Write-TestResult "解密后文件未生成" -Fail
}

# 3. 自定义链（压缩 + 混沌混淆 + AES）
Write-TestResult "---------- 自定义链（压缩 + 混沌混淆） ----------"
$seed = -join ((1..32 | ForEach-Object { '{0:X2}' -f (Get-Random -Maximum 256) }) -join ' ')
$chain = "08 06 12 03 20 $seed 0E 01 0F 00"
Write-TestResult "使用链: $chain"
& $dpep encrypt -f "$testDir\big.txt" -k "mypass" -p $chain *>$null
if (Test-Path "$testDir\big.txt.dpep") {
    Write-TestResult "自定义链加密成功" -Pass
} else {
    Write-TestResult "自定义链加密失败" -Fail
}
& $dpep decrypt -f "$testDir\big.txt.dpep" -k "mypass" -o "$testDir\big_decrypted.txt" *>$null
if (Test-Path "$testDir\big_decrypted.txt") {
    $diff = Compare-Object (Get-Content "$testDir\big.txt") (Get-Content "$testDir\big_decrypted.txt")
    if (-not $diff) { Write-TestResult "自定义链解密正确" -Pass } else { Write-TestResult "自定义链解密不一致" -Fail }
} else {
    Write-TestResult "自定义链解密失败，文件不存在" -Fail
}

# 4. 密钥文件模式（使用正确链 0E 02 0F 00）
Write-TestResult "---------- 密钥文件模式 ----------"
$keyFile = "$testDir\key.bin"
$bytes = New-Object byte[] 32; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
[System.IO.File]::WriteAllBytes($keyFile, $bytes)
& $dpep encrypt -f "$testDir\normal.txt" -K $keyFile -p "0E 02 0F 00" *>$null
if (Test-Path "$testDir\normal.txt.dpep") { Write-TestResult "密钥文件加密成功" -Pass } else { Write-TestResult "密钥文件加密失败" -Fail }
& $dpep decrypt -f "$testDir\normal.txt.dpep" -K $keyFile -o "$testDir\kf_decrypted.txt" *>$null
if (Test-Path "$testDir\kf_decrypted.txt") {
    $diff = Compare-Object (Get-Content "$testDir\normal.txt") (Get-Content "$testDir\kf_decrypted.txt")
    if (-not $diff) { Write-TestResult "密钥文件解密正确" -Pass } else { Write-TestResult "密钥文件解密不一致" -Fail }
} else {
    Write-TestResult "密钥文件解密失败，文件不存在" -Fail
}

# 5. 分离模式（加 -t 01 和 -s）
Write-TestResult "---------- 分离模式 ----------"
& $dpep encrypt -f "$testDir\normal.txt" -k "999" -t "01" -s -H "$testDir\header.hdr" -D "$testDir\data.dat" *>$null
if ((Test-Path "$testDir\header.hdr") -and (Test-Path "$testDir\data.dat")) {
    Write-TestResult "分离模式加密成功" -Pass
} else {
    Write-TestResult "分离模式加密失败" -Fail
}
& $dpep decrypt -s -H "$testDir\header.hdr" -D "$testDir\data.dat" -k "999" -o "$testDir\split_decrypted.txt" *>$null
if (Test-Path "$testDir\split_decrypted.txt") {
    $diff = Compare-Object (Get-Content "$testDir\normal.txt") (Get-Content "$testDir\split_decrypted.txt")
    if (-not $diff) { Write-TestResult "分离模式解密正确" -Pass } else { Write-TestResult "分离模式解密不一致" -Fail }
} else {
    Write-TestResult "分离模式解密失败，文件不存在" -Fail
}

# 6. 错误处理测试（基于退出码）
Write-TestResult "---------- 错误处理测试 ----------"
& $dpep decrypt -f "$testDir\normal.txt.dpep" -k "wrongpass" *>$null
if ($LASTEXITCODE -ne 0) { Write-TestResult "错误密码返回非零退出码" -Pass } else { Write-TestResult "错误密码未正确报错" -Fail }

& $dpep encrypt -f "$testDir\nofile.txt" -k "abc" -t "01" *>$null
if ($LASTEXITCODE -ne 0) { Write-TestResult "缺失文件返回非零退出码" -Pass } else { Write-TestResult "缺失文件未正确报错" -Fail }

$shortKey = "$testDir\short.bin"
[System.IO.File]::WriteAllBytes($shortKey, (New-Object byte[] 31))
& $dpep encrypt -f "$testDir\normal.txt" -K $shortKey -p "11 00" *>$null
if ($LASTEXITCODE -ne 0) { Write-TestResult "密钥文件长度校验生效" -Pass } else { Write-TestResult "密钥文件长度校验未触发" -Fail }

# 7. 模板系统
Write-TestResult "---------- 模板系统 ----------"
$output = & $dpep templates 2>&1 | Out-String
if ($output -match "01:") { Write-TestResult "模板列表显示正常" -Pass } else { Write-TestResult "模板列表异常" -Fail }

$customTpl = "$testDir\my_templates.json"
'{"test1":"08 06 0E 01 0F 00"}' | Out-File -Encoding UTF8 $customTpl
& $dpep encrypt -f "$testDir\normal.txt" -k "abc" -t "test1" --template-file $customTpl *>$null
if (Test-Path "$testDir\normal.txt.dpep") { Write-TestResult "自定义模板加密成功" -Pass } else { Write-TestResult "自定义模板加密失败" -Fail }

# 8. Verbose
Write-TestResult "---------- Verbose 输出 ----------"
& $dpep encrypt -f "$testDir\normal.txt" -k "test" -t "01" -v *>$null
if ($LASTEXITCODE -eq 0) { Write-TestResult "Verbose 模式无异常" -Pass } else { Write-TestResult "Verbose 模式异常" -Fail }

# 总结
Write-Host ""
Write-Host "=================== 测试总结 ===================" -ForegroundColor Yellow
Write-Host "通过: $passed" -ForegroundColor Green
Write-Host "失败: $failed" -ForegroundColor Red
if ($failed -eq 0) { Write-Host "所有自动化测试通过！" -ForegroundColor Green } else { Write-Host "存在失败项，请检查输出。" -ForegroundColor Red }
Write-Host "================================================" -ForegroundColor Yellow