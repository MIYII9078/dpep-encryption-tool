# DPEP · Dynamic Programmable Encryption Protocol

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go" alt="Go Version"/>
  <img src="https://img.shields.io/badge/version-1.1_Pre--1-brightgreen" alt="Version"/>
  <img src="https://img.shields.io/badge/license-Apache-2.0-blue" alt="License"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey" alt="Platform"/>
</p>

**DPEP** 不是另一个加密工具，而是一套**可编程的加密管线元协议**。  
你可以像搭积木一样自由组合压缩、混淆、自定义密码与 AES‑256‑GCM，生成**完全自描述**的加密文件——解密时无需任何外部配置，只需密码或密钥。

---

## 🔥 为什么需要 DPEP？

- **传统加密软件只给你一种固定的加密方式**（例如 AES‑256‑CBC），无法按需叠加混淆层、压缩层或自定义算法。
- **DPEP 让你“编程”自己的加密流程**：通过一串操作码，你可以组合出成千上万种独特的加密管线，即使攻击者知道你的算法，没有密钥也寸步难行。
- **纵深防御**：标准 AES‑GCM 在最外层提供可证明安全，内层可加入自研混淆（**ScrambleXOR**）或自定义分组密码（**AESCipher**），即使 AES 被突破（极不可能），攻击者还要面对额外变换。
- **数据与钥匙分离**：支持“分离模式”（.hdr + .dat），你可以把解密参数（头部）和加密数据分开存放，进一步提高安全性。
- **零门槛操作**：提供 **命令行 (CLI)** 和 **图形界面 (GUI)** 两种模式，新手也能轻松上手。

---

## 📸 快速预览

> TODO：此处可插入一张 GUI 操作截图（encrypt 选项卡），展示可视化构建操作链、文件上传、熵收集面板等。

---

## ⚡ 核心特性

- **🧩 可编程操作码链**  
  使用十六进制操作码自由组合：压缩（Deflate）、变长编码（Varint）、基数打包（BaseN）、混淆（**ScrambleXOR**）、分组加密（**AESCipher**）、AES‑256‑GCM 等。

- **🔐 纵深防御与安全设计**  
  - AES‑256‑GCM 提供认证加密，保证机密性与完整性  
  - PBKDF2‑HMAC‑SHA256（60 万次迭代）密钥派生  
  - 所有自研算法采用恒定时间实现，抵抗侧信道攻击  
  - 分离模式通过 SHA‑256 校验数据文件，防重组攻击  
  - 解密错误统一返回模糊信息，防止 Oracle 攻击  

- **🖥️ 双界面支持**  
  - **CLI 模式**：适合脚本、自动化，支持交互式向导、模板系统、国际化  
  - **GUI 模式**：浏览器可视化操作，支持文件上传、鼠标滑动画布 + 键盘乱敲收集随机熵生成密钥文件、操作链下拉构建  

- **📁 多种存储模式**  
  - **单文件模式**：所有信息打包在一个 `.dpep` 文件里  
  - **分离模式**：头部（.hdr）与数据（.dat）分开，可分别保存在不同位置  

- **🤝 多因素支持**  
  支持密码、密钥文件，预留生物特征 / 硬件令牌绑定（操作码 `0x0E` 和 `0x11`）

- **🌍 国际化**  
  自动检测系统语言，支持中文和英文（可扩展）

- **⚡ 轻量高性能**  
  纯 Go 编写，单文件可执行，无外部依赖，跨平台支持 Windows / macOS / Linux

---

## 🚀 快速开始

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/MIYII9078/dpep-encryption-tool.git
cd dpep-encryption-tool

# 编译 CLI 版本
go build -o dpep.exe

# 编译 GUI 版本（需在 gui 分支）
git checkout gui
go build -o dpep_gui.exe

> 如果你只想使用，可以直接从 [Releases](https://github.com/MIYII9078/dpep-encryption-tool/releases) 页面下载预编译的二进制文件。

### 命令行快速演示

```powershell
# 加密（使用模板 01，密码 123456）
.\dpep.exe encrypt -f secret.txt -k 123456 -t 01

# 解密
.\dpep.exe decrypt -f secret.txt.dpep -k 123456

# 生成一个用户参与的随机密钥文件（敲击键盘收集熵）
.\dpep.exe keyfile -o mykey.bin

# 用密钥文件加密
.\dpep.exe encrypt -f secret.txt -K mykey.bin -p "0E 02 0F 00"
```

### 图形界面启动

```powershell
.\dpep_gui.exe --gui
```

浏览器会自动打开，你可以在界面中上传文件、下拉选择操作链，点击“生成密钥文件”时，会弹出一个带有随机黑白方块的面板，用鼠标在方块上滑动并乱敲键盘，进度条从红色变成绿色后即可生成安全的密钥文件。

---

## 🧱 项目结构

```
DPEP/
├─ cmd/                  # CLI 命令（encrypt, decrypt, templates, keyfile）
├─ internal/
│  ├─ crypto/            # 密码学核心（AES‑GCM, ScrambleXOR, AESCipher, Deflate…）
│  ├─ protocol/          # 协议解析（头部序列化、操作链校验）
│  ├─ i18n/              # 国际化语言文件
│  └─ template/          # 操作码模板系统
├─ gui/                  # 图形界面（HTTP 服务 + 内嵌 HTML/JS）
├─ assets/               # 资源文件（语言、模板）
└─ test.ps1              # 自动化测试脚本
```

---

## 📄 操作码一览表

| 操作码 | 名称 | 参数说明 |
|--------|------|----------|
| `0x00` | 终结符 | 标记链结束 |
| `0x08` | Deflate 压缩 | 1 字节压缩级别（0‑9） |
| `0x09` | 直通（Raw） | 无操作 |
| `0x0A` | Varint 编码 | 变长整数编码（预留） |
| `0x0C` | 模板展开 | 从内置模板加载链（仅用于模板系统） |
| `0x0E` | 密钥派生 | 1 字节算法 ID（01=PBKDF2, 02=密钥文件, 04=生物特征） |
| `0x0F` | AES‑256‑GCM | 标准认证加密 |
| `0x10` | BaseN 编码 | 1 字节基数（0A=10, 24=36, 3E=62） |
| `0x11` | 密钥文件加密 | 直接使用 32 字节密钥 |
| `0x12` | ScrambleXOR | 基于 HMAC 的流密码混淆 (1 字节轮数 + 1 字节种子长度 + 种子) |
| `0x13` | AESCipher | 基于 AES 组件的 SPN 分组密码 (1 字节轮数固定 10 + 1 字节 S 盒选择) |
| `0x14` | 流式分帧（预留） | 2 字节最大载荷 + 1 字节标志 |
| `0x15`/`0x16` | 反调试/环境绑定 | 商业扩展（预留） |

---

## 🛡️ 安全设计

- **认证加密边界**：AES‑GCM 的 Tag 覆盖所有前置变换，任何篡改都会导致解密失败。
- **密钥隔离**：各操作码通过 HKDF 从主密钥派生独立密钥，单一密钥泄露不影响其他层。
- **自研算法的透明性**：  
  - **ScrambleXOR** 基于 HMAC‑SHA256 计数器模式生成密钥流，结合 AES S‑box 和字节循环移位，不涉及任何混沌理论专利。  
  - **AESCipher** 是一个 10 轮 SPN 分组密码，直接使用 AES 的 S‑box、ShiftRows 和 MDS 矩阵，本质上是 AES 的简化变体，未引入任何外部专利组件。
- **抗侧信道**：自研算法使用恒定时间实现和位切片技术。
- **抗压缩炸弹**：解压时限制输出/输入比 ≤ 200，最大输出 ≤ 100 MiB。
- **防 Oracle**：所有解密错误均返回统一信息，不泄露内部状态。

---

## 🧪 测试

项目包含自动化测试脚本，覆盖加密/解密、分离模式、错误处理、模板系统等。

```powershell
# 在项目根目录运行
.\test.ps1
```

---

## 🤝 贡献

DPEP 目前处于 **Beta 1.1 Pre‑1** 阶段，欢迎提交 Issue 和 Pull Request。  
如果你想参与开发，可以先看看以下方向：

- 完善多因素绑定（生物特征 / 硬件令牌）
- 实现流式加密/解密（直播场景）
- 为 GUI 添加拖拽上传、进度条
- 贡献其他语言文件（日语、法语等）

---

## 📃 许可

本项目采用 [Apache-2.0 license](https://github.com/MIYII9078/dpep-encryption-tool/blob/main/LICENSE)。

---

**DPEP** — 你的数据，你定义的保护。  
*Define your own encryption pipeline. Your data, your rules.*
```
