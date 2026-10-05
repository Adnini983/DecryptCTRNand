# DecryptCTRNand

3DS NAND Dump 离线解密工具（PC 端，Windows 原生）。

## 创作说明

本工具由 **豆包 AI 创作**（分析、拆解、验算、脚本与文档撰写均由 AI 完成）；**用户提供提示词、测试环境与密钥/实机 dump 材料配合验证**。

## 命名动机

当前 GodMode9（GM9）对开发机（dev）NAND 仍无法完全解密，本工具提供 PC 端离线解密替代方案。

## 主交付形态

**主交付 = Windows 原生 BAT + PowerShell**（.bat 启动器 + .ps1 核心逻辑）
- 纯 Windows 内置能力：.NET Framework 自带 Aes / SHA256 / BigInteger
- 零外部依赖、无需 Python / pip / OpenSSL

Python 版（`DecryptCTRNand.py`）保留为内部交叉验证参考，非主交付。

## 运行环境要求

**主交付零外部依赖（无 Python / pip / OpenSSL）。**

| 组件 | 最低版本 | 说明 |
|------|---------|------|
| Windows PowerShell | 5.1 | Win10 1903+ / Win11 预装；Win7/8.1 需安装 [WMF 5.1](https://www.microsoft.com/download/details.aspx?id=54616) |
| .NET Framework | 4.5+（推荐 4.8） | Win10 1903+ / Win11 预装 4.8；Win7/8.1 需手动安装 |
| System.Numerics.BigInteger | .NET 4.0+ | 128 位大数运算（scrambler / counter） |
| System.Security.Cryptography.Aes | .NET 3.5+（Aes.Create 工厂方法 4.0+） | AES-CBC / AES-CTR 加解密 |
| Add-Type 内联 C# | .NET Framework 自带 csc.exe | 无需 Visual Studio，.NET Framework 4.x 自带 C# 编译器 |

**推荐环境：Windows 10 1903 或更高版本（自带 PowerShell 5.1 + .NET Framework 4.8），开箱即用。**

## 功能

- 从明文 boot9 + OTP + eMMC CID 派生 console-unique normalKey
- 自动解密 OTP（dev / retail 双模式）
- 解析 NCSD 头与分区表
- 逐分区 AES-CTR 解密（CTRNAND / firm0 / firm1 / TWL / AGB save）
- 完整性校验（NCSD 魔数 / MBR 55AA / FIRM magic）

## 启动方式

### 方式一：BAT 启动器（推荐）

```cmd
DecryptCTRNand.bat -NandFile <sysnand.bin> -Boot9File <boot9.bin> -OtpFile <otp.mem> -CidFile <nand_cid.mem> -Mode dev
```

### 方式二：PowerShell 直接调用

```powershell
.\DecryptCTRNand.ps1 -NandFile <sysnand.bin> -Boot9File <boot9.bin> -OtpFile <otp.mem> -OtpDecrypted -CidFile <nand_cid.mem> -Mode dev
```

### 方式三：Python 交叉验证（参考）

```powershell
python DecryptCTRNand.py --nand <sysnand.bin> --boot9 <boot9.bin> --otp otp_dec.mem --otp-dec --cid-file nand_cid.mem
```

## 命令行参数（PS1/BAT 通用）

| 参数 | 说明 |
|------|------|
| `-NandFile` | NAND dump 文件路径（必填） |
| `-Boot9File` | 明文 boot9.bin 路径（必填） |
| `-OtpFile` | OTP 文件路径（必填，加密或解密均可） |
| `-OtpDecrypted` | OTP 已是解密明文（跳过自动解密） |
| `-CidHex` | eMMC CID（32 字符 hex 字符串） |
| `-CidFile` | nand_cid.mem 文件路径（16 字节） |
| `-OutDir` | 解密分区输出目录（可选） |
| `-Mode` | `dev`（默认）或 `retail` |

## 输入文件说明

| 文件 | 大小 | 说明 |
|------|------|------|
| sysnand.bin | ~950MB | 完整 NAND dump（GodMode9 格式） |
| boot9.bin | 64KB | 明文 boot9（GM9 dump 格式，含前 32KB prot + 后 32KB boot9） |
| otp.mem | 256B | 加密 OTP（GM9 dump 格式） |
| otp_dec.mem | 256B | 解密后 OTP（可选，跳过自动解密） |
| nand_cid.mem | 16B | eMMC CID（NAND 芯片出厂值） |

## 输出

- 密钥派生结果（slot0x04–0x07 normalKey）
- NCSD 分区表解析（偏移/大小/slot）
- 解密分区文件（partition_N_slotNN.bin，需 -OutDir 指定）

## 验证状态

| 平台 | 模式 | 状态 |
|------|------|------|
| Old3DS devkit (REFxxxxxxx) | dev | ✅ 端到端验证通过（CTRNAND MBR 55AA / firm0 FIRM magic） |
| New3DS retail (QJFxxxxxxx) | retail | ✅ 端到端验证通过（CTRNAND MBR 55AA / 卷标 CTR） |

**已知技术点：**
- slot0x05（New3DS CTRNAND）KeyY 为固定全局值 `0x4D804F4E9990194613A204AC584460BE`（dev/retail 通用），不从 boot9 keyblob 读取
- Old3DS CTRNAND = slot0x04，New3DS CTRNAND = slot0x05（按 NCSD crypttype 自动判定）

## 已知限制

- **CID 依赖**：AES-CTR nonce = SHA256(CID)[:16]，128 位不可暴力破解。CID 是 eMMC 芯片出厂值，不在 OTP 内，必须从实机 dump 获取。
- **TWL 分区**：nonce 方案不同（SHA1(CID) 反转），当前版本未实现。
- **组件级解析**：仅完成解密与结构验证（MBR / FIRM magic），NAND FS 挂载与文件系统级分析需后续工具。

## 详细验证明细（dev 本机）
- ✅ OTP 解密：已在 REFxxxxxxx 本机 dump 端到端验证通过（dev 模式，DEADB00F + SHA256 校验双通过）
- ✅ NCSD 解析：已在 REFxxxxxxx 本机 dump 端到端验证通过（5 分区识别正确）
- ✅ scrambler 公式：已用 dev slot0x2C 已知 KeyX/KeyY/KeyN 反推 C1 并前向验证通过
- ✅ keyinit 算法：已移植自 pyctr（MIT），slot0x04–0x07 normalKey 与 pyctr / Python 版逐字节匹配
- ✅ CTRNAND 解密：已在 REFxxxxxxx 本机 dump 端到端验证通过（MBR 55AA）
- ✅ firm0 解密：已在 REFxxxxxxx 本机 dump 端到端验证通过（FIRM magic）
- ✅ BAT/PS1 与 Python 版输出交叉验证一致

## 方案依据

- 3dbrew: CTR_NAND, OTP_Registers, AES_Registers
- pyctr (github.com/ihaveamac/pyctr) — crypto/engine.py (MIT License)
- decrypt9 / GodMode9 源码

## 敏感口径

- OTP / CID / movable.sed 等 per-console 敏感字段仅用于解密与验证，不展示明文
- 输出文件名使用通用名，不含原始序列号
