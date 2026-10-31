# DecryptCTRNand

## 简介

3DS NAND Dump 离线解密工具（PC 端，Windows 原生；另附纯 JDK 11 GUI 实现）。

- 本工具由**豆包 AI 创作**（分析、拆解、验算、脚本与文档撰写均由 AI 完成）；用户提供提示词、测试环境与实机 dump 材料配合验证。
- **命名动机**：GodMode9 对开发机（dev）NAND 仍无法完全解密，本工具提供 PC 端离线解密替代方案。
- **当前版本：2.0**（新增 TWL 分区解密；dev 开发机必须使用 raw OTP）。版本历史与详细变更见 `DEVELOPMENT.md`。

主交付形态：

- **主交付 = Windows 原生 BAT + PowerShell**（`DecryptCTRNand.bat` + `DecryptCTRNand.ps1`）：仅用 .NET Framework 内置 Aes / SHA256 / BigInteger，零外部依赖、无需 Python / pip / OpenSSL。
- **Python 参考实现**（`DecryptCTRNand.py`）：与主交付逐字节等价的交叉验证实现，仅需 `pycryptodome`。
- **Java 11 GUI**（`java/DecryptCTRNandGUI.java` → 本地构建 `java\DecryptCTRNandGUI.jar`）：纯 JDK（Swing + javax.crypto + BigInteger），零外部依赖；**双击 `.jar` 即 GUI**，同一 jar 也支持与 PS1 参数完全一致的 CLI 无头模式。

功能概述：

- 从明文 boot9 + OTP + eMMC CID 派生 console-unique normalKey（slot 0x03 TWL + 0x04–0x07）
- 自动解密 OTP（dev / retail 双模式，统一校验：DEADB00F + SHA256 + dev flag 与模式一致性）
- 解析 NCSD 头与分区表（边界/重叠检查，未知 crypt/fs 组合拒绝解密、不猜 AES slot）
- 逐分区解密：CTRNAND / firm0 / firm1 / AGB save 走 AES-CTR（SHA256(CID)[:16] nonce）；**TWL 分区（slot 0x03）走 DSi 专用方案**（SHA1(CID)[:16] 反转 nonce + TWL keyscrambler + 每 16 字节块 keystream 反转 XOR；dev 必须用 raw OTP 派生 CustId）
- 输出结构校验：CTRNAND MBR 55AA、FIRM magic、TWL blk0x1D 锚点 + MBR 55AA + twln FAT boot 55AA；核对实际写入字节数、记录每分区 SHA-256
- 输出安全：先写 `.tmp`、校验通过后原子提交；默认拒绝覆盖（需 `-Force`）；密钥/CID 默认隐藏（`-ShowKeys` 显示）

## 使用

启动方式（三端参数名完全一致，大小写不敏感）：

```cmd
REM 方式一：BAT 启动器（主交付，推荐）
DecryptCTRNand.bat -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out

REM 方式二：PowerShell 直接调用
.\DecryptCTRNand.ps1 -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out

REM 方式三：Python 参考实现
python DecryptCTRNand.py -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out

REM 方式四：Java 11 GUI / CLI（jar 双击即用）
DecryptCTRNandGUI.jar                    REM 双击 .jar：直接打开 Swing GUI（无需任何启动器）
java -jar DecryptCTRNandGUI.jar          REM 同上（命令行方式）
java -jar DecryptCTRNandGUI.jar -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out
```

命令行参数（PS1 / BAT、Python、Java CLI 三端统一）：

| 参数 | 说明 |
|------|------|
| `-NandFile` | NAND dump 文件路径（必填） |
| `-Boot9File` | 明文 boot9.bin（必填，64KB 或 32KB 均可） |
| `-OtpFile` | OTP 文件（必填，加密或解密均可） |
| `-OtpDecrypted` | OTP 已是解密明文（仍会统一校验） |
| `-CidHex` | eMMC CID，32 个 hex 字符 |
| `-CidFile` | nand_cid.mem（16 字节） |
| `-OutDir` | 解密分区输出目录 |
| `-Mode` | `dev`（默认）或 `retail` |
| `-Force` | 允许覆盖已存在的输出文件（默认拒绝） |
| `-ShowKeys` | 显示派生的 normalKey（默认隐藏） |

输入文件说明：

| 文件 | 大小 | 说明 |
|------|------|------|
| sysnand.bin | ~950MB | 完整 NAND dump（GodMode9 格式） |
| boot9.bin | 64KB / 32KB | 明文 boot9（64KB GM9 dump：前 32KB prot + 后 32KB boot9；或 32KB prot-only） |
| otp.mem | 256B | 加密 OTP（GM9 dump 格式） |
| otp_dec.mem | 256B | 解密后 OTP（可选，`-OtpDecrypted` 时使用，仍会校验） |
| nand_cid.mem | 16B | eMMC CID（NAND 芯片出厂值） |

输出说明：

- 默认仅输出状态行；`-ShowKeys` 时才显示 slot 0x03（TWL）与 0x04–0x07 normalKey 与 CID（敏感，默认隐藏）
- 解密分区文件 `partition_N_slotNN.bin`（需 `-OutDir`）：先写 `.tmp`，通过结构校验 + 字节数核对后原子提交；每分区打印 SHA-256
- 未知 crypt/fs 类型的分区会明确跳过并提示，**不会**擅自套用某个 AES slot

GUI 提示：路径输入框支持从资源管理器直接**拖放**文件/文件夹；每个标签页是一个独立解密任务，可同时运行（每任务独立日志与取消）；工具栏「**批量解密**」一键启动所有已配置（NAND 路径非空）且未在运行的标签页任务；语言内置「简体中文（默认）/ English」，切换即时生效。

## 编译

Java 11（jar 为本地构建产物，**不随仓库提交**——`.gitignore` 已排除 `*.jar`）：

```cmd
java\build.bat
```

产物：`java\DecryptCTRNandGUI.jar`（`javac --release 11` 编译，Java 11 字节码；Main-Class manifest）。**克隆仓库后先本地构建再使用**；分发/使用只需这一个 jar——双击即 GUI、`java -jar ... -NandFile ...` 即 CLI，无需任何启动器。

运行环境要求：Windows PowerShell 5.1 + .NET Framework 4.5+（推荐 4.8）；Java 版需 JRE/JDK 11+。完整要求表见 `DEVELOPMENT.md`。

## 许可

本工具以 **MIT License** 发布（见 `LICENSE`）。

实现参考：

- 3dbrew: CTR_NAND, OTP_Registers, AES_Registers
- pyctr (github.com/ihaveamac/pyctr) — crypto/engine.py（MIT License）
- decrypt9 / GodMode9 源码
