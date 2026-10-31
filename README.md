# DecryptCTRNand

3DS NAND Dump 离线解密工具（PC 端，Windows 原生；另附纯 JDK 11 GUI 实现）。

## 创作说明

本工具由 **豆包 AI 创作**（分析、拆解、验算、脚本与文档撰写均由 AI 完成）；**用户提供提示词、测试环境与密钥/实机 dump 材料配合验证**。

## 命名动机

当前 GodMode9（GM9）对开发机（dev）NAND 仍无法完全解密，本工具提供 PC 端离线解密替代方案。

## 版本

- **2.0（当前）**：新增 **TWL 分区解密**（NCSD crypttype 1 → slot 0x03，SHA1(CID) 反转 nonce + TWL keyscrambler + 块内字节反转 CTR；**dev 开发机必须使用 raw OTP（otp.mem/.bin），otp_dec 无法解出正确的 TWL 密钥**——已在真机 dump 实证）。版本号由 1.0 修正为 2.0（此前外部审计误把 1.0 读成 0.1）。
- 1.0（v0.2 加固版）：依据外部代码审计系统性加固正确性/输入验证/输出验证/安全，并新增纯 JDK 11 GUI 实现与合成测试向量三端交叉验证。
- v0.1：初版（BAT + PowerShell），已在用户实机 dump 上验证（见「验证状态」）。

## 主交付形态

- **主交付 = Windows 原生 BAT + PowerShell**（`DecryptCTRNand.bat` + `DecryptCTRNand.ps1`）：仅用 .NET Framework 内置 Aes / SHA256 / BigInteger，零外部依赖、无需 Python / pip / OpenSSL。
- **Python 参考实现**（`DecryptCTRNand.py`）：与主交付逐字节等价的交叉验证实现，仅需 `pycryptodome`。
- **Java 11 GUI**（`java/DecryptCTRNandGUI.java` → 本地构建 `java\DecryptCTRNandGUI.jar`）：纯 JDK（Swing + javax.crypto + BigInteger），**零外部依赖，只要有 JRE/JDK 11+ 即可使用**。**直接双击 `.jar` 即可打开 GUI，不需要任何启动器**；同一 jar 也支持与 PS1 参数完全一致的 `--cli` 无头模式。
  - **标签页多任务**：每个标签页是一个独立解密任务，可同时运行（每任务独立日志与取消）。
  - **路径框拖放**：NAND/boot9/OTP/CID/输出目录输入框可直接把文件或文件夹从资源管理器拖入。
  - **多语言接口**：内置语言仅「简体中文（默认）/ English」，可通过 `Lang.register(code, entries)` 扩展；GUI 内切换即时生效。
  - 注意：编译好的 jar **不随仓库提交**（`.gitignore` 已排除 `*.jar`），克隆后先用 `java\build.bat` 本地构建。

## 运行环境要求

| 组件 | 最低版本 | 说明 |
|------|---------|------|
| Windows PowerShell | 5.1 | Win10 1903+ / Win11 预装；Win7/8.1 需安装 [WMF 5.1](https://www.microsoft.com/download/details.aspx?id=54616) |
| .NET Framework | 4.5+（推荐 4.8） | Win10 1903+ / Win11 预装 4.8；Win7/8.1 需手动安装 |
| System.Numerics.BigInteger | .NET 4.0+ | 128 位大数运算（scrambler / counter） |
| System.Security.Cryptography.Aes | .NET 3.5+ | AES-CBC / AES-CTR 加解密 |
| Add-Type 内联 C# | .NET Framework 自带 csc.exe | 无需 Visual Studio |
| Java（GUI 版） | JRE/JDK 11+ | 仅 `java`/`javaw`，无其他依赖 |

**推荐环境：Windows 10 1903 或更高版本（自带 PowerShell 5.1 + .NET Framework 4.8），开箱即用。**

## 功能

- 从明文 boot9 + OTP + eMMC CID 派生 console-unique normalKey（slot 0x03 TWL + 0x04–0x07）
- 自动解密 OTP（dev / retail 双模式，**双路径统一校验**：DEADB00F + SHA256 + dev flag 与模式一致性）
- 解析 NCSD 头与分区表（**边界/重叠检查**，未知 crypt/fs 组合拒绝解密、不猜 AES slot）
- 逐分区解密：CTRNAND / firm0 / firm1 / AGB save 走 AES-CTR（SHA256(CID)[:16] nonce）；**TWL 分区（slot 0x03）走 DSi 专用方案**（SHA1(CID)[:16] 反转 nonce + TWL keyscrambler + 每 16 字节块 keystream 反转 XOR；dev 必须用 raw OTP 派生 CustId）
- 输出结构校验：CTRNAND MBR 55AA、FIRM magic、**TWL blk0x1D 锚点 + MBR 55AA + twln FAT boot 55AA**；并核对实际写入字节数、记录每分区 SHA-256
- 输出安全：先写 `.tmp`、校验通过后原子提交；默认拒绝覆盖（需 `-Force`）；密钥/CID 默认隐藏（`-ShowKeys` 显示）

### 2.0 变更

| 项目 | 2.0 处理 |
|------|------|
| TWL 分区解密 | 新增 slot 0x03 完整实现（PS1/Python/Java 三端）：NCSD crypttype 1 → TWL；nonce = SHA1(CID)[:16] 字节反转；keyscrambler = ROL42((keyX_LE ^ keyY_LE) + TWL_CONST)，16 字节 BE 输出；CTR 每块 keystream 块内反转后 XOR；counter 按绝对 16 字节块计（nonce + (abs >> 4)），加密范围 [0x1BE:0x200)（MBR，起点非 16 对齐）+ [0x12E00:end)（twln FAT16 + twlp FAT12），其余原样拷贝 |
| TWL dev 密钥必须用 raw OTP | dev CustId = **raw（加密）OTP[0:8] 小端**；otp_dec.mem 解不出正确 TWL 密钥（真机实证）。`-OtpDecrypted` 路径会先把明文 OTP 用 OTP normalKey 重加密回 raw 再派生态 TWL 密钥 |
| TWL 结构校验 | blk0x1D 锚点 @ 输出 +0x1D0、MBR 55AA @ +0x1FE、twln FAT boot 55AA @ +0x12E00+0x1FE（OEM `TWL     `） |
| 版本号 | 由 1.0 修正为 **2.0**（外部审计误把 1.0 读成 0.1；若按 0.x 口径应为 0.2 族，故新版本为 2.0） |
| `DecryptCTRNandGUI.bat` | 已删除（不再需要任何启动器；双击 jar 即 GUI） |

### v0.2 变更（对照审计逐项）

| 审计项 | v0.2 处理 |
|------|------|
| AES-CTR 逐块 `TransformFinalBlock` | 改为一次性生成 counter 流 + 单次 AES-ECB 批量加密（PS1/Python/Java 三端同构） |
| 读取无完整性检查（截断仍报成功） | 新增 `ReadExactly`：短读/截断立即抛错；输出核对实际写入字节数；每分区 SHA-256 |
| boot9 / OTP / CID 长度校验 | boot9 支持 0x10000 与 0x8000；OTP 严格 0x100；CID 严格 16B / 32 hex，密钥派生前完成 |
| NCSD 偏移启发式（0xB00000） | 删除；改用规则表：crypt1→slot03(TWL)、crypt2+fs1→04、fs3→06、fs4→07、crypt3→05，其余拒绝 |
| NCSD 分区表无边界/重叠检查 | 已加：offset<0x200 跳过（TWL offset 0 豁免）、零大小跳过、越界抛错、两两重叠抛错 |
| `-OtpDecrypted` 绕过校验 | 统一走 `Assert-ValidOtpPlain`（长度 + Magic + SHA256 + dev flag↔Mode 一致性），加密/解密两路径一致 |
| Mode 与 OTP dev flag 不一致 | 校验失败即中止，不再一路跑到底 |
| 直接打印 normalKey / CID | 默认隐藏；`-ShowKeys` 才显示；日志不落盘 |
| README 声称的 MBR/FIRM 校验未实现 | v0.2 已真正实现（MBR 55AA @ 分区内 +0x1FE；FIRM magic @ 分区内 +0x00——FIRM 镜像从分区偏移 0 开始，2.0 实机验证确认并修正此偏移）。**CTR 卷标断言取消**（从未实现，AES-CTR 无认证，保留结构合理性检查） |
| 输出被静默覆盖 | 默认拒绝覆盖，`-Force` 显式授权；`.tmp` 写入 → 校验 → 原子 rename 提交；finally 清理 |
| Python 未实现分区解密 | 已实现完整分区解密/结构校验/`-Force`/`-ShowKeys`/每分区 SHA-256 |
| Python retail keyinit 硬编码 dev | `keyinit(otp_plain, boot9, dev)` 由 `-Mode` 传入，零售 keyblob 偏移正确 |
| Python 缺明文 OTP 校验 | 与 PS1 相同的统一 `validate_otp` |
| 独立测试向量 | `tests/`：合成 boot9/OTP/CID/NCSD 向量 + 三端（PS1/Python/Java）逐字节交叉验证 + 负向用例（见「测试」） |

## 启动方式

### 方式一：BAT 启动器（主交付，推荐）

```cmd
DecryptCTRNand.bat -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out
```

### 方式二：PowerShell 直接调用

```powershell
.\DecryptCTRNand.ps1 -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out
```

### 方式三：Python 参考实现

```powershell
python DecryptCTRNand.py -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out
```

### 方式四：Java 11 GUI / CLI（jar 双击即用）

```cmd
DecryptCTRNandGUI.jar                    REM 双击 .jar：直接打开 Swing GUI（无需任何启动器）
java -jar DecryptCTRNandGUI.jar          REM 同上（命令行方式）
java -jar DecryptCTRNandGUI.jar -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out
```

- **双击 jar 即 GUI**：`Main-Class` 已写入 manifest，双击调用 `javaw` 打开窗口（需系统已关联 .jar 到 JRE/JDK，标准安装默认关联）。无参数运行时自动进入 GUI。**根目录不再有 `DecryptCTRNandGUI.bat`**——jar 本身就是启动器。

## 命令行参数（三端统一，与 PS1 完全一致）

**PS1 / BAT、Python、Java CLI 三端参数名完全一致**（大小写不敏感）；Java 可直接 `java -jar ... -NandFile ...` 使用，也接受可选 `--cli` 前缀；Python/Java 保留旧 `--nand` 风格别名（见各实现 `--help`）。

| PS1 / BAT | Python | Java CLI | 说明 |
|------|------|------|------|
| `-NandFile` | `-NandFile` | `-NandFile` | NAND dump 文件路径（必填） |
| `-Boot9File` | `-Boot9File` | `-Boot9File` | 明文 boot9.bin（必填，64KB 或 32KB 均可） |
| `-OtpFile` | `-OtpFile` | `-OtpFile` | OTP 文件（必填，加密或解密均可） |
| `-OtpDecrypted` | `-OtpDecrypted` | `-OtpDecrypted` | OTP 已是解密明文（仍会统一校验） |
| `-CidHex` | `-CidHex` | `-CidHex` | eMMC CID，32 个 hex 字符 |
| `-CidFile` | `-CidFile` | `-CidFile` | nand_cid.mem（16 字节） |
| `-OutDir` | `-OutDir` | `-OutDir` | 解密分区输出目录 |
| `-Mode` | `-Mode` | `-Mode` | `dev`（默认）或 `retail` |
| `-Force` | `-Force` | `-Force` | 允许覆盖已存在的输出文件（默认拒绝） |
| `-ShowKeys` | `-ShowKeys` | `-ShowKeys` | 显示派生的 normalKey（默认隐藏） |

## 输入文件说明

| 文件 | 大小 | 说明 |
|------|------|------|
| sysnand.bin | ~950MB | 完整 NAND dump（GodMode9 格式） |
| boot9.bin | 64KB / 32KB | 明文 boot9（64KB GM9 dump：前 32KB prot + 后 32KB boot9；或 32KB prot-only） |
| otp.mem | 256B | 加密 OTP（GM9 dump 格式） |
| otp_dec.mem | 256B | 解密后 OTP（可选，`-OtpDecrypted` 时使用，仍会校验） |
| nand_cid.mem | 16B | eMMC CID（NAND 芯片出厂值） |

## 输出

- 默认仅输出状态行；`-ShowKeys` 时才显示 slot 0x03（TWL）与 0x04–0x07 normalKey 与 CID（敏感，默认隐藏）
- 解密分区文件 `partition_N_slotNN.bin`（需 `-OutDir`）：先写 `.tmp`，通过结构校验 + 字节数核对后原子提交；每分区打印 SHA-256
- 未知 crypt/fs 类型的分区会明确跳过并提示，**不会**擅自套用某个 AES slot

## 完整性/安全说明（如实口径）

- **结构校验 ≠ 密码学认证**：AES-CTR 不提供完整性保护。MBR 55AA（2 字节）与 FIRM magic（4 字节）只是合理性检查；完整分区正确性以「与可信实现逐字节比对 / SHA-256 一致」为准（见「测试」）。
- README 早期版本声称的 **CTR 卷标校验从未实现，v0.2 已明确取消该断言**。
- 密钥与 CID 为 per-console 敏感材料：默认不显示、不落盘。

## 验证状态

### 实机验证

| 平台 | 模式 | 状态 |
|------|------|------|
| Old3DS devkit (REFxxxxxxx) | dev | ✅ v0.1 端到端验证通过（OTP 解密、NCSD 5 分区、CTRNAND MBR 55AA、firm0 FIRM magic） |
| New3DS retail (QJFxxxxxxx) | retail | ✅ v0.1 端到端验证通过（CTRNAND MBR 55AA） |
| New3DS XL devkit "Louvre" (QW00004551) | dev | ✅ **2.0 全分区端到端验证通过**（TWL 分区：raw OTP 派生、twln FAT16 / twlp FAT12 / MBR 55AA / blk0x1D 锚点 PASS；p2/p3 FIRM magic PASS；p4 CTRNAND MBR 55AA PASS；`otp_dec.mem` 解不出正确 TWL 密钥——实证） |

### 合成向量三端交叉验证（`tests/`，本地保留、不入库）

- `tests/` 整个目录已加入 `.gitignore` 并从远端仓库移除（本地保留做测试与真机素材）；
- 构造含全部槽位映射的合成 NAND（CTRNAND slot04、FIRM slot06、AGB slot07、TWL slot03、New3DS CTRNAND slot05），dev / retail 各一套；
- **PS1、Python、Java 三端解密输出与 oracle 逐字节一致**，且三端互为一致；
- `-OtpDecrypted` 路径输出一致；
- 负向用例通过：无 `-Force` 拒绝覆盖、零售模式拒绝 dev OTP（dev flag 一致性）、截断 NAND 拒绝、非法 CID hex 拒绝。

## 已知限制

- **CID 依赖**：AES-CTR nonce = SHA256(CID)[:16]，128 位不可暴力破解。CID 是 eMMC 芯片出厂值，不在 OTP 内，必须从实机 dump 获取。
- **TWL dev 必须 raw OTP**：dev 开发机的 TWL CustId 取 **raw（加密）OTP[0:8]**；若手头只有 `otp_dec.mem`，工具会自动用 OTP normalKey 重加密回 raw 再派生（无需手工操作）。
- **组件级解析**：仅完成解密与结构验证（MBR / FIRM magic / TWL 锚点），NAND FS 挂载与文件系统级分析需后续工具。

## 测试（`tests/` 为本地目录，不入库）

`tests/` 整个目录已在 `.gitignore` 中排除并从远端移除，克隆仓库后不会包含；在本地保留完整测试资产（合成向量 + 真机 dump 素材）。

```powershell
# 1) 生成合成向量（boot9/OTP/CID/NCSD，含 oracle 期望输出）
python tests\make_testvectors.py

# 2) 三端交叉验证（PS1 + Python；带上 Java jar 则三端）
#    对三端的调用统一使用与 PS1 一致的参数名（-NandFile 等）；
#    Java 不经 --cli 前缀直接调用，验证 jar 的 CLI 入口本身。
#    注意：jar 是本地构建产物（不入库），运行前先执行 java\build.bat。
powershell -ExecutionPolicy Bypass -File tests\run_crosscheck.ps1
powershell -ExecutionPolicy Bypass -File tests\run_crosscheck.ps1 -JavaJar java\DecryptCTRNandGUI.jar
```

退出码 0 = 全部通过。

## Java 11 构建（jar 为本地产物，不入库）

```cmd
java\build.bat
```

产物：`java\DecryptCTRNandGUI.jar`（`javac --release 11` 编译，Java 11 字节码；Main-Class manifest）。**jar 是编译产物，已加入 `.gitignore`（`*.jar`）不随仓库提交**——克隆仓库后先本地构建再使用。**分发/使用只需这一个 jar**：双击即 GUI、`java -jar ... -NandFile ...` 即 CLI，无需任何启动器。

## 方案依据

- 3dbrew: CTR_NAND, OTP_Registers, AES_Registers
- pyctr (github.com/ihaveamac/pyctr) — crypto/engine.py (MIT License)
- decrypt9 / GodMode9 源码

## 敏感口径

- OTP / CID / movable.sed / normalKey 等 per-console 敏感字段仅用于解密与验证，默认不展示明文（`-ShowKeys` 显式开启才显示）
- 输出文件名使用通用名，不含原始序列号
