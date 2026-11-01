# DecryptCTRNand — 开发与验证细节

> 本文档收录 README 之外的全部内容（版本历史、变更对照、运行环境、验证状态、测试、限制与安全口径）。
> README 仅保留「简介 / 使用 / 编译 / 许可」四个板块。
>
> **敏感口径**：本文档不出现任何明文设备序列号与密钥明文；实机条目中的设备 SN 一律以「SN 已打码」占位。

## 版本历史

- **2.1.1（当前源码，未发布）**：并发输出安全与提交语义加固（三端同构）：临时文件改为随机唯一命名（`<out>.<guid>.tmp`）；未 `-Force` 时提交阶段**不覆盖**已存在的输出（PS1 `File::Move` 失败即报错、Python `os.link` + `os.unlink`、Java 不带 `REPLACE_EXISTING` 的 `Files.move`）；PS1 非原子回退改用唯一 `.bak` 名，不再删除用户已有的 `<out>.bak`；TWL twln FAT boot 检查边界 `>` → `>=`（恰好 `0x13000` 字节的分区不再被跳过）；Java TWL 路径补 `finally` 清理 `.tmp`；GUI 拒绝两个运行中任务共用同一输出目录，取消后显示「已取消」而非「错误」；三端 banner / GUI 标题 / CLI 帮助统一为 2.1.1。明细见「2.1.1 变更」。
- **2.1.0（已发布，tag `2.1.0` = `149a64d`）**：第二轮审计修复（P0/P1/P2/P3），明细见「2.1.0 审计修复（第二轮）」。**注意**：2.1.0 的源码 banner 仍打印 2.0，且 README 当时未同步——这正是 2.1.1 统一版本号的起因。
- **2.0（tag `2.0.0` = `7f18716`，发布资产为修复前版本）**：新增 **TWL 分区解密**（NCSD crypttype 1 → slot 0x03，SHA1(CID) 反转 nonce + TWL keyscrambler + 块内字节反转 CTR；**dev 开发机必须使用 raw OTP（otp.mem/.bin），otp_dec 无法解出正确的 TWL 密钥**——已在真机 dump 实证）。版本号由 1.0 修正为 2.0（此前外部审计误把 1.0 读成 0.1）。**修复：零售 TWL keyX 中间 8 字节 "NINTENDO" 的 LE 打包常量错误**（真机零售 OTP 暴露，dev 分支不受影响）。
- **1.0（v0.2 加固版）**：依据外部代码审计系统性加固正确性/输入验证/输出验证/安全，并新增纯 JDK 11 GUI 实现与合成测试向量三端交叉验证。
- **v0.1**：初版（PowerShell），已在用户实机 dump 上验证（见「验证状态」）。

### 2.0 变更

| 项目 | 2.0 处理 |
|------|------|
| TWL 分区解密 | 新增 slot 0x03 完整实现（PS1/Python/Java 三端）：NCSD crypttype 1 → TWL；nonce = SHA1(CID)[:16] 字节反转；keyscrambler = ROL42((keyX_LE ^ keyY_LE) + TWL_CONST)，16 字节 BE 输出；CTR 每块 keystream 块内反转后 XOR；counter 按绝对 16 字节块计（nonce + (abs >> 4)），加密范围 [0x1BE:0x200)（MBR，起点非 16 对齐）+ [0x12E00:end)（twln FAT16 + twlp FAT12），其余原样拷贝 |
| TWL dev 密钥必须用 raw OTP | dev CustId = **raw（加密）OTP[0:8] 小端**；otp_dec.mem 解不出正确 TWL 密钥（真机实证）。`-OtpDecrypted` 路径会先把明文 OTP 用 OTP normalKey 重加密回 raw 再派生态 TWL 密钥 |
| TWL 结构校验 | blk0x1D 锚点 @ 输出 +0x1D0、MBR 55AA @ +0x1FE、twln FAT boot 55AA @ +0x12E00+0x1FE（OEM `TWL     `） |
| 版本号 | 由 1.0 修正为 **2.0**（外部审计误把 1.0 读成 0.1；若按 0.x 口径应为 0.2 族，故新版本为 2.0） |
| `DecryptCTRNandGUI.bat` | 已删除（不再需要任何启动器；双击 jar 即 GUI） |
| GUI 修复 | 移除全部「浏览…」按钮，路径输入框仅保留文本输入（可拖放）；对应 i18n 键清理；新增工具栏「批量解密」按钮（一键启动所有已配置且未在运行的标签页任务） |

### 2.1.0 审计修复（第二轮，P0/P1/P2/P3）

| 审计项 | 处理（PS1 / Python / Java 三端） |
|------|------|
| P0 `-Force` 提前删除旧输出 | 一律改为：先写独立 `.tmp` → 结构校验 + SHA-256 → 最后原子替换提交；替换失败保留旧文件。PS1 新增 `Commit-TempFile`（`[IO.File]::Replace` 优先，非 NTFS 回退「旧→.bak、tmp→out、.bak 删除，swap 失败恢复」）；Python 用 `os.replace`；Java 用 `Files.move(ATOMIC_MOVE)` 回退 `REPLACE_EXISTING`。提前 `Remove-Item`/`os.remove`/`Files.delete` 旧文件逻辑全部移除 |
| P0 TWL 分区位置约束 | NCSD 解析后强制：TWL 分区必须**唯一**、**索引 0**、**绝对偏移 0**，否则直接拒绝解密（MBR/blk0x1D/twln 校验与 counter 坐标系均假设偏移 0，非法布局不再继续尝试） |
| P1 完整读取语义 | Python 新增通用 `read_exact()`（循环读满，EOF 抛 `EOFError`→`ValueError` 带段名）；Java 四处 NAND 读取 + NCSD 头改 `readFully()` + `EOFException`（区分真实截断与其他 I/O 错误）；PS1 已有 `ReadExactly` 循环 |
| P1 crypttype=3 限 fstype | `crypt=1` 仅允许 `fs=1`（TWL）；`crypt=3` 仅允许 `fs=1`（New3DS CTRNAND slot05）；其余组合拒绝。与真机 NCSD 实证一致（RW/零售 p0 fs=1+crypt=1、p4 fs=1+crypt=2/3）。合成向量同步修正：TWL 的 fs 由自造约定 0x02 改为真机一致的 0x01 |
| P1 CTR 非对齐尾块 | Java `aesCtrCrypt` 取消 `%16` 拒绝，改按 `(len+15)/16` 块生成 keystream、只异或 `len` 字节——三端统一支持最后不足 16 字节块 |
| P2 TWL FAT OEM 断言 | twln boot 55AA 之外，真正断言 8 字节 OEM == `TWL     `（此前仅打印）；错误信息区分「55AA missing」与「OEM != TWL」 |
| P2 FIRM0/FIRM1 识别 | NCSD 日志按出现顺序标注 `role=FIRM0/FIRM1/FIRMn`（pyctr `firm_count` 语义；映射仍 slot 0x06） |
| P2 合成向量边界切片 | crosscheck 新增 5 组 TWL 边界比对：0x1BE-0x1FF（MBR 非对齐头）、0x1F0-0x20F（跨 counter block）、0x1F8-0x207（加密区结束切回原文）、0x12E00-0x12E1F（FAT 起始）、0x12E00-0x12E0F（单块） |
| P3 Python `-Mode` 大小写 | `args.mode = args.mode.lower()` 置于校验前（`-Mode DEV` 兼容，与 PS1 ValidateSet / Java toLowerCase 一致） |
| P3 Java GUI 取消语义 | SHA-256 循环内逐块检查取消标志（`fileSha256(..., cancelable, cancelled)`）+ 提交前再查一次；TWL 校验/提交阶段同样检查 |

> 密钥派生、nonce、CTR 块内反转公式本轮审计静态对照无错误，未改动；所有修复均为工程/校验/安全语义，密码学结果应与修复前逐字节一致（见「验证状态」）。

### 2.1.1 变更（并发 / 提交安全）

| 审计项 | 2.1.1 处理（PS1 / Python / Java 三端） |
|------|------|
| 多任务共用输出目录（GUI 多标签、多进程） | 临时文件改为随机唯一名 `<out>.<guid>.tmp`：两个任务不会再互相 truncate / 删除对方正在写的 `.tmp`。GUI 启动任务时检查目标目录是否已被其他运行中任务占用，冲突即拒绝并提示 |
| 未 `-Force` 仍可能覆盖（检查与提交间的 TOCTOU） | 提交阶段重新判定，不再只依赖开跑前的一次存在性检查：PS1 `[IO.File]::Move`（目标存在则失败）、Python `os.link` + `os.unlink`（存在则 `FileExistsError`）、Java 不带 `REPLACE_EXISTING` 的 `Files.move`（实测抛 `FileAlreadyExistsException`）；只有 `-Force` 才走替换路径 |
| PS1 非原子回退删除用户 `.bak` | 备份名改为 `<out>.bak.<guid>`，只在本次回退内创建和删除，绝不删除用户原有的 `<out>.bak` |
| twln FAT 检查漏判（`>` vs `>=`） | 分区恰好 `0x12E00 + 0x200 = 0x13000` 字节时也执行 FAT boot 校验（三端统一为 `>=`） |
| Java TWL 路径失败残留 `.tmp` | `decryptTwlPartition` 外层加 `try/finally`，任何异常或取消都会删除本次 `.tmp`；同时移除结构校验分支里重复的清理语句 |
| GUI 取消被显示为错误 | `done()` 在 `ExecutionException` 分支先判断取消标志，显示「已取消」而非「错误」 |
| 版本号自相矛盾 | 三端 banner / GUI 标题 / CLI 帮助统一由常量 `VERSION = "2.1.1"` 输出，不再写死 2.0 |

> 以上均为工程与提交语义改动，密码学路径未改；合成向量三端结果与 2.1.0 逐字节一致（见「验证状态」）。

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

> 注意：PS1 脚本需在 **Windows PowerShell 5.1**（`powershell.exe`）下运行；PowerShell 7（pwsh）的 `Add-Type` 内联 C# 因 .NET 程序集引用差异可能编译失败，属运行环境差异而非脚本缺陷。

## 完整性/安全说明（如实口径）

- **结构校验 ≠ 密码学认证**：AES-CTR 不提供完整性保护。MBR 55AA（2 字节）与 FIRM magic（4 字节）只是合理性检查；完整分区正确性以「与可信实现逐字节比对 / SHA-256 一致」为准（见「测试」）。
- 早期版本声称的 **CTR 卷标校验从未实现，v0.2 已明确取消该断言**。
- 密钥与 CID 为 per-console 敏感材料：默认不显示、不落盘。

## 验证状态

### 实机验证

| 平台 | 模式 | 状态 |
|------|------|------|
| Old3DS devkit（SN 已打码） | dev | ✅ v0.1 端到端验证通过（OTP 解密、NCSD 5 分区、CTRNAND MBR 55AA、firm0 FIRM magic） |
| New3DS retail（SN 已打码） | retail | ✅ v0.1 端到端验证通过（CTRNAND MBR 55AA） |
| New3DS XL devkit "Louvre"（SN 已打码） | dev | ✅ **2.0 全分区端到端验证通过**（TWL 分区：raw OTP 派生、twln FAT16 / twlp FAT12 / MBR 55AA / blk0x1D 锚点 PASS；p2/p3 FIRM magic PASS；p4 CTRNAND MBR 55AA PASS；`otp_dec.mem` 解不出正确 TWL 密钥——实证） |
| Old3DS devkit（SN 已打码） | dev | ✅ **2.0 三端（PS1/Python/Java）全分区 PASS**（TWL raw OTP、MBR/blk0x1D/twln 三锚点 PASS；p2/p3 FIRM magic PASS；p4 CTRNAND MBR 55AA PASS；5 分区 SHA-256 三端逐字节一致） |
| New3DS LL retail（SN 已打码） | retail | ✅ **2.0 三端（PS1/Python/Java）全分区 PASS**（TWL 三锚点 PASS；p2/p3 FIRM magic PASS；p4 crypt3→slot05 CTRNAND MBR 55AA PASS；5 分区 SHA-256 三端逐字节一致；零售 TWL keyX 字节序修复后复测通过） |

**第二轮审计修复后复测（2.1.0）**：上表两机（Old3DS devkit / New3DS LL retail）三端全分区重跑，5 分区 SHA-256 三端逐字节一致，且与修复前输出**逐字节相同**（审计修复仅涉及工程/校验/安全语义，密码学结果零回归）；TWL FAT OEM `TWL     ` 断言、FIRM0/FIRM1 角色标注在真机日志中均 PASS。

**2.1.1 回归（合成向量，本轮）**：三端（PS1 / Python / Java）对 dev / retail 两套向量 5 分区全部逐字节一致，TWL 5 组边界切片全 PASS，`-OtpDecrypted` PASS；新增负向用例（失败时旧输出逐字节不变且不残留 `.tmp`、重复 TWL 分区被拒、TWL 非零偏移被拒）三端全 PASS。2.1.1 未改动密码学路径，**本轮未重跑真机 dump**（本机无真机素材），真机基线以上表为准。

### 合成向量三端交叉验证（`tests/`，合成套件随仓库公开）

- `tests/` 只公开**合成**资产（`make_testvectors.py`、`run_crosscheck.ps1`、`expected/` 固定 oracle）；`vectors/` 由生成器确定性重建、`out/` 为运行产物，两者被忽略；真机 dump / OTP / CID 一律不入库。用法与局限见 `tests/README.md`；
- 构造含全部槽位映射的合成 NAND（CTRNAND slot04、FIRM slot06、AGB slot07、TWL slot03、New3DS CTRNAND slot05），dev / retail 各一套；TWL 分区 fs 类型与真机一致（0x01）；
- **PS1、Python、Java 三端解密输出与 oracle 逐字节一致**，且三端互为一致；
- 审计建议的 5 组 TWL 边界切片（0x1BE-0x1FF / 0x1F0-0x20F / 0x1F8-0x207 / 0x12E00-0x12E1F / 0x12E00-0x12E0F，覆盖 MBR 非对齐头、跨 counter block、加密区结束切回原文、FAT 起始）三端 × dev/retail 全部 PASS；
- `-OtpDecrypted` 路径输出一致；
- 负向用例通过：无 `-Force` 拒绝覆盖、零售模式拒绝 dev OTP（dev flag 一致性）、截断 NAND 拒绝、非法 CID hex 拒绝；**失败时旧输出逐字节不变且不残留 `.tmp`**、**重复 TWL 分区被拒**、**TWL 非零偏移被拒**（2.1.1 新增，三端）。
- **局限（务必知悉）**：生成器复用工具自身的 TWL 原语加密向量，属于自洽测试；TWL 密码学的对称性错误不会被该套件发现，真机基线才是算法锚点。

## 已知限制

- **CID 依赖**：AES-CTR nonce = SHA256(CID)[:16]，128 位不可暴力破解。CID 是 eMMC 芯片出厂值，不在 OTP 内，必须从实机 dump 获取。
- **TWL dev 必须 raw OTP**：dev 开发机的 TWL CustId 取 **raw（加密）OTP[0:8]**；若手头只有 `otp_dec.mem`，工具会自动用 OTP normalKey 重加密回 raw 再派生（无需手工操作）。
- **组件级解析**：仅完成解密与结构验证（MBR / FIRM magic / TWL 锚点），NAND FS 挂载与文件系统级分析需后续工具。
- **NCSD 尺寸警告**：真机 NAND 的 NCSD 头声明名义大小（O3DS 0x40000000 / N3DS 0x50000000）大于实际镜像（0x3AF00000 / 0x4D800000），工具会提示「dump may be truncated」——对完整真机 dump 属误报，解密不受影响。
- **并发/提交语义**：未 `-Force` 时提交是「不覆盖」语义（先到者胜，后者报错且不改动已有文件）；`-Force` 下同一路径的并发写属于最后提交者胜出，工具不提供跨进程锁。GUI 内部会拒绝两个运行中任务共用同一输出目录。

## 测试（合成套件随仓库公开）

`tests/` 只提交**合成**资产：生成器、交叉验证脚本与固定 oracle（`expected/`）；`vectors/` 可由生成器确定性重建、`out/` 为运行产物，二者被 `.gitignore` 忽略。真机 dump / OTP / CID 等素材不入库。详见 `tests/README.md`。

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

退出码 0 = 全部通过。负向用例额外覆盖：失败时旧输出逐字节不变且无 `.tmp` 残留、重复 TWL 分区、TWL 非零偏移（2.1.1 新增）。

## 敏感口径

- OTP / CID / movable.sed / normalKey 等 per-console 敏感字段仅用于解密与验证，默认不展示明文（`-ShowKeys` 显式开启才显示）
- 输出文件名使用通用名，不含原始序列号
- 文档（README / DEVELOPMENT）不包含任何明文设备 SN 与密钥明文；设备条目统一以「SN 已打码」占位
