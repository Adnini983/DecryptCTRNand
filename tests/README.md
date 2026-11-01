# tests/ — 合成向量与三端交叉验证

本目录只包含**合成**测试资产：没有任何真机 NAND dump、OTP、CID 或派生密钥。
真机素材与基线仅保存在本地（不入库），见 `DEVELOPMENT.md` 的「验证状态」。

## 目录

| 路径 | 入库 | 说明 |
|---|---|---|
| `make_testvectors.py` | ✅ | 合成 boot9 / OTP / CID / NCSD 向量生成器（确定性 LCG，可复现） |
| `run_crosscheck.ps1` | ✅ | 三端（PS1 / Python / Java）逐字节交叉验证 + 负向用例 |
| `expected/` | ✅ | 固定 oracle（期望解密结果），回归时作为基准比对 |
| `vectors/` | ❌（生成） | 合成 NAND / boot9 / OTP / CID；`make_testvectors.py` 确定性重建 |
| `out/` | ❌（临时） | 每次运行的输出与负向用例日志，可随时删除 |

## 运行

```powershell
# 1) 生成合成向量（需要 pycryptodome；会重建 vectors/ 与 expected/）
python tests\make_testvectors.py

# 2) 交叉验证（PS1 + Python）
powershell -ExecutionPolicy Bypass -File tests\run_crosscheck.ps1

# 3) 三端交叉验证（需先 java\build.bat 构建 jar）
powershell -ExecutionPolicy Bypass -File tests\run_crosscheck.ps1 -JavaJar java\DecryptCTRNandGUI.jar
```

退出码 0 = 全部通过。`run_crosscheck.ps1` 会先调用生成器，因此 `vectors/` 缺失也能直接跑。

## 覆盖范围

- dev / retail 两套密钥；NCSD 覆盖 slot 0x03(TWL) / 0x04 / 0x05 / 0x06 / 0x07 全部映射；
- 三端输出与 `expected/` 逐字节比对，且三端互相比对；
- TWL 5 组边界切片（MBR 非对齐头、跨 counter block、加密区结束、FAT 起始、单块）；
- `-OtpDecrypted` 路径；
- 负向用例：拒绝覆盖、dev flag 与模式不一致、截断 NAND、非法 CID、**失败时旧输出逐字节不变且不残留 `.tmp`**、**重复 TWL 分区被拒**、**TWL 非零偏移被拒**。

## 已知局限（重要）

1. **合成测试是自洽的**：生成器复用 `DecryptCTRNand.py` 的 TWL 原语来加密向量。因此
   TWL 密码学若存在**对称性**错误，三端仍会全部通过。真正的算法锚点是
   `DEVELOPMENT.md` 中的真机基线（与 pyctr / 实机 dump 逐字节对照）。
2. `expected/` 中的非 TWL 分区来自独立明文，TWL 分区则由「原始 NAND 的 raw 区 + 已知明文区」拼装，
   用于覆盖 raw/加密区边界行为，而不是独立的第三方实现。
3. 向量为固定种子的确定性数据，不含任何真实设备信息。
