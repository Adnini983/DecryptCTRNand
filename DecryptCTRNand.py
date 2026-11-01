#!/usr/bin/env python3
"""
decrypt3dsnand 2.1.1 - 3DS NAND Dump Decryptor (Pure Python)

Decrypt 3DS NAND dumps using plaintext boot9 + OTP + eMMC CID.
Dependencies: pycryptodome (Crypto.Cipher.AES)

v2.1.1 (concurrency / commit safety, kept in sync with DecryptCTRNand.ps1):
  * Temp files get a unique per-run name (<out>.<uuid>.tmp), so two tasks
    writing the same output directory cannot truncate/delete each other's
    in-flight .tmp file.
  * Publishing without -Force is no-clobber: the file is committed with
    os.link() (atomic, fails with FileExistsError if the name appeared
    meanwhile) instead of os.replace(), which would silently overwrite.
  * The twln FAT boot check no longer skips a partition of exactly
    0x12E00 + 0x200 bytes (boundary is now >=).

v2.0 (kept in sync with DecryptCTRNand.ps1):
  * keyinit() now receives dev/retail from --mode (was hardcoded dev=True, which
    broke retail key derivation).
  * --otp-dec plaintext is ALWAYS validated (DEADB00F magic + SHA256 + dev flag
    vs --mode), same as the encrypted path.
  * Strict input length validation (boot9 / OTP / CID).
  * NCSD partition table boundary/overlap checks; unknown crypt/fs combos are
    refused instead of defaulting to a guessed AES slot.
  * Full AES-CTR partition decryption implemented (--outdir), with MBR 55AA /
    FIRM magic structural checks, actual-byte-count verification, per-partition
    SHA-256 record, and .tmp -> rename commit.
  * Overwrite protection (--force required to overwrite).
  * CID / normalKeys hidden by default; use --show-keys to display.

Usage (parameters identical to DecryptCTRNand.ps1, case-insensitive):
    python DecryptCTRNand.py -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp.mem \
        -CidFile nand_cid.mem -Mode dev -OutDir out/
    python DecryptCTRNand.py -NandFile sysnand.bin -Boot9File boot9.bin -OtpFile otp_dec.mem \
        -OtpDecrypted -CidHex 8FA3544A... -Mode retail -OutDir out/ -Force -ShowKeys
    Legacy aliases still accepted: --nand --boot9 --otp --cid --cid-file --outdir
    --mode --otp-dec --force --show-keys.
"""

import argparse
import hashlib
import os
import struct
import sys
import uuid

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    sys.exit("[!] pycryptodome is required: pip install pycryptodome")

# === Constants ===
VERSION = "2.1.1"
# 3DS AES key scrambler C1 constant (reverse-engineered from dev slot0x2C)
C1 = int.from_bytes(bytes.fromhex("1FF9E9AAC5FE0408024591DC5D52768A"), byteorder='big')
MASK_128 = (1 << 128) - 1
OTP_MAGIC = bytes.fromhex("0FB0ADDE")
CHUNK_SIZE = 0x100000
# Fixed CTRNANDNew KeyY (dev/retail same), not stored in the keyblob
FIXED_KEYY_CTRNAND_NEW = bytes.fromhex("4D804F4E9990194613A204AC584460BE")

# TWL (DSi NAND, slot 0x03) constants
TWL_SCRAMBLE_CONST = int.from_bytes(
    bytes.fromhex("FFFEFB4E295902582A680F5F1A4F3E79"), byteorder='big')  # DSi keyscrambler additive
KEYY_TWL_DEV = bytes.fromhex("AABF76F17AB8E86697646A260500A0E1")       # Luma3DS key3YDev
KEYY_TWL_RETAIL = bytes.fromhex("76DCB90AD3C44DBD1DDD2D200500A0E1")    # fixed retail KeyY
# Universal TWL anchor: absolute block 0x1D ([0x1D0:0x1E0)) decrypts to this constant
TWL_BLK1D_ANCHOR = bytes.fromhex("8e400601a0c38d800400b30501000000")
# TWL MBR signature region + FAT boot area start (DSi-standard layout)
TWL_MBR_START = 0x1BE
TWL_FAT_START = 0x12E00


# === Crypto primitives ===
def rol128(data: bytes, n: int) -> bytes:
    """128-bit rotate left (big-endian)."""
    val = int.from_bytes(data, byteorder='big')
    result = ((val << n) | (val >> (128 - n))) & MASK_128
    return result.to_bytes(16, byteorder='big')


def ror128(data: bytes, n: int) -> bytes:
    """128-bit rotate right (big-endian)."""
    return rol128(data, 128 - n)


def scramble(keyx: bytes, keyy: bytes) -> bytes:
    """3DS AES key scrambler: (((KeyX ROL 2) XOR KeyY) + C1) ROR 41 (== pyctr rol 87)."""
    kx_rol2 = rol128(keyx, 2)
    xor = bytes(a ^ b for a, b in zip(kx_rol2, keyy))
    xor_int = int.from_bytes(xor, byteorder='big')
    sum_int = (xor_int + C1) & MASK_128
    sum_bytes = sum_int.to_bytes(16, byteorder='big')
    return ror128(sum_bytes, 41)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def aes_ctr_crypt(key: bytes, counter: bytes, data: bytes) -> bytes:
    """AES-CTR with an explicit 16-byte big-endian starting counter block."""
    cipher = AES.new(key, AES.MODE_CTR,
                     counter=Counter.new(128, initial_value=int.from_bytes(counter, 'big')))
    return cipher.decrypt(data)  # CTR decrypt == encrypt


def read_exact(f, n: int) -> bytes:
    """Read exactly n bytes or raise EOFError. read(n) is not guaranteed to fill
    the buffer even when the stream has more data, so loop until done/real EOF."""
    out = bytearray()
    while len(out) < n:
        chunk = f.read(n - len(out))
        if not chunk:
            raise EOFError(f"unexpected EOF: wanted {n} bytes, got {len(out)}")
        out += chunk
    return bytes(out)


def add_counter(nonce: bytes, blocks: int) -> bytes:
    """nonce (16B BE) + blocks, truncated to 128 bits."""
    val = (int.from_bytes(nonce, 'big') + blocks) & MASK_128
    return val.to_bytes(16, 'big')


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().upper()


def temp_path(out_file: str) -> str:
    """Unique per-run temp path: two tasks may target the same output directory."""
    return f"{out_file}.{uuid.uuid4().hex}.tmp"


def commit_file(tmp_file: str, out_file: str, force: bool) -> None:
    """Publish tmp_file as out_file: replace only with -Force, otherwise refuse.

    os.replace() always overwrites, so the no-clobber path uses a hard link: it
    is atomic and raises FileExistsError if the target appeared in the meantime.
    """
    if force:
        os.replace(tmp_file, out_file)
        return
    try:
        os.link(tmp_file, out_file)
    except FileExistsError:
        raise FileExistsError(
            f"Output already exists: {out_file}. Re-run with -Force to overwrite.")
    except OSError:
        # Filesystem without hard-link support: narrow the race window, then
        # fall back to a checked replace.
        if os.path.exists(out_file):
            raise FileExistsError(
                f"Output already exists: {out_file}. Re-run with -Force to overwrite.")
        os.replace(tmp_file, out_file)
        return
    os.unlink(tmp_file)


# === Input validation ===
def validate_otp(plain: bytes, mode: str, desc: str) -> None:
    """Unified OTP plaintext validation: length + magic + SHA256 + dev flag vs mode."""
    if len(plain) != 0x100:
        raise ValueError(f"OTP {desc}: expected exactly 0x100 (256) bytes, got {len(plain)}")
    if plain[0:4] != OTP_MAGIC:
        raise ValueError(f"OTP {desc}: DEADB00F magic not found. Not a valid (decrypted) OTP, or wrong mode key.")
    digest = sha256(plain[0:0xE0])
    if digest != plain[0xE0:0x100]:
        raise ValueError(f"OTP {desc}: SHA256 integrity check failed")
    dev_flag = plain[0x19]
    otp_is_dev = (dev_flag != 0)
    mode_is_dev = (mode == "dev")
    if otp_is_dev != mode_is_dev:
        raise ValueError(
            f"OTP {desc}: dev flag byte 0x{dev_flag:02X} inconsistent with --mode {mode}; "
            "refusing to derive keys with mismatched keyblob")
    print(f"    OTP dev flag: 0x{dev_flag:02X} (consistent with --mode {mode})")


def load_boot9(path: str) -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) not in (0x10000, 0x8000):
        raise ValueError(f"boot9: expected 0x10000 (64KB) or 0x8000 (32KB) bytes, got {len(data)}")
    return data


def load_otp(path: str) -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) != 0x100:
        raise ValueError(f"OTP: expected exactly 0x100 (256) bytes, got {len(data)}")
    return data


def load_cid(cid_hex: str, cid_file: str) -> bytes:
    if cid_file:
        with open(cid_file, 'rb') as f:
            cid = f.read()
        if len(cid) != 16:
            raise ValueError(f"CID file: expected exactly 16 bytes, got {len(cid)}")
        print("\n[+] CID loaded from file (16 bytes, hidden)")
        return cid
    if cid_hex:
        if len(cid_hex) != 32 or any(c not in '0123456789abcdefABCDEF' for c in cid_hex):
            raise ValueError(f"CID hex: expected exactly 32 hex characters, got '{cid_hex}'")
        print("\n[+] CID from hex (hidden)")
        return bytes.fromhex(cid_hex)
    print("\n[!] No CID provided.")
    print("    NAND AES-CTR nonce = SHA256(CID)[:16], 128-bit, cannot brute-force.")
    print("    Please provide --cid or --cid-file.")
    sys.exit(1)


# === OTP decryption ===
def decrypt_otp(otp_raw: bytes, boot9: bytes, mode: str) -> bytes:
    """Decrypt OTP with the mode's key/IV from boot9, then validate."""
    otp_base = 0x8000 if len(boot9) == 0x10000 else 0
    if mode == "dev":
        nk_off, iv_off = otp_base + 0x5700, otp_base + 0x5710
    else:
        nk_off, iv_off = otp_base + 0x56E0, otp_base + 0x56F0
    nk = boot9[nk_off:nk_off + 16]
    iv = boot9[iv_off:iv_off + 16]
    plain = aes_cbc_decrypt(nk, iv, otp_raw)
    validate_otp(plain, mode, "decrypted")
    print(f"[+] OTP decrypted successfully ({mode})")
    return plain


# === NCSD parsing ===
def parse_ncsd(nand_path: str, nand_len: int) -> list:
    """Parse NCSD header and partition table with boundary/overlap checks."""
    with open(nand_path, 'rb') as f:
        header = f.read(0x200)
    if len(header) < 0x200:
        raise ValueError(f"NAND: truncated NCSD header (read {len(header)} of 0x200 bytes)")

    magic = header[0x100:0x104]
    if magic != b'NCSD':
        raise ValueError(f"NCSD magic not found at +0x100. Got: {magic.hex()}")

    print("[+] NCSD magic found at +0x100")

    ncsd_size_units = struct.unpack_from("<I", header, 0x104)[0]
    if ncsd_size_units != 0 and ncsd_size_units * 0x200 > nand_len:
        print(f"    [!] NCSD header declares size > file length; dump may be truncated")

    partitions = []
    firm_count = 0
    for i in range(8):
        fstype = header[0x110 + i]
        crypttype = header[0x118 + i]
        offset_units, size_units = struct.unpack_from("<II", header, 0x120 + i * 8)

        if fstype == 0 and crypttype == 0:
            continue

        abs_offset = offset_units * 0x200
        abs_size = size_units * 0x200

        if abs_offset < 0x200 and crypttype != 1:
            print(f"    [!] Partition {i}: bogus offset 0x{abs_offset:X} (overlaps NCSD header), skipped")
            continue
        if abs_size == 0:
            print(f"    [!] Partition {i}: zero size, skipped")
            continue
        if abs_offset + abs_size > nand_len:
            raise ValueError(
                f"Partition {i}: offset+size 0x{abs_offset + abs_size:X} exceeds NAND file length "
                f"0x{nand_len:X}; dump truncated or partition table corrupt")

        # --- AES slot mapping (rule-based; refuses unknowns) ---
        # crypt 0x01: fs 0x01 = TWL             -> slot 0x03 (dedicated nonce/key scheme)
        # crypt 0x02: fs 0x01 = Old3DS CTRNAND  -> slot 0x04
        #             fs 0x03 = FIRM            -> slot 0x06
        #             fs 0x04 = AGB_FIRM save   -> slot 0x07
        # crypt 0x03: fs 0x01 = New3DS CTRNAND  -> slot 0x05
        # (pyctr identifies partitions by fs type first, then encryption type;
        #  unknown fs/crypt combinations are refused, not guessed.)
        slot = 0
        status = "decrypt"
        if crypttype == 1:
            if fstype == 1:
                slot = 0x03
                status = "twl"
            else:
                status = "unknown"
        elif crypttype == 2:
            if fstype == 1:
                slot = 0x04
            elif fstype == 3:
                slot = 0x06
            elif fstype == 4:
                slot = 0x07
            else:
                status = "unknown"
        elif crypttype == 3:
            if fstype == 1:
                slot = 0x05
            else:
                status = "unknown"
        else:
            status = "unknown"

        if status == "unknown":
            print(f"    [!] Partition {i}: unsupported combo fs=0x{fstype:02X} crypt=0x{crypttype:02X} - not decrypting")

        partitions.append({
            "index": i, "fstype": fstype, "crypttype": crypttype,
            "offset": abs_offset, "size": abs_size,
            "slot": slot, "status": status,
        })

        # FIRM partitions are identified by occurrence order (FIRM0, FIRM1),
        # mirroring pyctr's firm_count handling. Both still decrypt with slot 0x06.
        role_txt = ""
        if fstype == 3:
            role_txt = {0: ", role=FIRM0", 1: ", role=FIRM1"}.get(firm_count, f", role=FIRM{firm_count}")
            firm_count += 1

        slot_txt = "--" if status == "unknown" else f"0x{slot:02X}"
        print(f"    Partition {i}: slot={slot_txt} offset=0x{abs_offset:08X} size=0x{abs_size:08X} [{status}{role_txt}]")

    # overlap check
    for a in range(len(partitions)):
        pa = partitions[a]
        for b in range(a + 1, len(partitions)):
            pb = partitions[b]
            if not (pa["offset"] + pa["size"] <= pb["offset"] or
                    pb["offset"] + pb["size"] <= pa["offset"]):
                raise ValueError(
                    f"Partition table overlap: partition {pa['index']} and partition {pb['index']}")

    # --- TWL placement constraints (P0) ---
    # The TWL decrypt coordinate system assumes the partition starts at NAND
    # absolute offset 0 (encrypted ranges [0x1BE:0x200) + [0x12E00:end), with the
    # MBR / blk0x1D / twln FAT checks computed from output offset 0). Reject any
    # NCSD layout that breaks this assumption instead of producing garbage.
    twl_parts = [p for p in partitions if p["status"] == "twl"]
    if len(twl_parts) > 1:
        raise ValueError(
            "NCSD: multiple TWL partitions found (indexes "
            + ", ".join(str(p["index"]) for p in twl_parts) + "); expected exactly one.")
    if len(twl_parts) == 1:
        twl = twl_parts[0]
        if twl["index"] != 0 or twl["offset"] != 0:
            raise ValueError(
                f"NCSD: TWL partition must be index 0 with absolute offset 0 "
                f"(got index {twl['index']}, offset 0x{twl['offset']:X}); refusing to decrypt.")

    return partitions


# === Keyinit (ported from pyctr crypto/engine.py) ===
def keyinit(otp_plain: bytes, boot9: bytes, dev: bool) -> dict:
    """
    Derive console-unique normalKeys for NAND slots (0x04-0x07).
    dev/retail selects the keyblob offset inside the last-32KB region:
    retail = 0x5860, dev = 0x5C60.
    """
    if len(boot9) == 0x10000:
        b9 = boot9[0x8000:0x10000]
    else:
        b9 = boot9

    keyblob_offset = 0x5860 + (0x400 if dev else 0)

    b9_extdata_keygen = b9[keyblob_offset:keyblob_offset + 0x200]
    b9_extdata_otp = b9_extdata_keygen[0:0x24]

    # console_key_xy = SHA256(OTP_dec[0x90:0xAC] + b9_extdata_otp)
    otp_seed = otp_plain[0x90:0xAC]
    console_key_xy = sha256(otp_seed + b9_extdata_otp)

    slot3f_keyx = console_key_xy[0:16]
    slot3f_keyy = console_key_xy[16:32]
    slot3f_normalkey = scramble(slot3f_keyx, slot3f_keyy)

    # gen(): AES-CBC ENCRYPT with slot0x3F normal key
    extdata_off = 0

    def gen(n: int) -> bytes:
        nonlocal extdata_off
        extdata_off += 36
        iv = b9_extdata_keygen[extdata_off:extdata_off + 16]
        extdata_off += 16
        data = b9_extdata_keygen[extdata_off:extdata_off + 64]
        encrypted = aes_cbc_encrypt(slot3f_normalkey, iv, data)
        extdata_off += n
        return encrypted

    a = gen(64)
    slot04_07_keyx = a[0:16]

    keyblob = b9[keyblob_offset:keyblob_offset + 0x400]
    keyy_table = {
        0x04: keyblob[0x1F0:0x200],
        0x05: FIXED_KEYY_CTRNAND_NEW,  # New3DS CTRNAND KeyY is a fixed global value
        0x06: keyblob[0x210:0x220],
        0x07: keyblob[0x220:0x230],
    }

    result = {}
    for slot in range(0x04, 0x08):
        result[slot] = scramble(slot04_07_keyx, keyy_table[slot])
    return result


def derive_nonce(cid: bytes) -> bytes:
    """CTR nonce = SHA256(CID)[:16]."""
    return sha256(cid)[:16]


# === TWL (DSi NAND, slot 0x03) ===
def encrypt_otp(otp_plain: bytes, boot9: bytes, mode: str) -> bytes:
    """Re-encrypt plaintext OTP back to its raw (encrypted) form for TWL key derivation."""
    otp_base = 0x8000 if len(boot9) == 0x10000 else 0
    if mode == "dev":
        nk_off, iv_off = otp_base + 0x5700, otp_base + 0x5710
    else:
        nk_off, iv_off = otp_base + 0x56E0, otp_base + 0x56F0
    return aes_cbc_encrypt(boot9[nk_off:nk_off + 16], boot9[iv_off:iv_off + 16], otp_plain)


def scramble_twl(keyx: bytes, keyy: bytes) -> bytes:
    """DSi/TWL keyscrambler: ROL42(((kx_LE ^ ky_LE) + C) mod 2^128), result big-endian.

    Differs from the 3DS scramble (which uses ROL2/ROR41 with C1): TWL interprets
    keyX/keyY as little-endian integers and rotates the sum left by 42.
    """
    kx = int.from_bytes(keyx, byteorder='little')
    ky = int.from_bytes(keyy, byteorder='little')
    t = ((kx ^ ky) + TWL_SCRAMBLE_CONST) & MASK_128
    r = ((t << 42) | (t >> 86)) & MASK_128
    return r.to_bytes(16, byteorder='big')


def derive_twl_key(otp_enc: bytes, otp_plain: bytes, dev: bool) -> bytes:
    """Derive the TWL NAND (slot 0x03) normal key.

    dev   : CustId = RAW (encrypted) OTP[0:8]  little-endian  (otp_dec is WRONG here)
    retail: CustId = OTP_plain[8:16] ^ mask | 0x80000000
    """
    if dev:
        lo = int.from_bytes(otp_enc[0:4], byteorder='little')
        hi = int.from_bytes(otp_enc[4:8], byteorder='little')
        keyx = struct.pack('<IIII', lo, 0xEE7A4B1E, 0xAF42C08B, hi)
        keyy = KEYY_TWL_DEV
    else:
        lo = int.from_bytes(otp_plain[0x08:0x0C], byteorder='little')
        hi = int.from_bytes(otp_plain[0x0C:0x10], byteorder='little')
        lo = (lo ^ 0xB358A6AF) | 0x80000000
        hi = hi ^ 0x08C267B7
        keyx = struct.pack('<IIII', lo, 0x544E494E, 0x4F444E45, hi)  # "NINT" "ENDO"
        keyy = KEYY_TWL_RETAIL
    return scramble_twl(keyx, keyy)


def derive_twl_nonce(cid: bytes) -> bytes:
    """TWL nonce = SHA1(CID)[:16], byte-reversed (BE128 of LE128(SHA1(CID)[:16]))."""
    sh = sha1(cid)
    return bytes(sh[15 - i] for i in range(16))


def twl_ctr_crypt(normal_key: bytes, counter: bytes, data: bytes) -> bytes:
    """TWL CTR: AES-ECB(normal_key, BE128(counter)) keystream, applied byte-reversed per 16-byte block.

    The DSi AES engine operates on blocks in reversed byte order (pyctr _TWLCryptoWrapper),
    so data[i] ^= keystream[15-i] for every block. NOT interchangeable with aes_ctr_crypt.
    """
    n_blocks = len(data) // 16
    tail = len(data) % 16
    out = bytearray(len(data))
    if n_blocks:
        ctr_blocks = bytearray(n_blocks * 16)
        c = int.from_bytes(counter, byteorder='big')
        for i in range(n_blocks):
            ctr_blocks[i * 16:(i + 1) * 16] = c.to_bytes(16, byteorder='big')
            c += 1
        ks = AES.new(normal_key, AES.MODE_ECB).encrypt(bytes(ctr_blocks))
        for i in range(n_blocks):
            p = i * 16
            kb = ks[p:p + 16][::-1]  # byte-reversed keystream block
            out[p:p + 16] = (int.from_bytes(data[p:p + 16], 'big') ^
                             int.from_bytes(kb, 'big')).to_bytes(16, 'big')
    if tail:
        c = int.from_bytes(counter, 'big') + n_blocks
        ks = AES.new(normal_key, AES.MODE_ECB).encrypt(c.to_bytes(16, 'big'))
        for j in range(tail):
            out[n_blocks * 16 + j] = data[n_blocks * 16 + j] ^ ks[15 - j]
    return bytes(out)


def decrypt_twl_partition(nand_path: str, part: dict, twl_key: bytes, twl_nonce: bytes,
                          outdir: str, force: bool) -> None:
    """Decrypt a TWL NAND partition (NCSD p0, crypttype=0x01, slot 0x03).

    Only two ranges are AES-encrypted on the TWL region:
      [0x1BE:0x200)  - MBR partition table + boot signature (start is NOT 16-aligned)
      [0x12E00:end)  - twln (FAT16) + twlp (FAT12) + remainder
    Everything else (NCSD header/signature, DSi stage2 area) is copied raw.

    The TWL counter is per ABSOLUTE 16-byte block: counter(block at abs X) =
    nonce + (X >> 4). Because the first range starts at 0x1BE (block tail), the
    partial head is decrypted with the containing absolute block's keystream.
    """
    index = part["index"]
    out_file = os.path.join(outdir, f"partition_{index}_slot03.bin")
    tmp_file = temp_path(out_file)

    if os.path.exists(out_file):
        if not force:
            raise FileExistsError(f"Output already exists: {out_file}. Re-run with -Force to overwrite.")
        # -Force: old file is NOT removed here; commit_file() swaps it only after
        # the new file passed every check.
    if os.path.exists(tmp_file):
        os.remove(tmp_file)

    print(f"    Partition {index} (slot 0x03, TWL)... ", end="", flush=True)

    start = part["offset"]
    end = start + part["size"]
    enc_ranges = [(TWL_MBR_START, min(0x200, end)),
                  (max(TWL_FAT_START, start), end)]
    enc_ranges = [(s, e) for s, e in enc_ranges if s < e]

    def twl_decrypt_segment(pos: int, seg_end: int, nand, out) -> int:
        """Decrypt [pos, seg_end) with absolute-block counters; handles misaligned pos.
        Returns the number of bytes written."""
        seg_written = 0
        # partial head up to the next 16-byte boundary
        if pos & 15:
            head_end = min((pos + 15) & ~15, seg_end)
            n = head_end - pos
            nand.seek(pos)
            try:
                chunk = read_exact(nand, n)
            except EOFError:
                raise ValueError(f"Partition {index}: NAND truncated (TWL head)")
            block_base = pos & ~15
            block_ctr = add_counter(twl_nonce, block_base // 16)
            ks = AES.new(twl_key, AES.MODE_ECB).encrypt(block_ctr)
            rel = pos - block_base
            dec = bytes(chunk[j] ^ ks[15 - (rel + j)] for j in range(n))
            out.write(dec)
            seg_written += n
            pos = head_end
        # aligned bulk
        while pos < seg_end:
            to_read = min(CHUNK_SIZE, seg_end - pos)
            nand.seek(pos)
            try:
                chunk = read_exact(nand, to_read)
            except EOFError:
                raise ValueError(f"Partition {index}: NAND truncated (TWL range)")
            counter = add_counter(twl_nonce, pos // 16)
            out.write(twl_ctr_crypt(twl_key, counter, chunk))
            seg_written += len(chunk)
            pos += len(chunk)
        return seg_written

    written = 0
    try:
        with open(nand_path, 'rb') as nand, open(tmp_file, 'wb') as out:
            pos = start
            for (es, ee) in enc_ranges:
                # raw copy [pos, es)
                while pos < es:
                    to_read = min(CHUNK_SIZE, es - pos)
                    nand.seek(pos)
                    try:
                        chunk = read_exact(nand, to_read)
                    except EOFError:
                        raise ValueError(f"Partition {index}: NAND truncated (raw range)")
                    out.write(chunk)
                    written += len(chunk)
                    pos += len(chunk)
                # decrypt [es, ee)
                written += twl_decrypt_segment(es, ee, nand, out)
                pos = ee
            # tail raw copy
            while pos < end:
                to_read = min(CHUNK_SIZE, end - pos)
                nand.seek(pos)
                try:
                    chunk = read_exact(nand, to_read)
                except EOFError:
                    raise ValueError(f"Partition {index}: NAND truncated (tail range)")
                out.write(chunk)
                written += len(chunk)
                pos += len(chunk)

        if written != part["size"]:
            raise ValueError(f"Partition {index}: wrote {written} bytes but expected {part['size']}")

        # --- TWL structural checks ---
        with open(tmp_file, 'rb') as f:
            f.seek(TWL_MBR_START + 0x40)  # 0x1FE
            mbr_sig = f.read(2)
            f.seek(0x1D0)
            blk1d = f.read(16)
            if part["size"] >= TWL_FAT_START + 0x200:
                f.seek(TWL_FAT_START + 0x1FE)
                fat_sig = f.read(2)
                f.seek(TWL_FAT_START + 0x03)
                fat_oem = f.read(8)
            else:
                fat_sig = b'\x55\xAA'  # skipped: partition too small for twln boot
                fat_oem = b'<skipped>'

        notes = []
        if mbr_sig == b'\x55\xAA':
            notes.append("MBR 55AA OK")
        else:
            raise ValueError(f"Partition {index}: TWL MBR 55AA missing (wrong key/OTP?)")
        if blk1d == TWL_BLK1D_ANCHOR:
            notes.append("blk0x1D anchor OK")
        else:
            raise ValueError(f"Partition {index}: TWL block 0x1D anchor mismatch (wrong key/OTP?)")
        if part["size"] >= TWL_FAT_START + 0x200:
            if fat_sig == b'\x55\xAA' and fat_oem == b'TWL     ':
                notes.append("twln boot 55AA + OEM 'TWL     ' OK")
            else:
                raise ValueError(
                    f"Partition {index}: twln FAT boot 55AA missing or OEM != 'TWL     ' "
                    f"(got {fat_oem!r}, wrong offset?)")
        else:
            notes.append("twln boot check skipped (partition too small)")

        sha_hex = file_sha256(tmp_file)
        commit_file(tmp_file, out_file, force)

        print(f"saved ({part['size'] / 1048576:.1f} MB, wrote {written} bytes, {', '.join(notes)})")
        print(f"        SHA-256: {sha_hex}")
    finally:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)


# === Partition decryption ===
def decrypt_partition(nand_path: str, part: dict, normal_key: bytes, nonce: bytes,
                      outdir: str, force: bool) -> None:
    index = part["index"]
    slot = part["slot"]
    out_file = os.path.join(outdir, f"partition_{index}_slot{slot:02X}.bin")
    tmp_file = temp_path(out_file)

    if os.path.exists(out_file):
        if not force:
            raise FileExistsError(f"Output already exists: {out_file}. Re-run with -Force to overwrite.")
        # -Force: old file is NOT removed here; commit_file() swaps it only after
        # the new file passed every check.
    if os.path.exists(tmp_file):
        os.remove(tmp_file)

    print(f"    Partition {index} (slot 0x{slot:02X})... ", end="", flush=True)

    written = 0
    remaining = part["size"]
    try:
        with open(nand_path, 'rb') as nand, open(tmp_file, 'wb') as out:
            nand.seek(part["offset"])
            while remaining > 0:
                to_read = min(CHUNK_SIZE, remaining)
                try:
                    chunk = read_exact(nand, to_read)
                except EOFError:
                    raise ValueError(
                        f"Partition {index}: NAND truncated - expected {to_read} bytes (unexpected EOF)")
                abs_off = part["offset"] + (part["size"] - remaining)
                counter = add_counter(nonce, abs_off // 16)
                dec = aes_ctr_crypt(normal_key, counter, chunk)
                out.write(dec)
                written += len(dec)
                remaining -= len(chunk)

        if written != part["size"]:
            raise ValueError(f"Partition {index}: wrote {written} bytes but expected {part['size']}")

        # --- structural checks (sanity only) ---
        check_ok = True
        check_note = ""
        with open(tmp_file, 'rb') as f:
            head = f.read(0x200)
        if slot in (0x04, 0x05):
            if len(head) >= 0x200 and head[0x1FE:0x200] == b'\x55\xAA':
                check_note = "MBR 55AA OK"
            else:
                check_ok = False
                check_note = "MBR 55AA MISSING (wrong key/offset?)"
        elif slot == 0x06:
            # A FIRM image starts at partition offset 0x00 ("FIRM" magic at +0).
            if len(head) >= 0x04 and head[0x00:0x04] == b'FIRM':
                check_note = "FIRM magic OK"
            else:
                check_ok = False
                check_note = "FIRM magic MISSING (wrong key/offset?)"
        else:
            check_note = f"no structural check defined (slot 0x{slot:02X})"

        if not check_ok:
            os.remove(tmp_file)
            raise ValueError(f"Partition {index}: structural check failed - {check_note}")

        sha_hex = file_sha256(tmp_file)
        commit_file(tmp_file, out_file, force)  # no-clobber unless -Force

        print(f"saved ({part['size'] / 1048576:.1f} MB, wrote {written} bytes, {check_note})")
        print(f"        SHA-256: {sha_hex}")
    finally:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)


def print_help():
    print(f"""decrypt3dsnand {VERSION} - 3DS NAND Dump Decryptor (Pure Python, pycryptodome)

Usage:
  python DecryptCTRNand.py -NandFile <sysnand.bin> -Boot9File <boot9.bin> -OtpFile <otp.mem>
                           [-CidHex <32hex> | -CidFile <nand_cid.mem>]
                           [-OutDir <dir>] [-Mode dev|retail] [-Force] [-ShowKeys]
                           [-OtpDecrypted]

Parameters (identical to DecryptCTRNand.ps1, case-insensitive):
  -NandFile      NAND dump file path (required)
  -Boot9File     Plaintext boot9.bin path, 64KB or 32KB (required)
  -OtpFile       OTP file path (required; encrypted or decrypted)
  -OtpDecrypted  OTP is already decrypted plaintext (still validated)
  -CidHex        eMMC CID as 32-char hex string
  -CidFile       Path to nand_cid.mem (16 bytes)
  -OutDir        Output directory for decrypted partitions
  -Mode          dev (default) or retail
  -Force         Overwrite existing output files (default: refuse)
  -ShowKeys      Display derived normalKeys (hidden by default)

Legacy aliases still accepted: --nand --boot9 --otp --cid --cid-file --outdir
--mode --otp-dec --force --show-keys.""")


def parse_args(argv):
    """Case-insensitive PS1-style CLI parser (keeps legacy --name aliases)."""
    o = argparse.Namespace()
    o.nand = None
    o.boot9 = None
    o.otp = None
    o.otp_dec = False
    o.cid = None
    o.cid_file = None
    o.outdir = None
    o.mode = "dev"
    o.force = False
    o.show_keys = False

    aliases = {
        "nandfile": ("nand", False), "nand": ("nand", False),
        "boot9file": ("boot9", False), "boot9": ("boot9", False),
        "otpfile": ("otp", False), "otp": ("otp", False),
        "cidhex": ("cid", False), "cid": ("cid", False),
        "cidfile": ("cid_file", False), "cid-file": ("cid_file", False),
        "outdir": ("outdir", False), "out-dir": ("outdir", False),
        "mode": ("mode", False),
        "otpdecrypted": ("otp_dec", True), "otp-dec": ("otp_dec", True),
        "force": ("force", True),
        "showkeys": ("show_keys", True), "show-keys": ("show_keys", True),
        "help": ("help", True),
    }

    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-h", "--help", "/?"):
            print_help()
            sys.exit(0)
        if not tok.startswith("-"):
            sys.exit(f"[!] unexpected argument: {tok}")
        key = tok.lstrip("-").lower()
        if key not in aliases:
            sys.exit(f"[!] unknown argument: {tok} (see --help)")
        attr, is_flag = aliases[key]
        if is_flag:
            setattr(o, attr, True)
            i += 1
        else:
            if i + 1 >= len(argv):
                sys.exit(f"[!] {tok} requires a value")
            setattr(o, attr, argv[i + 1])
            i += 2
    return o


def main():
    args = parse_args(sys.argv[1:])
    # -Mode is case-insensitive (PS1 ValidateSet / Java toLowerCase already are)
    if isinstance(args.mode, str):
        args.mode = args.mode.lower()
    if args.mode not in ("dev", "retail"):
        sys.exit(f"[!] -Mode must be dev or retail, got '{args.mode}'")
    if args.nand is None or args.boot9 is None or args.otp is None:
        sys.exit("[!] -NandFile / -Boot9File / -OtpFile are required (see --help)")

    print(f"=== decrypt3dsnand {VERSION} ===")
    print(f"NAND: {args.nand}")
    print(f"boot9: {args.boot9}")
    print(f"OTP: {args.otp}")
    print(f"Mode: {args.mode}")

    if not os.path.isfile(args.nand):
        sys.exit(f"[!] NAND file not found: {args.nand}")
    if not os.path.isfile(args.boot9):
        sys.exit(f"[!] boot9 file not found: {args.boot9}")
    if not os.path.isfile(args.otp):
        sys.exit(f"[!] OTP file not found: {args.otp}")
    nand_len = os.path.getsize(args.nand)
    if nand_len < 0x200:
        sys.exit(f"[!] NAND: file too small to contain an NCSD header (< 0x200 bytes)")

    # Read inputs
    boot9 = load_boot9(args.boot9)
    otp_raw = load_otp(args.otp)

    # Step 1: OTP
    if args.otp_dec:
        print("\n[*] Using pre-decrypted OTP (validating anyway)")
        validate_otp(otp_raw, args.mode, "from file")
        otp_plain = otp_raw
        otp_enc = encrypt_otp(otp_plain, boot9, args.mode)  # re-encrypt -> raw form (for TWL)
        print("[+] OTP plaintext valid")
    else:
        print("\n[*] Decrypting OTP...")
        otp_enc = otp_raw
        otp_plain = decrypt_otp(otp_raw, boot9, args.mode)

    # Step 2: CID
    cid = load_cid(args.cid, args.cid_file)

    # Step 3: NCSD parse
    print("\n[*] Parsing NCSD header...")
    partitions = parse_ncsd(args.nand, nand_len)

    # Step 4: Keyinit
    print("\n[*] Keyinit (OTP + boot9 -> console-unique normalKeys)...")
    normal_keys = keyinit(otp_plain, boot9, dev=(args.mode == "dev"))
    # TWL slot 0x03 (separate scheme; dev uses the RAW OTP)
    twl_key = derive_twl_key(otp_enc, otp_plain, dev=(args.mode == "dev"))
    if args.show_keys:
        print("\n[+] Derived normalKeys:")
        for slot in sorted(normal_keys.keys()):
            print(f"    slot 0x{slot:02X}: {normal_keys[slot].hex().upper()}")
        print(f"    slot 0x03 (TWL): {twl_key.hex().upper()}")
    else:
        print(f"\n[+] Derived normalKeys (slots 0x03-0x07): OK (hidden; use -ShowKeys to display)")

    # Step 5: nonce
    nonce = derive_nonce(cid)
    twl_nonce = derive_twl_nonce(cid)
    print("\n[+] CTR nonce derived (SHA256(CID)[:16], hidden)")
    print("[+] TWL nonce derived (SHA1(CID)[:16] reversed, hidden)")

    # Step 6: decrypt partitions
    if args.outdir:
        print(f"\n[*] Decrypting partitions to: {args.outdir}")
        os.makedirs(args.outdir, exist_ok=True)
        for part in partitions:
            if part["status"] == "unknown":
                print(f"    Partition {part['index']}: unknown crypt/fs type, skipped")
                continue
            if part["status"] == "twl":
                decrypt_twl_partition(args.nand, part, twl_key, twl_nonce, args.outdir, args.force)
                continue
            if part["slot"] not in normal_keys:
                print(f"    Partition {part['index']}: slot 0x{part['slot']:02X} not derived ({part['status']}), skipping")
                continue
            decrypt_partition(args.nand, part, normal_keys[part["slot"]], nonce, args.outdir, args.force)
    else:
        print("\n[*] No -OutDir specified: keys derived, partitions not written to disk.")

    # Summary
    print("\n=== Summary ===")
    print(f"OTP: valid ({args.mode})")
    print(f"NCSD: parsed, {len(partitions)} non-empty partition(s)")
    print("CID: loaded (hidden)")
    print("Keyinit: completed (slots 0x03-0x07, incl. TWL)")
    print("nonce: derived")
    if args.outdir:
        print(f"Partitions: decrypted to {args.outdir} (structural checks applied)")
        print("Note: AES-CTR provides no integrity authentication; checks are structural sanity checks only.")
    else:
        print("Partitions: not decrypted (no -OutDir)")
    print("\nDone.")


if __name__ == "__main__":
    main()
