#!/usr/bin/env python3
"""
decrypt3dsnand v0.2 - 3DS NAND Dump Decryptor (Pure Python)

Decrypt 3DS NAND dumps using plaintext boot9 + OTP + eMMC CID.
Dependencies: pycryptodome (Crypto.Cipher.AES)

v0.2 fixes (kept in sync with DecryptCTRNand.ps1):
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

Usage:
    python DecryptCTRNand.py --nand sysnand.bin --boot9 boot9.bin --otp otp.mem \
        --cid-file nand_cid.mem --mode dev --outdir out/
    python DecryptCTRNand.py --nand sysnand.bin --boot9 boot9.bin --otp otp_dec.mem \
        --otp-dec --cid-hex 8FA3544A... --mode retail --outdir out/
"""

import argparse
import hashlib
import os
import struct
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    sys.exit("[!] pycryptodome is required: pip install pycryptodome")

# === Constants ===
# 3DS AES key scrambler C1 constant (reverse-engineered from dev slot0x2C)
C1 = int.from_bytes(bytes.fromhex("1FF9E9AAC5FE0408024591DC5D52768A"), byteorder='big')
MASK_128 = (1 << 128) - 1
OTP_MAGIC = bytes.fromhex("0FB0ADDE")
CHUNK_SIZE = 0x100000
# Fixed CTRNANDNew KeyY (dev/retail same), not stored in the keyblob
FIXED_KEYY_CTRNAND_NEW = bytes.fromhex("4D804F4E9990194613A204AC584460BE")


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


def add_counter(nonce: bytes, blocks: int) -> bytes:
    """nonce (16B BE) + blocks, truncated to 128 bits."""
    val = (int.from_bytes(nonce, 'big') + blocks) & MASK_128
    return val.to_bytes(16, 'big')


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().upper()


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
    for i in range(8):
        fstype = header[0x110 + i]
        crypttype = header[0x118 + i]
        offset_units, size_units = struct.unpack_from("<II", header, 0x120 + i * 8)

        if fstype == 0 and crypttype == 0:
            continue

        abs_offset = offset_units * 0x200
        abs_size = size_units * 0x200

        if abs_offset < 0x200:
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
        # crypt 0x01 = TWL (slot 0x03, different nonce scheme - not implemented here)
        # crypt 0x02: fs 0x01 = Old3DS CTRNAND -> slot 0x04
        #             fs 0x03 = FIRM           -> slot 0x06
        #             fs 0x04 = AGB_FIRM save  -> slot 0x07
        # crypt 0x03 = New3DS CTRNAND         -> slot 0x05
        slot = 0
        status = "decrypt"
        if crypttype == 1:
            slot = 0x03
            status = "unsupported"  # TWL nonce scheme not implemented
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
            slot = 0x05
        else:
            status = "unknown"

        if status == "unknown":
            print(f"    [!] Partition {i}: unsupported combo fs=0x{fstype:02X} crypt=0x{crypttype:02X} - not decrypting")

        partitions.append({
            "index": i, "fstype": fstype, "crypttype": crypttype,
            "offset": abs_offset, "size": abs_size,
            "slot": slot, "status": status,
        })

        slot_txt = "--" if status == "unknown" else f"0x{slot:02X}"
        print(f"    Partition {i}: slot={slot_txt} offset=0x{abs_offset:08X} size=0x{abs_size:08X} [{status}]")

    # overlap check
    for a in range(len(partitions)):
        pa = partitions[a]
        for b in range(a + 1, len(partitions)):
            pb = partitions[b]
            if not (pa["offset"] + pa["size"] <= pb["offset"] or
                    pb["offset"] + pb["size"] <= pa["offset"]):
                raise ValueError(
                    f"Partition table overlap: partition {pa['index']} and partition {pb['index']}")

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


# === Partition decryption ===
def decrypt_partition(nand_path: str, part: dict, normal_key: bytes, nonce: bytes,
                      outdir: str, force: bool) -> None:
    index = part["index"]
    slot = part["slot"]
    out_file = os.path.join(outdir, f"partition_{index}_slot{slot:02X}.bin")
    tmp_file = out_file + ".tmp"

    if os.path.exists(out_file):
        if not force:
            raise FileExistsError(f"Output already exists: {out_file}. Re-run with --force to overwrite.")
        os.remove(out_file)
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
                chunk = nand.read(to_read)
                if len(chunk) < to_read:
                    raise ValueError(
                        f"Partition {index}: NAND truncated - expected {to_read} bytes, got {len(chunk)}")
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
            if len(head) >= 0x104 and head[0x100:0x104] == b'FIRM':
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
        os.replace(tmp_file, out_file)  # commit

        print(f"saved ({part['size'] / 1048576:.1f} MB, wrote {written} bytes, {check_note})")
        print(f"        SHA-256: {sha_hex}")
    finally:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)


def main():
    parser = argparse.ArgumentParser(description="3DS NAND Dump Decryptor v0.2")
    parser.add_argument("--nand", required=True, help="NAND dump file path")
    parser.add_argument("--boot9", required=True, help="Plaintext boot9.bin path (64KB or 32KB)")
    parser.add_argument("--otp", required=True, help="OTP file path (encrypted or decrypted)")
    parser.add_argument("--otp-dec", action="store_true", help="OTP is already decrypted plaintext")
    parser.add_argument("--cid", help="eMMC CID as 32-char hex string")
    parser.add_argument("--cid-file", help="Path to nand_cid.mem (16 bytes)")
    parser.add_argument("--outdir", help="Output directory for decrypted partitions")
    parser.add_argument("--mode", choices=["dev", "retail"], default="dev", help="Console key mode")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output files")
    parser.add_argument("--show-keys", action="store_true", help="Display derived normalKeys (hidden by default)")
    args = parser.parse_args()

    print("=== decrypt3dsnand v0.2 ===")
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
        print("[+] OTP plaintext valid")
    else:
        print("\n[*] Decrypting OTP...")
        otp_plain = decrypt_otp(otp_raw, boot9, args.mode)

    # Step 2: CID
    cid = load_cid(args.cid, args.cid_file)

    # Step 3: NCSD parse
    print("\n[*] Parsing NCSD header...")
    partitions = parse_ncsd(args.nand, nand_len)

    # Step 4: Keyinit
    print("\n[*] Keyinit (OTP + boot9 -> console-unique normalKeys)...")
    normal_keys = keyinit(otp_plain, boot9, dev=(args.mode == "dev"))
    if args.show_keys:
        print("\n[+] Derived normalKeys:")
        for slot in sorted(normal_keys.keys()):
            print(f"    slot 0x{slot:02X}: {normal_keys[slot].hex().upper()}")
    else:
        print(f"\n[+] Derived normalKeys (slots 0x04-0x07): OK (hidden; use --show-keys to display)")

    # Step 5: nonce
    nonce = derive_nonce(cid)
    print("\n[+] CTR nonce derived (SHA256(CID)[:16], hidden)")

    # Step 6: decrypt partitions
    if args.outdir:
        print(f"\n[*] Decrypting partitions to: {args.outdir}")
        os.makedirs(args.outdir, exist_ok=True)
        for part in partitions:
            if part["status"] == "unknown":
                print(f"    Partition {part['index']}: unknown crypt/fs type, skipped")
                continue
            if part["slot"] not in normal_keys:
                print(f"    Partition {part['index']}: slot 0x{part['slot']:02X} not derived ({part['status']}), skipping")
                continue
            decrypt_partition(args.nand, part, normal_keys[part["slot"]], nonce, args.outdir, args.force)
    else:
        print("\n[*] No --outdir specified: keys derived, partitions not written to disk.")

    # Summary
    print("\n=== Summary ===")
    print(f"OTP: valid ({args.mode})")
    print(f"NCSD: parsed, {len(partitions)} non-empty partition(s)")
    print("CID: loaded (hidden)")
    print("Keyinit: completed (slots 0x04-0x07)")
    print("nonce: derived")
    if args.outdir:
        print(f"Partitions: decrypted to {args.outdir} (structural checks applied)")
        print("Note: AES-CTR provides no integrity authentication; checks are structural sanity checks only.")
    else:
        print("Partitions: not decrypted (no --outdir)")
    print("\nDone.")


if __name__ == "__main__":
    main()
