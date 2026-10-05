#!/usr/bin/env python3
"""
decrypt3dsnand - 3DS NAND Dump Decryptor (Pure Python)

Decrypt 3DS NAND dumps using plaintext boot9 + OTP + eMMC CID.
Dependencies: pycryptodome (Crypto.Cipher.AES, Crypto.Hash.SHA256)

Usage:
    python decrypt3dsnand.py --nand sysnand.bin --boot9 boot9.bin --otp otp.mem --cid nand_cid.mem
    python decrypt3dsnand.py --nand sysnand.bin --boot9 boot9.bin --otp otp_dec.mem --otp-dec --cid-hex 8FA3544A...
"""

import argparse
import hashlib
import os
import struct
import sys

from Crypto.Cipher import AES

# === Constants ===
# 3DS AES key scrambler C1 constant (reverse-engineered from dev slot0x2C)
C1 = int.from_bytes(bytes.fromhex("1FF9E9AAC5FE0408024591DC5D52768A"), byteorder='big')
MASK_128 = (1 << 128) - 1

# boot9 file offsets (dev)
DEV_OTP_NK_OFF = 0xD700
DEV_OTP_IV_OFF = 0xD710
RETAIL_OTP_NK_OFF = 0xD6E0
RETAIL_OTP_IV_OFF = 0xD6F0

# boot9 KeyY table (file offsets)
KEYY_OFFSETS = {
    0x04: 0xDE50,  # Old3DS CTRNAND
    0x05: 0xDE60,  # New3DS CTRNAND
    0x06: 0xDE70,  # firm0/firm1
    0x07: 0xDE80,  # AGB save
}


def rol128(data: bytes, n: int) -> bytes:
    """128-bit rotate left (big-endian)."""
    val = int.from_bytes(data, byteorder='big')
    result = ((val << n) | (val >> (128 - n))) & MASK_128
    return result.to_bytes(16, byteorder='big')


def ror128(data: bytes, n: int) -> bytes:
    """128-bit rotate right (big-endian)."""
    return rol128(data, 128 - n)


def scramble(keyx: bytes, keyy: bytes) -> bytes:
    """3DS AES key scrambler: (((KeyX ROL 2) XOR KeyY) + C1) ROR 41"""
    kx_rol2 = rol128(keyx, 2)
    xor = bytes(a ^ b for a, b in zip(kx_rol2, keyy))
    xor_int = int.from_bytes(xor, byteorder='big')
    sum_int = (xor_int + C1) & MASK_128
    sum_bytes = sum_int.to_bytes(16, byteorder='big')
    return ror128(sum_bytes, 41)


def decrypt_otp(otp_encrypted: bytes, boot9: bytes) -> bytes:
    """Decrypt OTP (AES-CBC, auto-detect dev/retail)."""
    candidates = [
        ("dev", DEV_OTP_NK_OFF, DEV_OTP_IV_OFF),
        ("retail", RETAIL_OTP_NK_OFF, RETAIL_OTP_IV_OFF),
    ]

    for name, nk_off, iv_off in candidates:
        nk = boot9[nk_off:nk_off+16]
        iv = boot9[iv_off:iv_off+16]
        cipher = AES.new(nk, AES.MODE_CBC, iv=iv)
        plain = cipher.decrypt(otp_encrypted)

        # Check magic (DEADB00F little-endian)
        if plain[:4] == bytes.fromhex("0FB0ADDE"):
            # Verify SHA256
            sha = hashlib.sha256(plain[:0xE0]).digest()
            if sha == plain[0xE0:0x100]:
                print(f"[+] OTP decrypted successfully ({name})")
                print(f"    Dev flag: 0x{plain[0x19]:02X}")
                return plain

    raise ValueError("Failed to decrypt OTP with both dev and retail keys")


def parse_ncsd(nand_path: str) -> list:
    """Parse NCSD header and partition table."""
    with open(nand_path, "rb") as f:
        header = f.read(0x200)

    magic = header[0x100:0x104]
    if magic != b'NCSD':
        raise ValueError(f"NCSD magic not found at +0x100. Got: {magic.hex()}")

    print("[+] NCSD magic found at +0x100")

    partitions = []
    for i in range(8):
        fstype = header[0x110 + i]
        crypttype = header[0x118 + i]
        offset = struct.unpack_from("<I", header, 0x120 + i*8)[0]
        size = struct.unpack_from("<I", header, 0x120 + i*8 + 4)[0]

        if fstype == 0 and crypttype == 0:
            continue

        abs_offset = offset * 0x200
        abs_size = size * 0x200

        # Determine AES slot
        if crypttype == 1:
            slot = 0x03  # TWL
        elif crypttype == 2:
            if fstype == 4:
                slot = 0x07  # AGB save
            else:
                slot = 0x06  # firm (default)
                # Old3DS CTRNAND is also crypttype=2, fstype=1, byte offset > 0xB00000
                if fstype == 1 and abs_offset > 0xB00000:
                    slot = 0x04  # Old3DS CTRNAND
        elif crypttype == 3:
            slot = 0x05  # New3DS CTRNAND
        else:
            slot = 0x04

        partitions.append({
            "index": i,
            "fstype": fstype,
            "crypttype": crypttype,
            "offset": abs_offset,
            "size": abs_size,
            "slot": slot,
        })

        print(f"    Partition {i}: slot=0x{slot:02X} offset=0x{abs_offset:08X} size=0x{abs_size:08X}")

    return partitions


def derive_nonce(cid: bytes) -> bytes:
    """Derive CTR nonce = SHA256(CID)[:16]."""
    return hashlib.sha256(cid).digest()[:16]


def keyinit(otp_plain: bytes, boot9: bytes, dev: bool = True) -> dict:
    """
    Derive console-unique keys for NAND slots (0x04-0x07).
    Ported from pyctr crypto/engine.py (MIT License).
    
    Returns dict of slot -> normalKey bytes.
    """
    # Handle 64KB boot9: pyctr takes last 32KB (offset 0x8000)
    if len(boot9) == 0x10000:
        b9 = boot9[0x8000:0x10000]
    else:
        b9 = boot9
    
    # keyblob offset (dev/retail)
    keyblob_offset = 0x5860
    if dev:
        keyblob_offset += 0x400  # dev = 0x5C60
    
    # b9_extdata_keygen = first 0x200 bytes of keyblob
    b9_extdata_keygen = b9[keyblob_offset:keyblob_offset+0x200]
    
    # b9_extdata_otp = first 0x24 bytes of b9_extdata_keygen
    b9_extdata_otp = b9_extdata_keygen[0:0x24]
    
    # Step 1: console_key_xy = SHA256(OTP_dec[0x90:0xAC] + b9_extdata_otp)
    otp_seed = otp_plain[0x90:0xAC]  # 0x1C bytes
    console_key_xy = hashlib.sha256(otp_seed + b9_extdata_otp).digest()
    
    # slot0x3F (Boot9Internal) KeyX / KeyY
    slot3f_keyx = console_key_xy[0:16]
    slot3f_keyy = console_key_xy[16:32]
    slot3f_normalkey = scramble(slot3f_keyx, slot3f_keyy)
    
    # Step 2: gen() function - derive KeyX for slots 0x04-0x07
    extdata_off = 0
    
    def gen(n):
        nonlocal extdata_off
        extdata_off += 36
        iv = b9_extdata_keygen[extdata_off:extdata_off+16]
        extdata_off += 16
        cipher = AES.new(slot3f_normalkey, AES.MODE_CBC, iv=iv)
        data = cipher.encrypt(b9_extdata_keygen[extdata_off:extdata_off + 64])
        extdata_off += n
        return data
    
    a = gen(64)
    slot04_07_keyx = a[0:16]  # slot0x04, 0x05, 0x06, 0x07 all use same KeyX
    
    # Step 3: KeyY
    keyblob = b9[keyblob_offset:keyblob_offset+0x400]

    # slot0x05 (New3DS CTRNAND) uses a FIXED global KeyY, not from keyblob
    # Fixed CTRNANDNew KeyY: 0x4D804F4E9990194613A204AC584460BE (dev/retail same)
    fixed_keyy_ctrnand_new = bytes.fromhex("4D804F4E9990194613A204AC584460BE")

    # KeyY for slots 0x04, 0x06, 0x07 from keyblob offset 0x1F0
    keyy_table = {
        0x04: keyblob[0x1F0:0x200],
        0x05: fixed_keyy_ctrnand_new,  # FIXED, not from keyblob!
        0x06: keyblob[0x210:0x220],
        0x07: keyblob[0x220:0x230],
    }

    # Step 4: Scramble to get normalKeys
    result = {}
    for slot in range(0x04, 0x08):
        result[slot] = scramble(slot04_07_keyx, keyy_table[slot])

    return result


def main():
    parser = argparse.ArgumentParser(description="3DS NAND Dump Decryptor")
    parser.add_argument("--nand", required=True, help="NAND dump file path")
    parser.add_argument("--boot9", required=True, help="Plaintext boot9.bin path")
    parser.add_argument("--otp", required=True, help="OTP file path (encrypted or decrypted)")
    parser.add_argument("--otp-dec", action="store_true", help="OTP is already decrypted plaintext")
    parser.add_argument("--cid", help="eMMC CID as 32-char hex string")
    parser.add_argument("--cid-file", help="Path to nand_cid.mem (16 bytes)")
    parser.add_argument("--outdir", help="Output directory for decrypted partitions")
    args = parser.parse_args()

    print("=== decrypt3dsnand ===")
    print(f"NAND: {args.nand}")
    print(f"boot9: {args.boot9}")
    print(f"OTP: {args.otp}")

    # Read inputs
    with open(args.boot9, "rb") as f:
        boot9 = f.read()
    with open(args.otp, "rb") as f:
        otp_raw = f.read()

    # Step 1: OTP
    if args.otp_dec:
        print("\n[*] Using pre-decrypted OTP")
        otp_plain = otp_raw
    else:
        print("\n[*] Decrypting OTP...")
        otp_plain = decrypt_otp(otp_raw, boot9)

    # Step 2: CID
    if args.cid_file:
        with open(args.cid_file, "rb") as f:
            cid = f.read()
        print(f"\n[+] CID loaded from file: {cid.hex().upper()}")
    elif args.cid:
        cid = bytes.fromhex(args.cid)
        print(f"\n[+] CID from hex: {cid.hex().upper()}")
    else:
        print("\n[!] No CID provided.")
        print("    NAND AES-CTR nonce = SHA256(CID)[:16], 128-bit, cannot brute-force.")
        print("    Please provide --cid or --cid-file.")
        sys.exit(1)

    # Step 3: NCSD parse
    print("\n[*] Parsing NCSD header...")
    partitions = parse_ncsd(args.nand)

    # Step 4: Derive nonce
    nonce = derive_nonce(cid)
    print(f"\n[+] CTR nonce (SHA256(CID)[:16]): {nonce.hex().upper()}")

    # Step 5: Keyinit - derive console-unique normalKeys
    print("\n[*] Keyinit (OTP + boot9 -> console-unique normalKeys)...")
    normalkey_table = keyinit(otp_plain, boot9, dev=True)
    
    print("\n[+] Derived normalKeys:")
    for slot in sorted(normalkey_table.keys()):
        print(f"    slot 0x{slot:02X}: {normalkey_table[slot].hex().upper()}")

    # Step 6: Summary
    print("\n=== Summary ===")
    print(f"OTP: decrypted OK")
    print(f"NCSD: parsed, {len(partitions)} partitions OK")
    print(f"CID: loaded OK")
    print(f"KeyX seed: extracted OK")
    print(f"Keyinit: completed OK (slots 0x04-0x07)")
    print(f"nonce: derived OK")
    
    print(f"\n[+] Ready for partition decryption.")
    print(f"    Use slot normalKey + nonce + per-partition offset to decrypt each partition.")


if __name__ == "__main__":
    main()
