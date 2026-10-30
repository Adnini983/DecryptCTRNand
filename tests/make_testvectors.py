#!/usr/bin/env python3
"""
make_testvectors.py - synthetic test-vector generator + oracle for DecryptCTRNand.

Builds a fake-but-valid 64KB boot9 (both dev and retail keyblobs and OTP keys),
fake OTP plaintexts (valid DEADB00F + SHA256 + dev flag), a fake eMMC CID, and
a fake NAND with a proper NCSD header covering every slot mapping:

    p0: fs=0x01 crypt=0x02 -> Old3DS CTRNAND  (slot 0x04)
    p1: fs=0x03 crypt=0x02 -> FIRM            (slot 0x06)
    p2: fs=0x04 crypt=0x02 -> AGB save        (slot 0x07)
    p3: fs=0x02 crypt=0x01 -> TWL             (unsupported, must be skipped)
    p4: fs=0x01 crypt=0x03 -> New3DS CTRNAND  (slot 0x05)

The NAND is encrypted twice (dev keys / retail keys). Expected decrypted
partition images are written to expected/. This lets the PowerShell, Python and
Java implementations be checked byte-for-byte against the oracle and against
each other.

NOTE: this is a SELF-CONSISTENT test (the oracle uses the same 3DS algorithms),
not a cross-check against an independent implementation. The anchor for the
algorithms is the original PS1's validation on real dev/retail dumps plus pyctr.

Run:  python make_testvectors.py
"""

import hashlib
import os
import struct

from Crypto.Cipher import AES
from Crypto.Util import Counter

BASE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(BASE, "vectors")
EXP = os.path.join(BASE, "expected")

C1 = int.from_bytes(bytes.fromhex("1FF9E9AAC5FE0408024591DC5D52768A"), byteorder='big')
MASK_128 = (1 << 128) - 1
OTP_MAGIC = bytes.fromhex("0FB0ADDE")
FIXED_KEYY_CTRNAND_NEW = bytes.fromhex("4D804F4E9990194613A204AC584460BE")

# ---- deterministic PRNG (ANSI C LCG) so vectors are reproducible ----
_rng_state = 0x12345678


def rnd(n: int) -> bytes:
    global _rng_state
    out = bytearray()
    for _ in range(n):
        _rng_state = (_rng_state * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((_rng_state >> 16) & 0xFF)
    return bytes(out)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def rol128(data: bytes, n: int) -> bytes:
    v = int.from_bytes(data, 'big')
    return (((v << n) | (v >> (128 - n))) & MASK_128).to_bytes(16, 'big')


def scramble(kx: bytes, ky: bytes) -> bytes:
    xor = int.from_bytes(rol128(kx, 2), 'big') ^ int.from_bytes(ky, 'big')
    x = (xor + C1) & MASK_128
    return rol128(x.to_bytes(16, 'big'), 87)


def add_counter(nonce: bytes, blocks: int) -> bytes:
    return ((int.from_bytes(nonce, 'big') + blocks) & MASK_128).to_bytes(16, 'big')


def aes_ctr(key: bytes, counter: bytes, data: bytes) -> bytes:
    c = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(counter, 'big')))
    return c.decrypt(data)


def aes_cbc_enc(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def keyinit(otp_plain: bytes, b9_32: bytes, dev: bool):
    """Mirror of the keyinit used by all three implementations (pyctr port)."""
    keyblob_off = 0x5860 + (0x400 if dev else 0)
    keygen = b9_32[keyblob_off:keyblob_off + 0x200]
    extdata_otp = keygen[0:0x24]
    console_xy = sha256(otp_plain[0x90:0xAC] + extdata_otp)
    slot3f = scramble(console_xy[0:16], console_xy[16:32])

    off = 0

    def gen(n):
        nonlocal off
        off += 36
        iv = keygen[off:off + 16]
        off += 16
        data = keygen[off:off + 64]
        enc = aes_cbc_enc(slot3f, iv, data)
        off += n
        return enc

    a = gen(64)
    kx = a[0:16]
    keyblob = b9_32[keyblob_off:keyblob_off + 0x400]
    ky = {
        0x04: keyblob[0x1F0:0x200],
        0x05: FIXED_KEYY_CTRNAND_NEW,
        0x06: keyblob[0x210:0x220],
        0x07: keyblob[0x220:0x230],
    }
    return {s: scramble(kx, ky[s]) for s in (0x04, 0x05, 0x06, 0x07)}


def make_otp_plain(dev: bool) -> bytes:
    plain = bytearray(rnd(0x100))
    plain[0:4] = OTP_MAGIC
    plain[0x80:0x90] = b'\x00' * 0x10          # all-zero per 3dbrew
    plain[0x19] = 0x01 if dev else 0x00        # dev flag
    plain[0xE0:0x100] = sha256(plain[0:0xE0])  # SHA-256 tail
    return bytes(plain)


def build_boot9() -> bytes:
    b9 = bytearray(rnd(0x10000))

    # OTP key/IV blobs (full-file offsets; 64KB dump layout)
    otp_keys = {}
    for mode, base in (("retail", 0xD6E0), ("dev", 0xD700)):
        k = rnd(16)
        iv = rnd(16)
        otp_keys[mode] = (k, iv)
        b9[base:base + 16] = k
        b9[base + 16:base + 32] = iv

    # keyblobs at 0xD860 (retail) / 0xDC60 (dev)  == 32KB-space 0x5860 / 0x5C60
    # KeyY locations inside the 0x400 keyblob (see keyinit):
    #   slot 0x04 -> keyblob[0x1F0:0x200]
    #   slot 0x06 -> keyblob[0x210:0x220]
    #   slot 0x07 -> keyblob[0x220:0x230]
    keyy = {
        "retail": {
            0x04: (0x1F0, bytes.fromhex("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF")),
            0x06: (0x210, bytes.fromhex("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF")),
            0x07: (0x220, bytes.fromhex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")),
        },
        "dev": {
            0x04: (0x1F0, bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")),
            0x06: (0x210, bytes.fromhex("E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF")),
            0x07: (0x220, bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")),
        },
    }
    for mode in ("retail", "dev"):
        kb_off = 0xD860 if mode == "retail" else 0xDC60
        keyblob = bytearray(rnd(0x400))
        for slot, (off, ky) in keyy[mode].items():
            keyblob[off:off + 16] = ky
        b9[kb_off:kb_off + 0x400] = keyblob

    return bytes(b9), otp_keys


# ---- NAND layout ----
PARTITIONS = [
    dict(index=0, fs=0x01, crypt=0x02, offset=0x200,      size=0x200000, fill=0x5A, slot=0x04, mbr=True),
    dict(index=1, fs=0x03, crypt=0x02, offset=0x200200,   size=0x40000,  fill=0x33, slot=0x06, firm=True),
    dict(index=2, fs=0x04, crypt=0x02, offset=0x240200,   size=0x10000,  fill=0x44, slot=0x07),
    dict(index=3, fs=0x02, crypt=0x01, offset=0x250200,   size=0x8000,   fill=0x22, slot=0x03),  # TWL: skipped
    dict(index=4, fs=0x01, crypt=0x03, offset=0x258200,   size=0x200000, fill=0x5B, slot=0x05, mbr=True),
]


def make_plain_partition(p) -> bytes:
    data = bytearray(bytes([p["fill"]]) * p["size"])
    if p.get("mbr"):
        data[0x1FE:0x200] = b'\x55\xAA'
    if p.get("firm"):
        data[0x100:0x104] = b'FIRM'
    return bytes(data)


def build_nand() -> tuple:
    total = PARTITIONS[-1]["offset"] + PARTITIONS[-1]["size"]
    nand = bytearray(total)

    # NCSD header
    nand[0x100:0x104] = b'NCSD'
    struct.pack_into("<I", nand, 0x104, total // 0x200)
    for i in range(8):
        if i < len(PARTITIONS):
            p = PARTITIONS[i]
            nand[0x110 + i] = p["fs"]
            nand[0x118 + i] = p["crypt"]
            struct.pack_into("<I", nand, 0x120 + i * 8, p["offset"] // 0x200)
            struct.pack_into("<I", nand, 0x120 + i * 8 + 4, p["size"] // 0x200)
        else:
            nand[0x110 + i] = 0
            nand[0x118 + i] = 0

    plains = {}
    for p in PARTITIONS:
        plains[p["index"]] = make_plain_partition(p)
        nand[p["offset"]:p["offset"] + p["size"]] = plains[p["index"]]

    return bytes(nand), plains


def encrypt_nand(plain_nand: bytes, normal_keys: dict, nonce: bytes, dev: bool) -> bytes:
    out = bytearray(plain_nand)
    for p in PARTITIONS:
        if p["slot"] not in normal_keys:
            continue  # TWL etc.
        key = normal_keys[p["slot"]]
        data = plain_nand[p["offset"]:p["offset"] + p["size"]]
        counter = add_counter(nonce, p["offset"] // 16)
        out[p["offset"]:p["offset"] + p["size"]] = aes_ctr(key, counter, data)
    return bytes(out)


def main():
    os.makedirs(VEC, exist_ok=True)
    os.makedirs(EXP, exist_ok=True)

    cid = rnd(16)
    nonce = sha256(cid)[0:16]

    boot9, otp_keys = build_boot9()
    b9_32 = boot9[0x8000:0x10000]

    plain_nand, plains = build_nand()

    for mode in ("dev", "retail"):
        dev = (mode == "dev")
        otp_plain = make_otp_plain(dev)
        otp_enc = aes_cbc_enc(*otp_keys[mode], otp_plain)

        with open(os.path.join(VEC, f"otp_{mode}.bin"), "wb") as f:
            f.write(otp_enc)
        with open(os.path.join(VEC, f"otp_plain_{mode}.bin"), "wb") as f:
            f.write(otp_plain)

        keys = keyinit(otp_plain, b9_32, dev)
        nand_enc = encrypt_nand(plain_nand, keys, nonce, dev)
        with open(os.path.join(VEC, f"nand_{mode}.bin"), "wb") as f:
            f.write(nand_enc)

        print(f"[{mode}] normalKeys:")
        for s in sorted(keys):
            print(f"    slot 0x{s:02X}: {keys[s].hex().upper()}")

    with open(os.path.join(VEC, "boot9.bin"), "wb") as f:
        f.write(boot9)
    with open(os.path.join(VEC, "cid.bin"), "wb") as f:
        f.write(cid)

    # expected decrypted partitions (same plaintext for both modes)
    for p in PARTITIONS:
        if p["slot"] in (0x03,):
            continue  # TWL not decrypted by the tool
        name = f"partition_{p['index']}_slot{p['slot']:02X}.bin"
        with open(os.path.join(EXP, name), "wb") as f:
            f.write(plains[p["index"]])

    print("\nWrote vectors ->", VEC)
    print("Wrote expected ->", EXP)
    print("NAND size: 0x%X bytes" % len(plain_nand))
    print("nonce: " + nonce.hex().upper())


if __name__ == "__main__":
    main()
