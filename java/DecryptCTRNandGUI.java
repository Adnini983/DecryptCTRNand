/*
 * DecryptCTRNandGUI - 3DS NAND Dump Decryptor (Pure JDK 11, zero external deps)
 *
 * 2.0 - Java implementation kept byte-for-byte compatible with
 *        DecryptCTRNand.ps1 / DecryptCTRNand.py (see tests/).
 *
 * Pure JDK only: javax.swing + javax.crypto + java.util.BigInteger.
 * Runs either as a Swing GUI (double-click the jar / java -jar, no launcher
 * needed) or headless CLI with PS1-identical parameters:
 *     java -jar DecryptCTRNandGUI.jar -NandFile sysnand.bin -Boot9File boot9.bin \
 *          -OtpFile otp.mem -CidFile nand_cid.mem -Mode dev -OutDir out -Force
 *     (a leading --cli is also accepted; legacy --nand-style aliases too)
 *
 * GUI (2.0):
 *   - Tabbed multi-task: each tab is an independent decryption task; tasks run
 *     concurrently (per-task log routing + cancellation, ThreadLocal-based).
 *   - Drag & drop: path fields accept dropped files/folders from the OS.
 *   - i18n interface (Lang): built-in zh-CN (default) + en only; third-party
 *     languages can be registered via Lang.register(code, entries).
 *
 * Build (JDK >= 11; target 11 bytecode):
 *     javac --release 11 -d out/classes DecryptCTRNandGUI.java
 *     jar cfm DecryptCTRNandGUI.jar MANIFEST.MF -C out/classes .
 *     (MANIFEST.MF contains "Main-Class: DecryptCTRNandGUI")
 *     (the compiled jar is NOT committed to git; build it locally, see build.bat)
 */

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;

public class DecryptCTRNandGUI {

    // ---------------- constants ----------------
    static final byte[] OTP_MAGIC = hex("0FB0ADDE");
    static final BigInteger C1 = new BigInteger("1FF9E9AAC5FE0408024591DC5D52768A", 16);
    static final BigInteger MASK_128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
    static final byte[] FIXED_KEYY_CTRNAND_NEW = hex("4D804F4E9990194613A204AC584460BE");
    // TWL (DSi NAND, slot 0x03) constants
    static final BigInteger TWL_CONST = new BigInteger("FFFEFB4E295902582A680F5F1A4F3E79", 16);
    static final byte[] KEYY_TWL_DEV = hex("AABF76F17AB8E86697646A260500A0E1");
    static final byte[] KEYY_TWL_RETAIL = hex("76DCB90AD3C44DBD1DDD2D200500A0E1");
    static final byte[] TWL_BLK1D_ANCHOR = hex("8e400601a0c38d800400b30501000000");
    static final long TWL_MBR_START = 0x1BE;
    static final long TWL_FAT_START = 0x12E00;
    static final int CHUNK = 0x100000;
    static final int[] KEY_Y_OFFSETS = {0x1F0, 0x210, 0x220}; // slots 0x04, 0x06, 0x07
    static final String[] EXPECTED_SLOT_NAMES = {"slot04", "slot06", "slot07", "slot05"};

    // ---------------- helpers ----------------
    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static byte[] sub(byte[] src, int off, int len) {
        return Arrays.copyOfRange(src, off, off + len);
    }

    // ---------------- crypto ----------------
    static byte[] rol128(byte[] data, int n) {
        BigInteger v = new BigInteger(1, data);
        BigInteger r = v.shiftLeft(n).or(v.shiftRight(128 - n)).and(MASK_128);
        return to16(r.toByteArray());
    }

    static byte[] ror128(byte[] data, int n) {
        return rol128(data, 128 - n);
    }

    static byte[] to16(byte[] b) {
        if (b.length == 16) return b;
        byte[] out = new byte[16];
        if (b.length > 16) System.arraycopy(b, b.length - 16, out, 0, 16); // drop sign byte
        else System.arraycopy(b, 0, out, 16 - b.length, b.length);
        return out;
    }

    /** 3DS key scrambler: (((KeyX ROL 2) XOR KeyY) + C1) ROR 41 (128-bit big-endian). */
    static byte[] scramble(byte[] keyX, byte[] keyY) {
        byte[] kx2 = rol128(keyX, 2);
        byte[] xor = new byte[16];
        for (int i = 0; i < 16; i++) xor[i] = (byte) (kx2[i] ^ keyY[i]);
        BigInteger s = new BigInteger(1, xor).add(C1).and(MASK_128);
        return ror128(to16(s.toByteArray()), 41);
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] aesCbc(int mode, byte[] key, byte[] iv, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("AES-CBC failed: " + e.getMessage(), e);
        }
    }

    static byte[] aesEcbEncrypt(byte[] key, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("AES-ECB failed: " + e.getMessage(), e);
        }
    }

    static void inc128(byte[] c) {
        for (int i = 15; i >= 0; i--) {
            c[i]++;
            if (c[i] != 0) break;
        }
    }

    /**
     * AES-CTR decrypt/encrypt in place. Counter block for a 16-byte block at
     * absolute NAND offset X = nonce + (X >> 4), 128-bit big-endian (pyctr
     * convention). One ECB pass over the whole counter stream per call.
     * data.length must be a multiple of 16.
     */
    static byte[] aesCtrCrypt(byte[] key, byte[] nonce, long absOffset, byte[] data) {
        if (data.length % 16 != 0) {
            throw new RuntimeException("AES-CTR: data length " + data.length + " not a multiple of 16");
        }
        int blocks = data.length / 16;
        BigInteger base = new BigInteger(1, nonce).add(BigInteger.valueOf(absOffset >>> 4)).and(MASK_128);
        byte[] ctr = to16(base.toByteArray());
        byte[] stream = new byte[data.length];
        for (int i = 0; i < blocks; i++) {
            System.arraycopy(ctr, 0, stream, i * 16, 16);
            inc128(ctr);
        }
        byte[] ks = aesEcbEncrypt(key, stream);
        for (int i = 0; i < data.length; i++) data[i] ^= ks[i];
        return data;
    }

    // ---------------- TWL (DSi NAND, slot 0x03) ----------------
    static byte[] sha1(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static void putU32LE(byte[] b, int off, long v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >> 8);
        b[off + 2] = (byte) (v >> 16);
        b[off + 3] = (byte) (v >> 24);
    }

    static byte[] rev16(byte[] b) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) out[i] = b[15 - i];
        return out;
    }

    /** DSi/TWL keyscrambler: ROL42(((keyX_LE ^ keyY_LE) + TWL_CONST) mod 2^128), BE output. */
    static byte[] scrambleTwl(byte[] keyX, byte[] keyY) {
        BigInteger kx = new BigInteger(1, rev16(keyX));
        BigInteger ky = new BigInteger(1, rev16(keyY));
        BigInteger t = kx.xor(ky).add(TWL_CONST).and(MASK_128);
        BigInteger r = t.shiftLeft(42).or(t.shiftRight(86)).and(MASK_128);
        return to16(r.toByteArray());
    }

    /**
     * TWL NAND (slot 0x03) normal key.
     * dev   : CustId = RAW (encrypted) OTP[0:8] little-endian (otp_dec is WRONG here)
     * retail: CustId = OTP_plain[8:16] ^ 0x08C267B7B358A6AF | 0x80000000
     */
    static byte[] deriveTwlKey(byte[] otpEnc, byte[] otpPlain, boolean dev) {
        long lo, hi;
        byte[] keyy;
        if (dev) {
            lo = readU32LE(otpEnc, 0);
            hi = readU32LE(otpEnc, 4);
            keyy = KEYY_TWL_DEV;
        } else {
            lo = readU32LE(otpPlain, 8);
            hi = readU32LE(otpPlain, 12);
            lo = (lo ^ 0xB358A6AFL) | 0x80000000L;
            hi = hi ^ 0x08C267B7L;
            keyy = KEYY_TWL_RETAIL;
        }
        byte[] keyx = new byte[16];
        putU32LE(keyx, 0, lo);
        putU32LE(keyx, 4, dev ? 0xEE7A4B1EL : 0x4E494E54L);
        putU32LE(keyx, 8, dev ? 0xAF42C08BL : 0x454E444FL);
        putU32LE(keyx, 12, hi);
        return scrambleTwl(keyx, keyy);
    }

    /** TWL nonce = SHA1(CID)[:16], byte-reversed (BE128 of the LE128 integer). */
    static byte[] deriveTwlNonce(byte[] cid) {
        byte[] sh = sha1(cid);
        byte[] n = new byte[16];
        for (int i = 0; i < 16; i++) n[i] = sh[15 - i];
        return n;
    }

    /** Re-encrypt plaintext OTP back to its raw form (TWL dev CustId needs the raw OTP). */
    static byte[] encryptOtp(byte[] otpPlain, byte[] boot9, String mode) {
        int otpBase = boot9.length == 0x10000 ? 0x8000 : 0;
        int nkOff = otpBase + ("dev".equals(mode) ? 0x5700 : 0x56E0);
        return aesCbc(Cipher.ENCRYPT_MODE, sub(boot9, nkOff, 16), sub(boot9, nkOff + 16, 16), otpPlain);
    }

    /** 128-bit big-endian counter = nonce + (absOffset >> 4). */
    static byte[] counterFor(byte[] nonce, long absOffset) {
        BigInteger base = new BigInteger(1, nonce).add(BigInteger.valueOf(absOffset >>> 4)).and(MASK_128);
        return to16(base.toByteArray());
    }

    /**
     * TWL CTR: keystream block = AES-ECB(key, BE128(counter)), XORed byte-reversed per
     * 16-byte block (the DSi AES engine processes blocks in reversed byte order;
     * pyctr _TWLCryptoWrapper). NOT interchangeable with aesCtrCrypt.
     */
    static byte[] twlCtrCrypt(byte[] key, byte[] counter, byte[] data) throws Exception {
        int nBlocks = (data.length + 15) / 16;
        byte[] ctrStream = new byte[nBlocks * 16];
        byte[] ctr = counter.clone();
        for (int i = 0; i < nBlocks; i++) {
            System.arraycopy(ctr, 0, ctrStream, i * 16, 16);
            inc128(ctr);
        }
        byte[] ks = aesEcbEncrypt(key, ctrStream);
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int blockBase = (i / 16) * 16;
            int rev = blockBase + 15 - (i % 16);
            out[i] = (byte) (data[i] ^ ks[rev]);
        }
        return out;
    }

    // ---------------- TWL partition decryption ----------------
    static void decryptTwlPartition(Path nand, Partition p, byte[] twlKey, byte[] twlNonce,
                                    Path outDir, boolean force, boolean cancelable,
                                    java.util.concurrent.atomic.AtomicBoolean cancelled) throws Exception {
        String name = String.format("partition_%d_slot03.bin", p.index);
        Path outFile = outDir.resolve(name);
        Path tmpFile = outDir.resolve(name + ".tmp");

        if (Files.exists(outFile)) {
            if (!force) {
                throw new IOException("Output already exists: " + outFile + ". Re-run with --force to overwrite.");
            }
            Files.delete(outFile);
        }
        Files.deleteIfExists(tmpFile);

        log("    Partition " + p.index + " (slot 0x03, TWL)...");

        long start = p.offset;
        long end = p.offset + p.size;
        long[][] encRanges = {
                {TWL_MBR_START, Math.min(0x200, end)},
                {Math.max(TWL_FAT_START, start), end},
        };
        long written = 0;
        byte[] buf = new byte[CHUNK];
        try (RandomAccessFile raf = new RandomAccessFile(nand.toFile(), "r");
             java.io.OutputStream out = Files.newOutputStream(tmpFile, StandardOpenOption.CREATE,
                     StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            long pos = start;
            for (long[] range : encRanges) {
                long es = range[0], ee = range[1];
                if (es >= ee) continue;
                // raw copy [pos, es)
                while (pos < es) {
                    if (cancelable && cancelled.get()) throw new IOException("Cancelled by user.");
                    int toRead = (int) Math.min(CHUNK, es - pos);
                    raf.seek(pos);
                    int read = raf.read(buf, 0, toRead);
                    if (read < toRead) throw new IOException("Partition " + p.index + ": NAND truncated (raw range)");
                    out.write(buf, 0, read);
                    written += read;
                    pos += read;
                }
                // decrypt [es, ee) - counters are per ABSOLUTE 16-byte block; handle misaligned head
                while (pos < ee) {
                    if (cancelable && cancelled.get()) throw new IOException("Cancelled by user.");
                    if ((pos & 15) != 0) {
                        int headLen = (int) Math.min(16 - (pos & 15), ee - pos);
                        raf.seek(pos);
                        int read = raf.read(buf, 0, headLen);
                        if (read < headLen) throw new IOException("Partition " + p.index + ": NAND truncated (TWL head)");
                        long blockBase = pos & ~15L;
                        byte[] ks = aesEcbEncrypt(twlKey, counterFor(twlNonce, blockBase));
                        int rel = (int) (pos - blockBase);
                        byte[] dec = new byte[headLen];
                        for (int j = 0; j < headLen; j++) {
                            dec[j] = (byte) (buf[j] ^ ks[15 - (rel + j)]);
                        }
                        out.write(dec);
                        written += headLen;
                        pos += headLen;
                        continue;
                    }
                    int toRead = (int) Math.min(CHUNK, ee - pos);
                    raf.seek(pos);
                    int read = raf.read(buf, 0, toRead);
                    if (read < toRead) throw new IOException("Partition " + p.index + ": NAND truncated (TWL range)");
                    byte[] dec = twlCtrCrypt(twlKey, counterFor(twlNonce, pos), Arrays.copyOf(buf, toRead));
                    out.write(dec);
                    written += toRead;
                    pos += toRead;
                }
            }
            // tail raw copy
            while (pos < end) {
                if (cancelable && cancelled.get()) throw new IOException("Cancelled by user.");
                int toRead = (int) Math.min(CHUNK, end - pos);
                raf.seek(pos);
                int read = raf.read(buf, 0, toRead);
                if (read < toRead) throw new IOException("Partition " + p.index + ": NAND truncated (tail range)");
                out.write(buf, 0, read);
                written += read;
                pos += read;
            }
        }

        if (written != p.size) {
            throw new IOException("Partition " + p.index + ": wrote " + written + " bytes but expected " + p.size);
        }

        // --- TWL structural checks (sanity only; AES-CTR is not authenticated) ---
        byte[] mbr = new byte[0x42];
        try (RandomAccessFile f = new RandomAccessFile(tmpFile.toFile(), "r")) {
            f.seek(0x1BE);
            int n = f.read(mbr);
            if (n < 0x42) throw new IOException("Partition " + p.index + ": output too short for TWL MBR checks");
        }
        boolean mbrSigOk = (mbr[0x40] & 0xFF) == 0x55 && (mbr[0x41] & 0xFF) == 0xAA;
        boolean blk1dOk = java.util.Arrays.equals(sub(mbr, 0x12, 16), TWL_BLK1D_ANCHOR);

        boolean fatChecked = p.size > TWL_FAT_START + 0x200;
        boolean fatSigOk = true;
        String oem = "<skipped>";
        if (fatChecked) {
            byte[] fat = new byte[0x200];
            try (RandomAccessFile f = new RandomAccessFile(tmpFile.toFile(), "r")) {
                f.seek(0x12E00);
                int n = f.read(fat);
                if (n < 0x200) throw new IOException("Partition " + p.index + ": TWL region too small for twln boot check");
            }
            fatSigOk = (fat[0x1FE] & 0xFF) == 0x55 && (fat[0x1FF] & 0xFF) == 0xAA;
            oem = new String(fat, 3, 8, java.nio.charset.StandardCharsets.US_ASCII);
        }

        String checkNote;
        if (!mbrSigOk) {
            Files.deleteIfExists(tmpFile);
            throw new IOException("Partition " + p.index + ": TWL MBR 55AA missing (wrong key/OTP?)");
        }
        if (!blk1dOk) {
            Files.deleteIfExists(tmpFile);
            throw new IOException("Partition " + p.index + ": TWL block 0x1D anchor mismatch (wrong key/OTP?)");
        }
        if (!fatSigOk) {
            Files.deleteIfExists(tmpFile);
            throw new IOException("Partition " + p.index + ": twln FAT boot 55AA missing (wrong offset?)");
        }
        checkNote = fatChecked
                ? "MBR 55AA OK, blk0x1D anchor OK, twln boot 55AA OK (OEM='" + oem + "')"
                : "MBR 55AA OK, blk0x1D anchor OK, twln boot check skipped (partition too small)";

        String sha = fileSha256(tmpFile);
        try {
            Files.move(tmpFile, outFile, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(tmpFile, outFile, StandardCopyOption.REPLACE_EXISTING);
        }
        log(String.format("        saved (%s, wrote %d bytes, %s)",
                p.size / 1048576.0 == Math.floor(p.size / 1048576.0)
                        ? (p.size / 1048576) + " MB"
                        : String.format("%.1f MB", p.size / 1048576.0),
                written, checkNote));
        log("        SHA-256: " + sha);
        try {
            Files.deleteIfExists(tmpFile);
        } catch (IOException ignored) {
        }
    }

    // ---------------- OTP ----------------
    static void validateOtp(byte[] plain, String mode, String desc) {
        if (plain.length != 0x100) {
            throw new RuntimeException("OTP " + desc + ": expected exactly 0x100 (256) bytes, got " + plain.length);
        }
        if ((plain[0] & 0xFF) != 0x0F || (plain[1] & 0xFF) != 0xB0
                || (plain[2] & 0xFF) != 0xAD || (plain[3] & 0xFF) != 0xDE) {
            throw new RuntimeException("OTP " + desc + ": DEADB00F magic not found. Not a valid (decrypted) OTP, or wrong mode key.");
        }
        byte[] digest = sha256(sub(plain, 0, 0xE0));
        byte[] tail = sub(plain, 0xE0, 0x20);
        if (!MessageDigest.isEqual(digest, tail)) {
            throw new RuntimeException("OTP " + desc + ": SHA256 integrity check failed.");
        }
        int devFlag = plain[0x19] & 0xFF;
        boolean otpIsDev = devFlag != 0;
        boolean modeIsDev = "dev".equals(mode);
        if (otpIsDev != modeIsDev) {
            throw new RuntimeException("OTP " + desc + ": dev flag byte 0x" + String.format("%02X", devFlag)
                    + " is inconsistent with mode " + mode + "; refusing to derive keys with mismatched keyblob.");
        }
        log("    OTP dev flag: 0x" + String.format("%02X", devFlag) + " (consistent with mode " + mode + ")");
    }

    static byte[] decryptOtp(byte[] otpRaw, byte[] boot9, String mode) {
        int otpBase = boot9.length == 0x10000 ? 0x8000 : 0;
        int nkOff, ivOff;
        if ("dev".equals(mode)) {
            nkOff = otpBase + 0x5700;
            ivOff = otpBase + 0x5710;
        } else {
            nkOff = otpBase + 0x56E0;
            ivOff = otpBase + 0x56F0;
        }
        byte[] nk = sub(boot9, nkOff, 16);
        byte[] iv = sub(boot9, ivOff, 16);
        byte[] plain = aesCbc(Cipher.DECRYPT_MODE, nk, iv, otpRaw);
        validateOtp(plain, mode, "decrypted");
        log("[+] OTP decrypted successfully (" + mode + ")");
        return plain;
    }

    static byte[] loadBoot9(Path p) throws IOException {
        byte[] data = Files.readAllBytes(p);
        if (data.length != 0x10000 && data.length != 0x8000) {
            throw new RuntimeException("boot9: expected 0x10000 (64KB) or 0x8000 (32KB) bytes, got " + data.length);
        }
        return data;
    }

    static byte[] loadOtp(Path p) throws IOException {
        byte[] data = Files.readAllBytes(p);
        if (data.length != 0x100) {
            throw new RuntimeException("OTP: expected exactly 0x100 (256) bytes, got " + data.length);
        }
        return data;
    }

    static byte[] loadCid(String cidHex, String cidFile) throws IOException {
        if (cidFile != null && !cidFile.isEmpty()) {
            byte[] cid = Files.readAllBytes(Paths.get(cidFile));
            if (cid.length != 16) {
                throw new RuntimeException("CID file: expected exactly 16 bytes, got " + cid.length);
            }
            log("[+] CID loaded from file (16 bytes, hidden)");
            return cid;
        }
        if (cidHex != null && !cidHex.isEmpty()) {
            if (cidHex.length() != 32 || !cidHex.matches("[0-9a-fA-F]{32}")) {
                throw new RuntimeException("CID hex: expected exactly 32 hex characters.");
            }
            log("[+] CID from hex (hidden)");
            return hex(cidHex);
        }
        throw new RuntimeException("No CID provided. NAND AES-CTR nonce = SHA256(CID)[:16], 128-bit, cannot brute-force. Please provide CID.");
    }

    // ---------------- NCSD ----------------
    static class Partition {
        int index, fstype, crypttype, slot;
        long offset, size;
        String status; // decrypt | unsupported | unknown
    }

    static List<Partition> parseNcsd(Path nand, long nandLen) throws IOException {
        byte[] header = new byte[0x200];
        try (RandomAccessFile raf = new RandomAccessFile(nand.toFile(), "r")) {
            int read = raf.read(header);
            if (read < 0x200) {
                throw new RuntimeException("NAND: truncated NCSD header (read " + read + " of 0x200 bytes)");
            }
        }
        if (header[0x100] != 'N' || header[0x101] != 'C' || header[0x102] != 'S' || header[0x103] != 'D') {
            throw new RuntimeException("NCSD magic not found at +0x100. Got: "
                    + toHex(sub(header, 0x100, 4)));
        }
        log("[+] NCSD magic found at +0x100");

        long ncsdSizeUnits = readU32LE(header, 0x104);
        if (ncsdSizeUnits != 0 && ncsdSizeUnits * 0x200 > nandLen) {
            log("    [!] NCSD header declares size > file length; dump may be truncated");
        }

        List<Partition> parts = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            int fstype = header[0x110 + i] & 0xFF;
            int crypttype = header[0x118 + i] & 0xFF;
            long offsetUnits = readU32LE(header, 0x120 + i * 8);
            long sizeUnits = readU32LE(header, 0x120 + i * 8 + 4);

            if (fstype == 0 && crypttype == 0) continue;

            long absOffset = offsetUnits * 0x200;
            long absSize = sizeUnits * 0x200;

            if (absOffset < 0x200 && crypttype != 1) {
                log("    [!] Partition " + i + ": bogus offset 0x" + Long.toHexString(absOffset)
                        + " (overlaps NCSD header), skipped");
                continue;
            }
            if (absSize == 0) {
                log("    [!] Partition " + i + ": zero size, skipped");
                continue;
            }
            if (absOffset + absSize > nandLen) {
                throw new RuntimeException("Partition " + i + ": offset+size 0x"
                        + Long.toHexString(absOffset + absSize) + " exceeds NAND file length 0x"
                        + Long.toHexString(nandLen) + "; dump truncated or partition table corrupt");
            }

            // --- AES slot mapping (rule-based; refuses unknowns) ---
            Partition p = new Partition();
            p.index = i;
            p.fstype = fstype;
            p.crypttype = crypttype;
            p.offset = absOffset;
            p.size = absSize;
            p.status = "decrypt";
            if (crypttype == 1) {
                p.slot = 0x03;
                p.status = "twl"; // TWL: dedicated key (raw OTP for dev) + SHA1(CID) nonce + reversed-block CTR
            } else if (crypttype == 2) {
                if (fstype == 1) p.slot = 0x04;            // Old3DS CTRNAND
                else if (fstype == 3) p.slot = 0x06;       // FIRM
                else if (fstype == 4) p.slot = 0x07;       // AGB save
                else p.status = "unknown";
            } else if (crypttype == 3) {
                p.slot = 0x05;                             // New3DS CTRNAND
            } else {
                p.status = "unknown";
            }

            if ("unknown".equals(p.status)) {
                log("    [!] Partition " + i + ": unsupported combo fs=0x" + String.format("%02X", fstype)
                        + " crypt=0x" + String.format("%02X", crypttype) + " - not decrypting");
            }
            parts.add(p);

            String slotTxt = "unknown".equals(p.status) ? "--" : String.format("0x%02X", p.slot);
            log("    Partition " + i + ": slot=" + slotTxt + " offset=0x" + String.format("%08X", absOffset)
                    + " size=0x" + String.format("%08X", absSize) + " [" + p.status + "]");
        }

        // overlap check
        for (int a = 0; a < parts.size(); a++) {
            for (int b = a + 1; b < parts.size(); b++) {
                Partition pa = parts.get(a), pb = parts.get(b);
                if (!(pa.offset + pa.size <= pb.offset || pb.offset + pb.size <= pa.offset)) {
                    throw new RuntimeException("Partition table overlap: partition " + pa.index
                            + " and partition " + pb.index);
                }
            }
        }
        return parts;
    }

    static long readU32LE(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8)
                | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }

    // ---------------- keyinit (pyctr port) ----------------
    static java.util.Map<Integer, byte[]> keyinit(byte[] otpPlain, byte[] boot9, boolean dev) {
        byte[] b9 = boot9.length == 0x10000 ? sub(boot9, 0x8000, 0x8000) : boot9;
        int keyblobOff = 0x5860 + (dev ? 0x400 : 0);

        byte[] keygen = sub(b9, keyblobOff, 0x200);
        byte[] extdataOtp = sub(keygen, 0, 0x24);
        byte[] otpSeed = sub(otpPlain, 0x90, 0x1C);
        byte[] consoleKeyXy = sha256(concat(otpSeed, extdataOtp));

        byte[] slot3fKeyX = sub(consoleKeyXy, 0, 16);
        byte[] slot3fKeyY = sub(consoleKeyXy, 16, 16);
        byte[] slot3fNormal = scramble(slot3fKeyX, slot3fKeyY);

        final int[] extdataOff = {0};
        java.util.function.IntFunction<byte[]> gen = new java.util.function.IntFunction<byte[]>() {
            public byte[] apply(int n) {
                extdataOff[0] += 36;
                byte[] iv = sub(keygen, extdataOff[0], 16);
                extdataOff[0] += 16;
                byte[] data = sub(keygen, extdataOff[0], 64);
                byte[] enc = aesCbc(Cipher.ENCRYPT_MODE, slot3fNormal, iv, data);
                extdataOff[0] += n;
                return enc;
            }
        };

        byte[] a = gen.apply(64);
        byte[] kx = sub(a, 0, 16);

        byte[] keyblob = sub(b9, keyblobOff, 0x400);
        byte[][] keyy = new byte[8][];
        keyy[0x04] = sub(keyblob, 0x1F0, 16);
        keyy[0x05] = FIXED_KEYY_CTRNAND_NEW;
        keyy[0x06] = sub(keyblob, 0x210, 16);
        keyy[0x07] = sub(keyblob, 0x220, 16);

        java.util.Map<Integer, byte[]> out = new java.util.HashMap<>();
        for (int slot = 0x04; slot <= 0x07; slot++) {
            out.put(slot, scramble(kx, keyy[slot]));
        }
        return out;
    }

    // ---------------- partition decryption ----------------
    static void decryptPartition(Path nand, Partition p, byte[] key, byte[] nonce,
                                 Path outDir, boolean force, boolean cancelable,
                                 java.util.concurrent.atomic.AtomicBoolean cancelled) throws IOException {
        String name = String.format("partition_%d_slot%02X.bin", p.index, p.slot);
        Path outFile = outDir.resolve(name);
        Path tmpFile = outDir.resolve(name + ".tmp");

        if (Files.exists(outFile)) {
            if (!force) {
                throw new IOException("Output already exists: " + outFile + ". Re-run with --force to overwrite.");
            }
            Files.delete(outFile);
        }
        Files.deleteIfExists(tmpFile);

        log("    Partition " + p.index + " (slot 0x" + String.format("%02X", p.slot) + ")...");

        long written = 0;
        long remaining = p.size;
        byte[] buf = new byte[CHUNK];
        try {
            try (RandomAccessFile raf = new RandomAccessFile(nand.toFile(), "r");
                 java.io.OutputStream out = Files.newOutputStream(tmpFile, StandardOpenOption.CREATE,
                         StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                raf.seek(p.offset);
                while (remaining > 0) {
                    if (cancelable && cancelled.get()) {
                        throw new IOException("Cancelled by user.");
                    }
                    int toRead = (int) Math.min(CHUNK, remaining);
                    int read = raf.read(buf, 0, toRead);
                    if (read < toRead) {
                        throw new IOException("Partition " + p.index + ": NAND truncated - expected "
                                + toRead + " bytes, got " + read);
                    }
                    long absOff = p.offset + (p.size - remaining);
                    byte[] dec = aesCtrCrypt(key, nonce, absOff, Arrays.copyOf(buf, toRead));
                    out.write(dec);
                    written += toRead;
                    remaining -= toRead;
                }
            }

            if (written != p.size) {
                throw new IOException("Partition " + p.index + ": wrote " + written
                        + " bytes but expected " + p.size);
            }

            // --- structural sanity checks (AES-CTR has no authentication) ---
            boolean checkOk = true;
            String checkNote = "";
            byte[] head = new byte[0x200];
            try (RandomAccessFile f = new RandomAccessFile(tmpFile.toFile(), "r")) {
                int n = f.read(head);
                if (p.slot == 0x04 || p.slot == 0x05) {
                    if (n >= 0x200 && (head[0x1FE] & 0xFF) == 0x55 && (head[0x1FF] & 0xFF) == 0xAA) {
                        checkNote = "MBR 55AA OK";
                    } else {
                        checkOk = false;
                        checkNote = "MBR 55AA MISSING (wrong key/offset?)";
                    }
                } else if (p.slot == 0x06) {
                    // FIRM image starts at partition offset 0x00 ("FIRM" magic at +0)
                    if (n >= 0x04 && head[0] == 'F' && head[1] == 'I' && head[2] == 'R' && head[3] == 'M') {
                        checkNote = "FIRM magic OK";
                    } else {
                        checkOk = false;
                        checkNote = "FIRM magic MISSING (wrong key/offset?)";
                    }
                } else {
                    checkNote = String.format("no structural check defined (slot 0x%02X)", p.slot);
                }
            }

            if (!checkOk) {
                Files.deleteIfExists(tmpFile);
                throw new IOException("Partition " + p.index + ": structural check failed - " + checkNote);
            }

            String sha = fileSha256(tmpFile);
            try {
                Files.move(tmpFile, outFile, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(tmpFile, outFile, StandardCopyOption.REPLACE_EXISTING);
            }

            log(String.format("        saved (%s, wrote %d bytes, %s)",
                    p.size / 1048576.0 == Math.floor(p.size / 1048576.0)
                            ? (p.size / 1048576) + " MB"
                            : String.format("%.1f MB", p.size / 1048576.0),
                    written, checkNote));
            log("        SHA-256: " + sha);
        } finally {
            try {
                Files.deleteIfExists(tmpFile);
            } catch (IOException ignored) {
            }
        }
    }

    static String fileSha256(Path p) throws IOException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new IOException(e);
        }
        byte[] buf = new byte[CHUNK];
        try (java.io.InputStream in = Files.newInputStream(p)) {
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        return toHex(md.digest());
    }

    // ---------------- logging / cancellation ----------------
    interface Log {
        void log(String line);
    }

    static Log CLI_LOG = new Log() {
        public void log(String line) {
            System.out.println(line);
        }
    };

    /** Per-thread routed log target: CLI by default; each GUI task worker sets its
     *  own, so multiple tabs can decrypt concurrently without log cross-talk. */
    static final ThreadLocal<Log> CURRENT_LOG = new ThreadLocal<Log>() {
        protected Log initialValue() {
            return CLI_LOG;
        }
    };

    static void log(String line) {
        CURRENT_LOG.get().log(line);
    }

    // ---------------- pipeline ----------------
    static class Options {
        String nand, boot9, otp, cidHex, cidFile, outdir, mode;
        boolean otpDec, force, showKeys;
    }

    /** Full pipeline: OTP -> CID -> NCSD -> keyinit -> nonce -> partitions. */
    static void runPipeline(Options o, boolean cancelable,
                            java.util.concurrent.atomic.AtomicBoolean cancelled) throws Exception {
        if (o.nand == null || o.nand.isEmpty()) throw new RuntimeException("NAND file required");
        if (o.boot9 == null || o.boot9.isEmpty()) throw new RuntimeException("boot9 file required");
        if (o.otp == null || o.otp.isEmpty()) throw new RuntimeException("OTP file required");

        Path nandPath = Paths.get(o.nand);
        if (!Files.isRegularFile(nandPath)) throw new RuntimeException("NAND file not found: " + o.nand);
        Path boot9Path = Paths.get(o.boot9);
        if (!Files.isRegularFile(boot9Path)) throw new RuntimeException("boot9 file not found: " + o.boot9);
        Path otpPath = Paths.get(o.otp);
        if (!Files.isRegularFile(otpPath)) throw new RuntimeException("OTP file not found: " + o.otp);
        long nandLen = Files.size(nandPath);
        if (nandLen < 0x200) throw new RuntimeException("NAND: file too small to contain an NCSD header (< 0x200 bytes)");

        log("=== DecryptCTRNand 2.0 (Java) ===");
        log("NAND: " + o.nand);
        log("boot9: " + o.boot9);
        log("OTP: " + o.otp);
        log("Mode: " + o.mode);

        byte[] boot9 = loadBoot9(boot9Path);
        byte[] otpRaw = loadOtp(otpPath);

        // 1. OTP
        byte[] otpPlain;
        if (o.otpDec) {
            log("[*] Using pre-decrypted OTP (validating anyway)");
            validateOtp(otpRaw, o.mode, "from file");
            otpPlain = otpRaw;
            // Re-encrypt the plaintext back to its raw form: TWL (slot 0x03) derives its
            // dev CustId from the RAW OTP[0:8], so otp_dec.mem alone would give wrong keys.
            otpRaw = encryptOtp(otpPlain, boot9, o.mode);
            log("[+] OTP plaintext valid");
        } else {
            log("[*] Decrypting OTP...");
            otpPlain = decryptOtp(otpRaw, boot9, o.mode);
        }

        // 2. CID
        byte[] cid = loadCid(o.cidHex, o.cidFile);

        // 3. NCSD
        log("[*] Parsing NCSD header...");
        List<Partition> parts = parseNcsd(nandPath, nandLen);

        // 4. keyinit
        log("[*] Keyinit (OTP + boot9 -> console-unique normalKeys)...");
        java.util.Map<Integer, byte[]> normalKeys = keyinit(otpPlain, boot9, "dev".equals(o.mode));
        byte[] twlKey = deriveTwlKey(otpRaw, otpPlain, "dev".equals(o.mode));
        byte[] twlNonce = deriveTwlNonce(cid);
        if (o.showKeys) {
            log("[+] Derived normalKeys:");
            log("    slot 0x03 (TWL): " + toHex(twlKey));
            for (int slot = 0x04; slot <= 0x07; slot++) {
                log("    slot 0x" + String.format("%02X", slot) + ": " + toHex(normalKeys.get(slot)));
            }
        } else {
            log("[+] Derived normalKeys (slots 0x03-0x07, incl. TWL): OK (hidden; use -ShowKeys to display)");
        }

        // 5. nonce
        byte[] nonce = sub(sha256(cid), 0, 16);
        log("[+] CTR nonce derived (SHA256(CID)[:16], hidden)");
        log("[+] TWL nonce derived (SHA1(CID)[:16] reversed, hidden)");

        // 6. partitions
        if (o.outdir == null || o.outdir.isEmpty()) {
            log("[*] No output directory: keys derived, partitions not written to disk.");
        } else {
            Path outDir = Paths.get(o.outdir);
            Files.createDirectories(outDir);
            log("[*] Decrypting partitions to: " + o.outdir);
            for (Partition p : parts) {
                if (cancelable && cancelled.get()) throw new RuntimeException("Cancelled by user.");
                if ("unknown".equals(p.status)) {
                    log("    Partition " + p.index + ": unknown crypt/fs type, skipped");
                    continue;
                }
                if ("twl".equals(p.status)) {
                    decryptTwlPartition(nandPath, p, twlKey, twlNonce, outDir,
                            o.force, cancelable, cancelled);
                    continue;
                }
                if (!normalKeys.containsKey(p.slot)) {
                    log("    Partition " + p.index + ": slot 0x" + String.format("%02X", p.slot)
                            + " not derived (" + p.status + "), skipping");
                    continue;
                }
                decryptPartition(nandPath, p, normalKeys.get(p.slot), nonce, outDir,
                        o.force, cancelable, cancelled);
            }
        }

        log("=== Summary ===");
        log("OTP: valid (" + o.mode + ")");
        log("NCSD: parsed, " + parts.size() + " non-empty partition(s)");
        log("CID: loaded (hidden)");
        log("Keyinit: completed (slots 0x03-0x07, incl. TWL)");
        log("nonce: derived");
        if (o.outdir != null && !o.outdir.isEmpty()) {
            log("Partitions: decrypted to " + o.outdir + " (structural checks applied)");
            log("Note: AES-CTR provides no integrity authentication; checks are structural sanity checks only.");
        } else {
            log("Partitions: not decrypted (no output directory)");
        }
        log("Done.");
    }

    // ---------------- CLI ----------------
    static void printCliHelp() {
        System.out.println("DecryptCTRNand 2.0 (Java) - 3DS NAND Dump Decryptor CLI");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar DecryptCTRNandGUI.jar -NandFile <sysnand.bin> -Boot9File <boot9.bin> -OtpFile <otp.mem>");
        System.out.println("                        [-CidHex <32hex> | -CidFile <nand_cid.mem>]");
        System.out.println("                        [-OutDir <dir>] [-Mode dev|retail] [-Force] [-ShowKeys] [-OtpDecrypted]");
        System.out.println("  (the optional --cli prefix is also accepted; double-clicking the jar opens the GUI)");
        System.out.println();
        System.out.println("Parameters (identical to DecryptCTRNand.ps1, case-insensitive):");
        System.out.println("  -NandFile      NAND dump file path (required)");
        System.out.println("  -Boot9File     Plaintext boot9.bin path, 64KB or 32KB (required)");
        System.out.println("  -OtpFile       OTP file path (required; encrypted or decrypted)");
        System.out.println("  -OtpDecrypted  OTP is already decrypted plaintext (still validated)");
        System.out.println("  -CidHex        eMMC CID as 32-char hex string");
        System.out.println("  -CidFile       Path to nand_cid.mem (16 bytes)");
        System.out.println("  -OutDir        Output directory for decrypted partitions");
        System.out.println("  -Mode          dev (default) or retail");
        System.out.println("  -Force         Overwrite existing output files (default: refuse)");
        System.out.println("  -ShowKeys      Display derived normalKeys (hidden by default)");
        System.out.println();
        System.out.println("Legacy aliases still accepted: --nand --boot9 --otp --cid --cid-file");
        System.out.println("--outdir --mode --otp-dec --force --show-keys.");
    }

    static String stripDashes(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == '-') i++;
        return s.substring(i).toLowerCase(Locale.ROOT);
    }

    /** A non-empty first argument that is a known option selects CLI mode; otherwise GUI. */
    static boolean isCliInvocation(String[] args) {
        if (args.length == 0) return false;
        if ("--cli".equalsIgnoreCase(args[0])) return true;
        if (!args[0].startsWith("-")) return false;
        switch (stripDashes(args[0])) {
            case "nandfile": case "nand":
            case "boot9file": case "boot9":
            case "otpfile": case "otp":
            case "cidhex": case "cid":
            case "cidfile": case "cid-file":
            case "outdir": case "out-dir":
            case "mode":
            case "otpdecrypted": case "otp-dec":
            case "force":
            case "showkeys": case "show-keys":
            case "help": case "h": case "?":
                return true;
            default:
                return false;
        }
    }

    static void runCli(String[] args) {
        Options o = new Options();
        o.mode = "dev";
        int i = 0;
        if (args.length > 0 && "--cli".equalsIgnoreCase(args[0])) i = 1;
        for (; i < args.length; i++) {
            String a = args[i];
            switch (stripDashes(a)) {
                case "nandfile": case "nand": o.nand = needValue(args, i, a); i++; break;
                case "boot9file": case "boot9": o.boot9 = needValue(args, i, a); i++; break;
                case "otpfile": case "otp": o.otp = needValue(args, i, a); i++; break;
                case "cidhex": case "cid": o.cidHex = needValue(args, i, a); i++; break;
                case "cidfile": case "cid-file": o.cidFile = needValue(args, i, a); i++; break;
                case "outdir": case "out-dir": o.outdir = needValue(args, i, a); i++; break;
                case "mode":
                    o.mode = needValue(args, i, a).toLowerCase(Locale.ROOT);
                    if (!"dev".equals(o.mode) && !"retail".equals(o.mode)) {
                        System.err.println("[!] -Mode must be dev or retail");
                        System.exit(1);
                    }
                    i++;
                    break;
                case "otpdecrypted": case "otp-dec": o.otpDec = true; break;
                case "force": o.force = true; break;
                case "showkeys": case "show-keys": o.showKeys = true; break;
                case "help": case "h": case "?":
                    printCliHelp();
                    System.exit(0);
                    break;
                default:
                    System.err.println("[!] unknown argument: " + a);
                    System.exit(1);
            }
        }
        if (o.nand == null || o.boot9 == null || o.otp == null) {
            System.err.println("[!] -NandFile / -Boot9File / -OtpFile are required (see --help)");
            System.exit(1);
        }
        try {
            runPipeline(o, false, new java.util.concurrent.atomic.AtomicBoolean(false));
        } catch (Exception e) {
            System.err.println("[ERROR] " + e.getMessage());
            System.err.println("Decryption aborted; no incomplete partition files were left behind.");
            System.exit(1);
        }
    }

    static String needValue(String[] args, int i, String opt) {
        if (i + 1 >= args.length) {
            System.err.println("[!] " + opt + " requires a value");
            System.exit(1);
        }
        return args[i + 1];
    }

    // ---------------- GUI ----------------
    public static void main(String[] args) {
        if (isCliInvocation(args)) {
            runCli(args);
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new MainFrame().setVisible(true);
            }
        });
    }

    // ---------------- i18n ----------------
    /**
     * Minimal resource-bundle-style i18n interface. Built-in languages:
     * "zh-CN" (Simplified Chinese, default) and "en". Third parties may add
     * languages at runtime via Lang.register(code, entries).
     */
    static class Lang {
        static final java.util.Map<String, java.util.Map<String, String>> DICTS =
                new java.util.LinkedHashMap<>();
        static final java.util.List<String> CODES = new ArrayList<>();
        static String current = "zh-CN";
        static java.util.Map<String, String> cur;

        static void register(String code, java.util.Map<String, String> entries) {
            DICTS.put(code, entries);
            if (!CODES.contains(code)) CODES.add(code);
        }

        static String t(String key) {
            if (cur == null) cur = DICTS.get(current);
            String v = cur == null ? null : cur.get(key);
            return v != null ? v : key;
        }

        static void set(String code) {
            if (DICTS.containsKey(code)) {
                current = code;
                cur = DICTS.get(code);
            }
        }

        static String displayName(String code) {
            return "zh-CN".equals(code) ? "简体中文" : "English";
        }

        static {
            java.util.Map<String, String> zh = new java.util.HashMap<>();
            zh.put("title", "DecryptCTRNand 2.0 - 3DS NAND 解密工具（纯 JDK 11）");
            zh.put("newTask", "＋ 新建任务");
            zh.put("closeTab", "×");
            zh.put("language", "语言:");
            zh.put("nand", "NAND dump:");
            zh.put("boot9", "boot9.bin:");
            zh.put("otp", "OTP 文件:");
            zh.put("cidHex", "CID（十六进制）:");
            zh.put("cidFile", "CID 文件:");
            zh.put("outdir", "输出目录:");
            zh.put("mode", "模式:");
            zh.put("otpDec", "OTP 已是解密明文 (-OtpDecrypted)");
            zh.put("force", "允许覆盖已有输出 (-Force)");
            zh.put("showKeys", "显示派生密钥 (-ShowKeys)");
            zh.put("browse", "浏览…");
            zh.put("start", "开始解密");
            zh.put("cancel", "取消");
            zh.put("working", "处理中…");
            zh.put("successTitle", "=== 成功 ===");
            zh.put("successBody", "所有选中分区均已解密并通过校验。");
            zh.put("cancelTitle", "=== 已取消 ===");
            zh.put("errorTitle", "=== 错误 ===");
            zh.put("abortNote", "解密中止；未留下任何不完整的分区文件。");
            zh.put("dropHint", "可将文件或文件夹拖放到此输入框");
            zh.put("taskTab", "任务");
            register("zh-CN", zh);

            java.util.Map<String, String> en = new java.util.HashMap<>();
            en.put("title", "DecryptCTRNand 2.0 - 3DS NAND Decryptor (Pure JDK 11)");
            en.put("newTask", "+ New Task");
            en.put("closeTab", "×");
            en.put("language", "Language:");
            en.put("nand", "NAND dump:");
            en.put("boot9", "boot9.bin:");
            en.put("otp", "OTP file:");
            en.put("cidHex", "CID (hex):");
            en.put("cidFile", "CID file:");
            en.put("outdir", "Output dir:");
            en.put("mode", "Mode:");
            en.put("otpDec", "OTP is already decrypted (-OtpDecrypted)");
            en.put("force", "Force overwrite existing outputs");
            en.put("showKeys", "Show derived keys (-ShowKeys)");
            en.put("browse", "Browse...");
            en.put("start", "Start Decryption");
            en.put("cancel", "Cancel");
            en.put("working", "Working...");
            en.put("successTitle", "=== SUCCESS ===");
            en.put("successBody", "All selected partitions decrypted and verified.");
            en.put("cancelTitle", "=== CANCELLED ===");
            en.put("errorTitle", "=== ERROR ===");
            en.put("abortNote", "Decryption aborted; no incomplete partition files were left behind.");
            en.put("dropHint", "You can drag & drop a file or folder onto this field");
            en.put("taskTab", "Task");
            register("en", en);

            set("zh-CN"); // default language: Simplified Chinese
        }
    }

    /** Drag & drop support for path fields: dropping a file/folder fills the field. */
    static void enableFileDrop(final JTextField field) {
        field.setToolTipText(Lang.t("dropHint"));
        field.setTransferHandler(new TransferHandler() {
            public boolean canImport(TransferSupport support) {
                return support.isDrop()
                        && support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
            }

            public boolean importData(TransferSupport support) {
                try {
                    @SuppressWarnings("unchecked")
                    java.util.List<File> files = (java.util.List<File>)
                            support.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (!files.isEmpty()) {
                        field.setText(files.get(0).getAbsolutePath());
                        return true;
                    }
                } catch (Exception ignored) {
                    // not a file drop; ignore
                }
                return false;
            }
        });
    }

    // ---------------- main frame (tabbed multi-task) ----------------
    static class MainFrame extends JFrame {
        final JTabbedPane tabs = new JTabbedPane();
        final JButton newTaskBtn = new JButton();
        final JLabel labLang = new JLabel();
        final JComboBox<String> langBox =
                new JComboBox<>(new String[]{Lang.displayName("zh-CN"), Lang.displayName("en")});

        MainFrame() {
            super(Lang.t("title"));
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLayout(new BorderLayout());

            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 6));
            newTaskBtn.addActionListener(e -> addTask());
            toolbar.add(newTaskBtn);
            toolbar.add(labLang);
            langBox.setSelectedItem(Lang.displayName(Lang.current));
            langBox.addActionListener(e -> {
                Lang.set(displayToCode((String) langBox.getSelectedItem()));
                applyLanguage();
            });
            toolbar.add(langBox);
            add(toolbar, BorderLayout.NORTH);

            add(tabs, BorderLayout.CENTER);
            addTask();

            applyLanguage();
            pack();
            setLocationRelativeTo(null);
            setMinimumSize(new Dimension(860, 560));
        }

        String displayToCode(String display) {
            for (String code : Lang.CODES) {
                if (Lang.displayName(code).equals(display)) return code;
            }
            return Lang.current;
        }

        void addTask() {
            int idx = tabs.getTabCount();
            tabs.addTab("", new TaskPanel(this));
            tabs.setTabComponentAt(idx, new TabHeader(this, idx));
            refreshTabTitle(idx);
            tabs.setSelectedIndex(idx);
        }

        void closeTab(int idx) {
            if (idx < 0 || idx >= tabs.getTabCount()) return;
            TaskPanel p = (TaskPanel) tabs.getComponentAt(idx);
            if (p.task != null && !p.task.isDone()) {
                p.cancelled.set(true); // cancel in-flight work, then close the tab
            }
            tabs.removeTabAt(idx);
            refreshAllTabTitles();
            if (tabs.getTabCount() == 0) addTask(); // always keep at least one task
        }

        void refreshAllTabTitles() {
            for (int i = 0; i < tabs.getTabCount(); i++) refreshTabTitle(i);
        }

        void refreshTabTitle(int i) {
            TabHeader h = (TabHeader) tabs.getTabComponentAt(i);
            h.title.setText(Lang.t("taskTab") + " " + (i + 1));
            h.close.setText(Lang.t("closeTab"));
        }

        void applyLanguage() {
            setTitle(Lang.t("title"));
            newTaskBtn.setText(Lang.t("newTask"));
            labLang.setText(Lang.t("language"));
            refreshAllTabTitles();
            for (int i = 0; i < tabs.getTabCount(); i++) {
                ((TaskPanel) tabs.getComponentAt(i)).applyLanguage();
            }
        }

        /** Close button embedded in each tab header. */
        static class TabHeader extends JPanel {
            final JLabel title = new JLabel();
            final JButton close = new JButton(Lang.t("closeTab"));

            TabHeader(final MainFrame owner, final int idx) {
                setOpaque(false);
                setLayout(new FlowLayout(FlowLayout.LEFT, 4, 0));
                close.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));
                close.setContentAreaFilled(false);
                close.setFocusable(false);
                close.setMargin(new Insets(0, 2, 0, 2));
                close.addActionListener(e ->
                        owner.closeTab(owner.tabs.indexOfTabComponent(TabHeader.this)));
                add(title);
                add(close);
            }
        }
    }

    // ---------------- per-task panel ----------------
    static class TaskPanel extends JPanel {
        final JTextField nandField = new JTextField(36);
        final JTextField boot9Field = new JTextField(36);
        final JTextField otpField = new JTextField(36);
        final JTextField cidHexField = new JTextField(36);
        final JTextField cidFileField = new JTextField(36);
        final JTextField outdirField = new JTextField(36);
        final JComboBox<String> modeBox = new JComboBox<>(new String[]{"dev", "retail"});
        final JCheckBox otpDecBox = new JCheckBox();
        final JCheckBox forceBox = new JCheckBox();
        final JCheckBox showKeysBox = new JCheckBox();
        final JProgressBar progress = new JProgressBar(0, 100);
        final JTextArea logArea = new JTextArea();
        final JButton startBtn = new JButton();
        final JButton cancelBtn = new JButton();
        final JButton bNand = new JButton();
        final JButton bBoot9 = new JButton();
        final JButton bOtp = new JButton();
        final JButton bCid = new JButton();
        final JButton bOutdir = new JButton();
        final JLabel labNand = new JLabel();
        final JLabel labBoot9 = new JLabel();
        final JLabel labOtp = new JLabel();
        final JLabel labCidHex = new JLabel();
        final JLabel labCidFile = new JLabel();
        final JLabel labOutdir = new JLabel();
        final JLabel labMode = new JLabel();
        final java.util.concurrent.atomic.AtomicBoolean cancelled =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        boolean running;
        DecryptTask task;

        TaskPanel(MainFrame owner) {
            setLayout(new BorderLayout());

            JPanel form = new JPanel(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(4, 6, 4, 6);
            c.anchor = GridBagConstraints.WEST;

            addRow(form, c, 0, labNand, nandField, bNand, false);
            addRow(form, c, 1, labBoot9, boot9Field, bBoot9, false);
            addRow(form, c, 2, labOtp, otpField, bOtp, false);
            addRow(form, c, 3, labCidHex, cidHexField, null, false);
            addRow(form, c, 4, labCidFile, cidFileField, bCid, false);
            addRow(form, c, 5, labOutdir, outdirField, bOutdir, true);

            c.gridx = 1;
            c.gridy++;
            JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            opts.add(labMode);
            opts.add(modeBox);
            opts.add(otpDecBox);
            opts.add(forceBox);
            opts.add(showKeysBox);
            form.add(opts, c);

            add(form, BorderLayout.NORTH);

            logArea.setEditable(false);
            logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JScrollPane scroll = new JScrollPane(logArea);
            scroll.setPreferredSize(new Dimension(700, 220));
            add(scroll, BorderLayout.CENTER);

            JPanel south = new JPanel(new BorderLayout());
            progress.setStringPainted(true);
            progress.setIndeterminate(true);
            progress.setVisible(false);
            south.add(progress, BorderLayout.NORTH);
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 6));
            buttons.add(startBtn);
            buttons.add(cancelBtn);
            cancelBtn.setEnabled(false);
            south.add(buttons, BorderLayout.CENTER);
            add(south, BorderLayout.SOUTH);

            // drag & drop onto path fields
            enableFileDrop(nandField);
            enableFileDrop(boot9Field);
            enableFileDrop(otpField);
            enableFileDrop(cidFileField);
            enableFileDrop(outdirField);

            startBtn.addActionListener(e -> startDecrypt());
            cancelBtn.addActionListener(e -> {
                if (task != null && !task.isDone()) {
                    cancelled.set(true);
                    cancelBtn.setEnabled(false);
                    appendLog(Lang.t("cancelTitle") + " - " + Lang.t("cancel") + "…");
                }
            });

            applyLanguage();
        }

        void addRow(JPanel form, GridBagConstraints c, int y, JLabel label,
                    JTextField field, JButton browseBtn, boolean dirsOnly) {
            c.gridx = 0;
            c.gridy = y + 1;
            form.add(label, c);
            c.gridx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1.0;
            form.add(field, c);
            c.weightx = 0;
            if (browseBtn != null) {
                browseBtn.addActionListener(e -> {
                    JFileChooser fc = new JFileChooser();
                    if (dirsOnly) fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                    if (fc.showOpenDialog(TaskPanel.this) == JFileChooser.APPROVE_OPTION) {
                        field.setText(fc.getSelectedFile().getAbsolutePath());
                    }
                });
                form.add(browseBtn, c);
            }
            c.fill = GridBagConstraints.NONE;
        }

        void startDecrypt() {
            Options o = new Options();
            o.nand = nandField.getText().trim();
            o.boot9 = boot9Field.getText().trim();
            o.otp = otpField.getText().trim();
            o.cidHex = cidHexField.getText().trim();
            o.cidFile = cidFileField.getText().trim();
            o.outdir = outdirField.getText().trim();
            o.mode = (String) modeBox.getSelectedItem();
            o.otpDec = otpDecBox.isSelected();
            o.force = forceBox.isSelected();
            o.showKeys = showKeysBox.isSelected();

            logArea.setText("");
            cancelled.set(false);
            running = true;
            startBtn.setEnabled(false);
            cancelBtn.setEnabled(true);
            progress.setVisible(true);
            progress.setString(Lang.t("working"));

            task = new DecryptTask(o);
            task.execute();
        }

        void appendLog(String line) {
            SwingUtilities.invokeLater(() -> {
                logArea.append(line + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }

        void applyLanguage() {
            labNand.setText(Lang.t("nand"));
            labBoot9.setText(Lang.t("boot9"));
            labOtp.setText(Lang.t("otp"));
            labCidHex.setText(Lang.t("cidHex"));
            labCidFile.setText(Lang.t("cidFile"));
            labOutdir.setText(Lang.t("outdir"));
            labMode.setText(Lang.t("mode"));
            otpDecBox.setText(Lang.t("otpDec"));
            forceBox.setText(Lang.t("force"));
            showKeysBox.setText(Lang.t("showKeys"));
            startBtn.setText(Lang.t("start"));
            cancelBtn.setText(Lang.t("cancel"));
            for (JButton b : new JButton[]{bNand, bBoot9, bOtp, bCid, bOutdir}) {
                b.setText(Lang.t("browse"));
            }
            for (JTextField f : new JTextField[]{nandField, boot9Field, otpField,
                    cidFileField, outdirField}) {
                f.setToolTipText(Lang.t("dropHint"));
            }
            if (running) {
                progress.setString(Lang.t("working"));
            }
        }

        class DecryptTask extends SwingWorker<Void, String> {
            final Options o;

            DecryptTask(Options o) {
                this.o = o;
            }

            protected Void doInBackground() throws Exception {
                final Log taskLog = new Log() {
                    public void log(String line) {
                        DecryptTask.this.publish(line);
                    }
                };
                CURRENT_LOG.set(taskLog);
                try {
                    runPipeline(o, true, cancelled);
                } finally {
                    CURRENT_LOG.remove();
                }
                return null;
            }

            protected void process(List<String> chunks) {
                for (String s : chunks) appendLog(s);
            }

            protected void done() {
                running = false;
                startBtn.setEnabled(true);
                cancelBtn.setEnabled(false);
                progress.setVisible(false);
                progress.setString("");
                try {
                    get();
                    appendLog(Lang.t("successTitle"));
                    appendLog(Lang.t("successBody"));
                } catch (InterruptedException e) {
                    appendLog(Lang.t("cancelTitle"));
                } catch (ExecutionException e) {
                    Throwable t = e.getCause() != null ? e.getCause() : e;
                    appendLog(Lang.t("errorTitle"));
                    appendLog(t.getMessage() != null ? t.getMessage() : t.toString());
                    appendLog(Lang.t("abortNote"));
                }
            }
        }
    }
}
