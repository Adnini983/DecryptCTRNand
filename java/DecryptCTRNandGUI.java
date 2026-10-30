/*
 * DecryptCTRNandGUI - 3DS NAND Dump Decryptor (Pure JDK 11, zero external deps)
 *
 * v0.2 - Java implementation kept byte-for-byte compatible with
 *        DecryptCTRNand.ps1 / DecryptCTRNand.py (see tests/).
 *
 * Pure JDK only: javax.swing + javax.crypto + java.util.BigInteger.
 * Runs either as a Swing GUI (double-click / java -jar) or headless CLI:
 *     java -jar DecryptCTRNandGUI.jar --cli --nand ... --boot9 ... --otp ... \
 *          --cid-file ... --mode dev --outdir out --force
 *
 * Build (JDK >= 11; target 11 bytecode):
 *     javac --release 11 -d out/classes DecryptCTRNandGUI.java
 *     jar cfm DecryptCTRNandGUI.jar MANIFEST.MF -C out/classes .
 *     (MANIFEST.MF contains "Main-Class: DecryptCTRNandGUI")
 */

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
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
import java.util.concurrent.ExecutionException;

public class DecryptCTRNandGUI {

    // ---------------- constants ----------------
    static final byte[] OTP_MAGIC = hex("0FB0ADDE");
    static final BigInteger C1 = new BigInteger("1FF9E9AAC5FE0408024591DC5D52768A", 16);
    static final BigInteger MASK_128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
    static final byte[] FIXED_KEYY_CTRNAND_NEW = hex("4D804F4E9990194613A204AC584460BE");
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

            if (absOffset < 0x200) {
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
                p.status = "unsupported"; // TWL nonce scheme not implemented
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
                    if (n >= 0x104 && head[0x100] == 'F' && head[0x101] == 'I' && head[0x102] == 'R' && head[0x103] == 'M') {
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

    /** Routed log target: CLI by default, swapped to the GUI worker while running. */
    static volatile Log CURRENT_LOG = CLI_LOG;

    static void log(String line) {
        CURRENT_LOG.log(line);
    }

    static java.util.concurrent.atomic.AtomicBoolean CANCELLED = new java.util.concurrent.atomic.AtomicBoolean(false);

    // ---------------- pipeline ----------------
    static class Options {
        String nand, boot9, otp, cidHex, cidFile, outdir, mode;
        boolean otpDec, force, showKeys;
    }

    /** Full pipeline: OTP -> CID -> NCSD -> keyinit -> nonce -> partitions. */
    static void runPipeline(Options o, boolean cancelable) throws Exception {
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

        log("=== DecryptCTRNand v0.2 (Java) ===");
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
        if (o.showKeys) {
            log("[+] Derived normalKeys:");
            for (int slot = 0x04; slot <= 0x07; slot++) {
                log("    slot 0x" + String.format("%02X", slot) + ": " + toHex(normalKeys.get(slot)));
            }
        } else {
            log("[+] Derived normalKeys (slots 0x04-0x07): OK (hidden; use --show-keys to display)");
        }

        // 5. nonce
        byte[] nonce = sub(sha256(cid), 0, 16);
        log("[+] CTR nonce derived (SHA256(CID)[:16], hidden)");

        // 6. partitions
        if (o.outdir == null || o.outdir.isEmpty()) {
            log("[*] No output directory: keys derived, partitions not written to disk.");
        } else {
            Path outDir = Paths.get(o.outdir);
            Files.createDirectories(outDir);
            log("[*] Decrypting partitions to: " + o.outdir);
            for (Partition p : parts) {
                if (CANCELLED.get()) throw new RuntimeException("Cancelled by user.");
                if ("unknown".equals(p.status)) {
                    log("    Partition " + p.index + ": unknown crypt/fs type, skipped");
                    continue;
                }
                if (!normalKeys.containsKey(p.slot)) {
                    log("    Partition " + p.index + ": slot 0x" + String.format("%02X", p.slot)
                            + " not derived (" + p.status + "), skipping");
                    continue;
                }
                decryptPartition(nandPath, p, normalKeys.get(p.slot), nonce, outDir,
                        o.force, cancelable, CANCELLED);
            }
        }

        log("=== Summary ===");
        log("OTP: valid (" + o.mode + ")");
        log("NCSD: parsed, " + parts.size() + " non-empty partition(s)");
        log("CID: loaded (hidden)");
        log("Keyinit: completed (slots 0x04-0x07)");
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
    static void runCli(String[] args) {
        Options o = new Options();
        o.mode = "dev";
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--nand": o.nand = args[++i]; break;
                case "--boot9": o.boot9 = args[++i]; break;
                case "--otp": o.otp = args[++i]; break;
                case "--cid": o.cidHex = args[++i]; break;
                case "--cid-file": o.cidFile = args[++i]; break;
                case "--outdir": o.outdir = args[++i]; break;
                case "--mode":
                    String m = args[++i];
                    if (!"dev".equals(m) && !"retail".equals(m)) {
                        System.err.println("[!] --mode must be dev or retail");
                        System.exit(1);
                    }
                    o.mode = m;
                    break;
                case "--otp-dec": o.otpDec = true; break;
                case "--force": o.force = true; break;
                case "--show-keys": o.showKeys = true; break;
                default:
                    System.err.println("[!] unknown argument: " + a);
                    System.exit(1);
            }
        }
        try {
            runPipeline(o, false);
        } catch (Exception e) {
            System.err.println("[ERROR] " + e.getMessage());
            System.err.println("Decryption aborted; no incomplete partition files were left behind.");
            System.exit(1);
        }
    }

    // ---------------- GUI ----------------
    public static void main(String[] args) {
        if (args.length > 0 && "--cli".equals(args[0])) {
            runCli(Arrays.copyOfRange(args, 1, args.length));
            return;
        }
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new MainFrame().setVisible(true);
            }
        });
    }

    static class MainFrame extends JFrame {
        final JTextField nandField = new JTextField(40);
        final JTextField boot9Field = new JTextField(40);
        final JTextField otpField = new JTextField(40);
        final JTextField cidHexField = new JTextField(40);
        final JTextField cidFileField = new JTextField(40);
        final JTextField outdirField = new JTextField(40);
        final JComboBox<String> modeBox = new JComboBox<>(new String[]{"dev", "retail"});
        final JCheckBox otpDecBox = new JCheckBox("OTP is already decrypted (-OtpDecrypted)");
        final JCheckBox forceBox = new JCheckBox("Force overwrite existing outputs");
        final JCheckBox showKeysBox = new JCheckBox("Show derived keys (hidden by default)");
        final JProgressBar progress = new JProgressBar(0, 100);
        final JTextArea logArea = new JTextArea();
        final JButton startBtn = new JButton("Start Decryption");
        final JButton cancelBtn = new JButton("Cancel");
        DecryptTask task;

        MainFrame() {
            super("DecryptCTRNand v0.2 (Pure JDK 11)");
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLayout(new BorderLayout());

            JPanel form = new JPanel(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(4, 6, 4, 6);
            c.anchor = GridBagConstraints.WEST;
            c.gridx = 0;
            c.gridy = 0;

            addRow(form, c, 0, "NAND dump:", nandField, "Select NAND");
            addRow(form, c, 1, "boot9.bin:", boot9Field, "Select boot9");
            addRow(form, c, 2, "OTP file:", otpField, "Select OTP");
            addRow(form, c, 3, "CID (hex):", cidHexField, "");
            addRow(form, c, 4, "CID file:", cidFileField, "Select CID");
            addRow(form, c, 5, "Output dir:", outdirField, "Select output dir");

            c.gridx = 1;
            c.gridy++;
            JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            opts.add(new JLabel("Mode:"));
            opts.add(modeBox);
            opts.add(otpDecBox);
            opts.add(forceBox);
            opts.add(showKeysBox);
            form.add(opts, c);

            add(form, BorderLayout.NORTH);

            logArea.setEditable(false);
            logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JScrollPane scroll = new JScrollPane(logArea);
            scroll.setPreferredSize(new Dimension(760, 260));
            add(scroll, BorderLayout.CENTER);

            JPanel south = new JPanel(new BorderLayout());
            progress.setStringPainted(true);
            progress.setString("");
            progress.setIndeterminate(true);
            progress.setVisible(false);
            south.add(progress, BorderLayout.NORTH);
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 6));
            buttons.add(startBtn);
            buttons.add(cancelBtn);
            cancelBtn.setEnabled(false);
            south.add(buttons, BorderLayout.CENTER);
            add(south, BorderLayout.SOUTH);

            startBtn.addActionListener(e -> startDecrypt());
            cancelBtn.addActionListener(e -> {
                if (task != null) {
                    CANCELLED.set(true);
                    cancelBtn.setEnabled(false);
                    log("Cancel requested...");
                }
            });

            pack();
            setLocationRelativeTo(null);
            setMinimumSize(new Dimension(780, 480));
        }

        void addRow(JPanel form, GridBagConstraints c, int y, String label,
                    JTextField field, String browseText) {
            c.gridx = 0;
            c.gridy = y + 1;
            form.add(new JLabel(label), c);
            c.gridx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1.0;
            form.add(field, c);
            c.weightx = 0;
            if (!browseText.isEmpty()) {
                JButton b = new JButton("Browse");
                b.addActionListener(e -> {
                    JFileChooser fc = new JFileChooser();
                    if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                        field.setText(fc.getSelectedFile().getAbsolutePath());
                    }
                });
                form.add(b, c);
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
            CANCELLED.set(false);
            startBtn.setEnabled(false);
            cancelBtn.setEnabled(true);
            progress.setVisible(true);
            progress.setString("Working...");

            task = new DecryptTask(o);
            task.execute();
        }

        void log(String line) {
            SwingUtilities.invokeLater(() -> {
                logArea.append(line + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }

        class DecryptTask extends SwingWorker<Void, String> {
            final Options o;

            DecryptTask(Options o) {
                this.o = o;
            }

            protected Void doInBackground() throws Exception {
                CURRENT_LOG = new Log() {
                    public void log(String line) {
                        DecryptTask.this.publish(line);
                    }
                };
                try {
                    runPipeline(o, true);
                } finally {
                    CURRENT_LOG = CLI_LOG;
                }
                return null;
            }

            protected void process(List<String> chunks) {
                for (String s : chunks) log(s);
            }

            protected void done() {
                startBtn.setEnabled(true);
                cancelBtn.setEnabled(false);
                progress.setVisible(false);
                try {
                    get();
                    log("=== SUCCESS ===");
                    log("All selected partitions decrypted and verified.");
                } catch (InterruptedException e) {
                    log("=== CANCELLED ===");
                } catch (ExecutionException e) {
                    Throwable t = e.getCause() != null ? e.getCause() : e;
                    log("=== ERROR ===");
                    log(t.getMessage());
                    log("Decryption aborted; no incomplete partition files were left behind.");
                }
            }
        }
    }
}
