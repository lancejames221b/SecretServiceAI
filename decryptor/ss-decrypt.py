#!/usr/bin/env python3
"""ss-decrypt.py: portable secretservice decryptor. Standard library + pynacl only.

No email account access needed. You only need:
  1. a saved raw email file (.eml) -- see README.md for how to save one,
  2. your private key file (created with --genkey).

Usage:
  python3 ss-decrypt.py --genkey mykey.key
      Generate a keypair. The private key is saved to mykey.key (readable only
      by you) and your public key is printed. Send the public key to the person who gave you this tool.

  python3 ss-decrypt.py --eml message.eml --key mykey.key
      Auto-detect the hidden carrier (headers, signature, or logo image),
      decrypt with your private key, and print the secret message.
"""

import argparse
import base64
import os
import re
import struct
import sys
import zlib
from email import message_from_bytes, policy

ENVELOPE_VERSION = "SS1"


# ---------------------------------------------------------------- key files

def _write_private(path, seed):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(seed).decode("ascii") + "\n")


def genkey(path):
    from nacl.public import PrivateKey
    if os.path.exists(path):
        raise SystemExit("error: %s already exists, will not overwrite" % path)
    priv = PrivateKey.generate()
    _write_private(path, bytes(priv))
    print("Private key saved to %s (only you can read it)." % path)
    print("Send this public key to the person who gave you this tool:")
    print(base64.b64encode(bytes(priv.public_key)).decode("ascii"))


def load_private(path):
    from nacl.public import PrivateKey
    with open(path, "r") as f:
        return PrivateKey(base64.b64decode(f.read().strip()))


# ------------------------------------------------------------- envelope

def open_envelope(envelope, priv):
    from nacl.public import SealedBox
    ver, sep, b64 = envelope.partition(":")
    if ver != ENVELOPE_VERSION or not sep or not b64:
        raise ValueError("not a secretservice v1 envelope")
    return SealedBox(priv).decrypt(base64.b64decode(b64)).decode("utf-8")


# ------------------------------------------------- carrier: custom headers

def _header_extract(msg):
    parts = {}
    for name, value in msg.items():
        lname = name.lower()
        if lname.startswith("x-ss-"):
            try:
                n = int(lname[len("x-ss-"):])
            except ValueError:
                continue
            parts[n] = re.sub(r"\s+", "", value or "")
    if not parts:
        return None
    env = "".join(parts[n] for n in sorted(parts))
    return env if env.startswith(ENVELOPE_VERSION + ":") else None


# ------------------------------------------- carrier: zero-width signature

_ZW0 = "\u200b"
_ZW1 = "\u200c"
_MARK = "\u2060"


def _plain_text(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.get_filename():
                try:
                    return part.get_content()
                except Exception:
                    continue
        return None
    if msg.get_content_type() == "text/plain":
        try:
            return msg.get_content()
        except Exception:
            return None
    return None


def _sig_extract(text):
    if not text:
        return None
    m = re.search(_MARK + "([\u200b\u200c]+)" + _MARK, text)
    if not m:
        return None
    bits = "".join("0" if c == _ZW0 else "1" for c in m.group(1))
    bits = bits[:len(bits) // 8 * 8]
    if not bits:
        return None
    raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    try:
        env = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return env if env.startswith(ENVELOPE_VERSION + ":") else None


# ------------------------------------------------- carrier: logo PNG (LSB)

def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _decode_png(data):
    """Minimal PNG decoder: 8-bit RGB/RGBA, non-interlaced. Returns (w, h, rgb)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG file")
    pos, idat = 8, b""
    w = h = bitd = ctype = interlace = None
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ, chunk = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + ln]
        pos += 12 + ln
        if typ == b"IHDR":
            w, h, bitd, ctype, _, _, interlace = struct.unpack(">IIBBBBB", chunk)
        elif typ == b"IDAT":
            idat += chunk
        elif typ == b"IEND":
            break
    if bitd != 8 or ctype not in (2, 6) or interlace != 0:
        raise ValueError("only 8-bit RGB/RGBA non-interlaced PNG is supported")
    ch = 3 if ctype == 2 else 4
    raw = zlib.decompress(idat)
    stride = w * ch
    out = bytearray()
    prev = bytearray(stride)
    p = 0
    for _ in range(h):
        f = raw[p]
        p += 1
        line = bytearray(raw[p:p + stride])
        p += stride
        if f == 1:
            for i in range(ch, stride):
                line[i] = (line[i] + line[i - ch]) & 0xFF
        elif f == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif f == 3:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif f == 4:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                line[i] = (line[i] + _paeth(a, b, c)) & 0xFF
        elif f != 0:
            raise ValueError("unsupported PNG filter")
        out += line
        prev = line
    if ch == 4:
        rgb = bytearray()
        for i in range(0, len(out), 4):
            rgb += out[i:i + 3]
        return w, h, bytes(rgb)
    return w, h, bytes(out)


def _logo_extract(rgb):
    bits = "".join(str(b & 1) for b in rgb)
    if len(bits) < 32:
        return None
    total = int(bits[:32], 2)
    if total > 100000:
        return None
    need = 32 + total * 8
    if len(bits) < need:
        return None
    raw = bytes(int(bits[32 + i:32 + i + 8], 2) for i in range(0, total * 8, 8))
    try:
        env = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return env if env.startswith(ENVELOPE_VERSION + ":") else None


def _image_extract(msg):
    for part in msg.walk():
        if part.get_content_maintype() != "image":
            continue
        try:
            data = part.get_payload(decode=True)
        except Exception:
            continue
        if not data:
            continue
        try:
            _, _, rgb = _decode_png(data)
            env = _logo_extract(rgb)
        except Exception:
            continue
        if env:
            return env
    return None


# ------------------------------------------------------------------ main

def decrypt_eml(eml_path, key_path):
    with open(eml_path, "rb") as f:
        msg = message_from_bytes(f.read(), policy=policy.default)
    env = _header_extract(msg)
    carrier = "header" if env else None
    if not env:
        env = _sig_extract(_plain_text(msg))
        carrier = "signature" if env else None
    if not env:
        env = _image_extract(msg)
        carrier = "logo" if env else None
    if not env:
        raise SystemExit("No hidden secretservice payload found in this email.")
    priv = load_private(key_path)
    try:
        plaintext = open_envelope(env, priv)
    except Exception:
        raise SystemExit("Found a payload (%s carrier) but your key could not open it."
                         % carrier)
    return plaintext


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decrypt secretservice sealed emails. Needs only Python 3 and pynacl.")
    ap.add_argument("--genkey", metavar="KEYFILE",
                    help="generate a keypair into KEYFILE and print your public key")
    ap.add_argument("--eml", metavar="FILE", help="saved raw email file (.eml)")
    ap.add_argument("--key", metavar="KEYFILE", help="your private key file")
    args = ap.parse_args(argv)

    if args.genkey:
        genkey(args.genkey)
        return
    if not args.eml or not args.key:
        ap.error("--eml and --key are both required (or use --genkey)")
    print(decrypt_eml(args.eml, args.key))


if __name__ == "__main__":
    main()
