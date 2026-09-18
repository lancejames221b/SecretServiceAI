"""The three carriers that hide a sealed envelope inside ordinary email.

header:    envelope base64 split into 60-char chunks in X-Ss-1, X-Ss-2, ...
signature: envelope bits as zero-width chars (U+200B=0, U+200C=1) wrapped in
           U+2060 markers, placed right after the "-- " signature delimiter.
logo:      LSB steganography in a PNG: 4-byte big-endian length prefix plus
           envelope bytes, 1 bit per RGB channel LSB.
"""

import io
import re
import struct

# --- header carrier ---------------------------------------------------------

HEADER_PREFIX = "X-Ss-"
HEADER_CHUNK = 60


def header_chunks(envelope):
    return [envelope[i:i + HEADER_CHUNK]
            for i in range(0, len(envelope), HEADER_CHUNK)]


def header_extract(msg):
    """Reassemble X-Ss-N headers from a parsed email Message. None if absent."""
    parts = {}
    for name, value in msg.items():
        lname = name.lower()
        if lname.startswith(HEADER_PREFIX.lower()):
            try:
                n = int(lname[len(HEADER_PREFIX):])
            except ValueError:
                continue
            parts[n] = re.sub(r"\s+", "", value or "")
    if not parts:
        return None
    env = "".join(parts[n] for n in sorted(parts))
    return env if env.startswith("SS1:") else None


# --- signature carrier (zero-width steganography) ----------------------------

_ZW0 = "\u200b"   # zero width space -> bit 0
_ZW1 = "\u200c"   # zero width non-joiner -> bit 1
_MARK = "\u2060"  # word joiner, wraps the payload


def sig_embed(envelope, body):
    """Append the envelope as zero-width chars after the signature delimiter."""
    bits = "".join(format(b, "08b") for b in envelope.encode("ascii"))
    zw = _MARK + "".join(_ZW0 if ch == "0" else _ZW1 for ch in bits) + _MARK
    lines = body.split("\n")
    idx = None
    for i, line in enumerate(lines):
        if line == "--" or line.startswith("-- "):
            idx = i
    if idx is None:
        return body.rstrip("\n") + "\n\n-- \n" + zw + "\n"
    head = "\n".join(lines[:idx + 1])
    tail = "\n".join(lines[idx + 1:])
    out = head + "\n" + zw
    if tail.strip():
        out += "\n" + tail
    return out + "\n"


def sig_extract(text):
    """Find the zero-width payload in plain text. None if absent."""
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
    return env if env.startswith("SS1:") else None


# --- logo carrier (LSB steganography in PNG) ---------------------------------

_LSB_CAP = 100000  # sanity cap on length-prefixed payloads


def _lsb_embed(img, payload):
    """Hide length-prefixed bytes in RGB LSBs. Returns the PIL Image."""
    bits = "".join(format(b, "08b") for b in payload)
    w, h = img.size
    if len(bits) > w * h * 3:
        raise ValueError(
            "image too small for payload: need %d bits, have %d"
            % (len(bits), w * h * 3))
    px = img.load()
    i = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            if i < len(bits):
                r = (r & 0xFE) | int(bits[i]); i += 1
            if i < len(bits):
                g = (g & 0xFE) | int(bits[i]); i += 1
            if i < len(bits):
                b = (b & 0xFE) | int(bits[i]); i += 1
            px[x, y] = (r, g, b)
            if i >= len(bits):
                break
        if i >= len(bits):
            break
    return img


def _lsb_extract_raw(img):
    """Read length-prefixed bytes from RGB LSBs. None if absent/invalid."""
    img = img.convert("RGB")
    px = img.load()
    w, h = img.size
    bits = []
    total = None
    need = 32
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            bits.append(str(r & 1)); bits.append(str(g & 1)); bits.append(str(b & 1))
            if total is None and len(bits) >= 32:
                total = int("".join(bits[:32]), 2)
                if total > _LSB_CAP:  # not our payload
                    return None
                need = 32 + total * 8
            if total is not None and len(bits) >= need:
                break
        if total is not None and len(bits) >= need:
            break
    if total is None or len(bits) < need:
        return None
    return bytes(int("".join(bits[32 + i:32 + i + 8]), 2)
                 for i in range(0, total * 8, 8))


def default_logo(size=400):
    """Generate a tasteful monogram logo PNG (PIL Image)."""
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (size, size), (26, 32, 48))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([10, 10, size - 10, size - 10], radius=40,
                        outline=(198, 178, 128), width=4)
    try:
        font = ImageFont.load_default(size=size // 4)
    except TypeError:  # very old Pillow
        font = ImageFont.load_default()
    text = "LJ"
    bbox = d.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text(((size - tw) / 2, (size - th) / 2 - bbox[1]),
           text, font=font, fill=(198, 178, 128))
    return img


def logo_embed(envelope, logo_path=None):
    """Hide the envelope in a PNG's RGB LSBs. Returns a PIL Image."""
    from PIL import Image
    img = Image.open(logo_path).convert("RGB") if logo_path else default_logo()
    payload = struct.pack(">I", len(envelope)) + envelope.encode("ascii")
    return _lsb_embed(img, payload)


def logo_extract(img):
    """Recover the envelope from a PNG's RGB LSBs. None if absent/invalid."""
    raw = _lsb_extract_raw(img)
    if raw is None:
        return None
    try:
        env = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return env if env.startswith("SS1:") else None


# --- meme carrier: a sealed envelope hidden in any image, for texting --------

MEME_PREFIX = b"SSM1:"


def meme_embed(envelope, image_path, pubkey_b64=None):
    """Hide a sealed envelope in ANY image (a meme, a photo) so it can be
    texted. Converts to PNG (lossless) automatically. Optionally also hides
    the sender's public key for key discovery. Returns a PIL Image.

    IMPORTANT: the recipient must receive the EXACT bytes. Texting apps
    recompress photos sent as photos, which destroys the hidden data.
    Send the image AS A FILE / DOCUMENT (Signal: + > File, WhatsApp:
    attach > Document), never as a photo.
    """
    from PIL import Image
    img = Image.open(image_path).convert("RGB")
    inner = (MEME_PREFIX + struct.pack(">I", len(envelope))
             + envelope.encode("ascii"))
    if pubkey_b64:
        key = pubkey_b64.strip().encode("ascii")
        inner += (PHOTOKEY_PREFIX.encode("ascii") + struct.pack(">I", len(key))
                  + key)
    payload = struct.pack(">I", len(inner)) + inner
    return _lsb_embed(img, payload)


def meme_extract(img):
    """Recover (envelope, pubkey_or_None) from a meme image.
    None envelope if absent/invalid."""
    raw = _lsb_extract_raw(img)
    if raw is None or not raw.startswith(MEME_PREFIX):
        return None, None
    rest = raw[len(MEME_PREFIX):]
    if len(rest) < 4:
        return None, None
    (env_len,) = struct.unpack(">I", rest[:4])
    env = rest[4:4 + env_len]
    try:
        envelope = env.decode("ascii")
    except UnicodeDecodeError:
        return None, None
    if not envelope.startswith("SS1:"):
        return None, None
    pubkey = None
    tail = rest[4 + env_len:]
    if tail.startswith(PHOTOKEY_PREFIX.encode("ascii")) and len(tail) >= 10:
        (klen,) = struct.unpack(">I", tail[6:10])
        try:
            pubkey = tail[10:10 + klen].decode("ascii")
        except UnicodeDecodeError:
            pubkey = None
    return envelope, pubkey


# --- photo key: a public key hidden in an ordinary photo ---------------------

PHOTOKEY_PREFIX = "SSPK1:"


def photokey_embed(pubkey_b64, image_path):
    """Hide a base64 public key in a photo's RGB LSBs. Returns a PIL Image.

    The key is invisible to viewers; anyone running photokey_extract on the
    image recovers it. Used for the signature avatar so every mail quietly
    advertises the sender's public key.
    """
    from PIL import Image
    img = Image.open(image_path).convert("RGB")
    data = (PHOTOKEY_PREFIX + pubkey_b64.strip()).encode("ascii")
    payload = struct.pack(">I", len(data)) + data
    return _lsb_embed(img, payload)


def photokey_extract(img):
    """Recover a hidden public key (base64) from a photo. None if absent."""
    raw = _lsb_extract_raw(img)
    if raw is None:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text.startswith(PHOTOKEY_PREFIX):
        return None
    key = text[len(PHOTOKEY_PREFIX):].strip()
    return key or None


def image_to_png_bytes(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
