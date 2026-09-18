"""MIME assembly for sealed messages and carrier auto-detection on receipt."""

import base64
import html as _html
import io
from email import message_from_bytes, policy
from email.message import EmailMessage

from . import carriers

CARRIERS = ("header", "signature", "logo")
# Standing rule (2026-09-18, Lance): every outgoing message, sealed or
# ordinary, carries the sender's public key in the headers, so the key is
# just routine header furniture instead of a tell that only appears on
# secret mail. Neutral names on purpose: nothing here names the system.
PUBKEY_HEADER = "X-Public-Key"
SIGNKEY_HEADER = "X-Signing-Key"
# Retired name, still honored when reading old sealed mail.
LEGACY_PUBKEY_HEADER = "X-Secretservice-Pubkey"


def _html_cover(body, sig_name):
    paras = "".join(
        "<p>%s</p>" % _html.escape(p).replace("\n", "<br>")
        for p in body.split("\n\n") if p.strip())
    if sig_name:
        sig = ("<p>--<br>%s<br>"
               "<img src=\"cid:secretservice-logo\" width=\"140\" alt=\"\">"
               "</p>" % _html.escape(sig_name))
    else:
        sig = ("<p><img src=\"cid:secretservice-logo\" width=\"140\" "
               "alt=\"\"></p>")
    return "<html><body>%s%s</body></html>" % (paras, sig)


def build_message(to_addr, from_addr, subject, body, carrier, envelope,
                  logo_path=None, sig_name="", sender_pubkey=None,
                  sender_sigkey=None):
    """Build the full MIME message (bytes) for one sealed envelope.

    sender_pubkey: base64 X25519 key advertised in the X-Public-Key header
    so the recipient can reply secretly. sender_sigkey: base64 Ed25519
    verify key advertised in X-Signing-Key when the message is signed.
    """
    if carrier not in CARRIERS:
        raise ValueError("carrier must be one of: %s" % ", ".join(CARRIERS))

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    if sender_pubkey:
        msg[PUBKEY_HEADER] = sender_pubkey
    if sender_sigkey:
        msg[SIGNKEY_HEADER] = sender_sigkey

    if carrier == "header":
        msg.set_content(body)
        for i, chunk in enumerate(carriers.header_chunks(envelope), 1):
            msg["%s%d" % (carriers.HEADER_PREFIX, i)] = chunk
    elif carrier == "signature":
        msg.set_content(carriers.sig_embed(envelope, body))
    elif carrier == "logo":
        img = carriers.logo_embed(envelope, logo_path)
        png = carriers.image_to_png_bytes(img)
        html_part = EmailMessage()
        html_part.set_content(_html_cover(body, sig_name), subtype="html")
        html_part.add_related(png, "image", "png", cid="<secretservice-logo>",
                              filename="logo.png", disposition="inline")
        msg.set_content(body)  # plain-text fallback
        msg.add_alternative(html_part)
    return msg.as_bytes()


def _plain_text(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if (part.get_content_type() == "text/plain"
                    and not part.get_filename()):
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


def _header_key(raw_bytes, *names):
    """Return a validated 32-byte base64 key from the first matching header."""
    try:
        msg = message_from_bytes(raw_bytes, policy=policy.default)
    except Exception:
        return None
    for name in names:
        try:
            val = (msg.get(name) or "").strip()
        except Exception:
            continue
        if not val:
            continue
        try:
            raw = base64.b64decode(val, validate=True)
        except Exception:
            continue
        if len(raw) == 32:
            return val
    return None


def sender_pubkey_from_raw(raw_bytes):
    """Return the sender's advertised X25519 public key from message headers,
    or None. Honors the retired X-Secretservice-Pubkey name too. Never raises.
    """
    return _header_key(raw_bytes, PUBKEY_HEADER, LEGACY_PUBKEY_HEADER)


def sender_sigkey_from_raw(raw_bytes):
    """Return the sender's advertised Ed25519 verify key, or None.
    Never raises."""
    return _header_key(raw_bytes, SIGNKEY_HEADER)


def photo_keys_from_raw(raw_bytes):
    """Find public keys hidden in attached/inline photos. Returns [base64]."""
    found = []
    try:
        msg = message_from_bytes(raw_bytes, policy=policy.default)
    except Exception:
        return found
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
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            key = carriers.photokey_extract(img)
        except Exception:
            continue
        if key and key not in found:
            found.append(key)
    return found


def extract_from_raw(raw_bytes):
    """Auto-detect carrier in raw MIME. Returns (carrier, envelope) or (None, None)."""
    msg = message_from_bytes(raw_bytes, policy=policy.default)

    env = carriers.header_extract(msg)
    if env:
        return "header", env

    text = _plain_text(msg)
    env = carriers.sig_extract(text)
    if env:
        return "signature", env

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
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            env = carriers.logo_extract(img)
        except Exception:
            continue
        if env:
            return "logo", env

    return None, None
