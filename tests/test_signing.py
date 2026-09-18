"""Tests for the optional Ed25519 signing layer.

Run: .venv/bin/python tests/test_signing.py
Isolated key directory via SECRETSERVICE_KEYS_DIR; no network, no send.
"""
import base64
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from secretservice import crypto, mime  # noqa: E402

SECRET = "the eagle has landed"
BODY = "Hi,\n\nQuick follow-up on yesterday.\n\nBest,\nLance"


def check(name, cond, detail=""):
    print(("PASS" if cond else "FAIL"), "-", name, detail)
    if not cond:
        sys.exit(1)


def main():
    tmp = tempfile.mkdtemp(prefix="ss-sign-test-")
    os.environ["SECRETSERVICE_KEYS_DIR"] = os.path.join(tmp, "keys")

    enc_pub = crypto.generate("alice")
    sig_pub = crypto.sig_generate("alice")
    check("sig keygen writes 0600 file",
          oct(os.stat(crypto.sig_key_path("alice")).st_mode & 0o777) == "0o600")
    check("sig pubkey round-trips", crypto.sig_pubkey_of("alice") == sig_pub)

    # sign -> verify round trip
    inner = crypto.sign_inner(SECRET, "alice")
    check("signed container format", inner.startswith("SSS1:"))
    signed, sig_b64, clean = crypto.unwrap_signed(inner)
    check("unwrap parses container", signed and clean == SECRET)
    check("signature verifies",
          crypto.verify_inner(sig_pub, sig_b64, SECRET))

    # unsigned text unwraps as unsigned
    signed2, sb2, clean2 = crypto.unwrap_signed(SECRET)
    check("unsigned text stays unsigned",
          not signed2 and sb2 is None and clean2 == SECRET)

    # tampered signature fails
    bad = bytearray(base64.b64decode(sig_b64))
    bad[0] ^= 1
    bad_b64 = base64.b64encode(bytes(bad)).decode()
    check("tampered signature rejected",
          not crypto.verify_inner(sig_pub, bad_b64, SECRET))

    # wrong verify key fails
    crypto.sig_generate("mallory")
    check("wrong verify key rejected",
          not crypto.verify_inner(crypto.sig_pubkey_of("mallory"),
                                  sig_b64, SECRET))

    # full sealed round trip with key advertisement headers
    env = crypto.seal_signed_envelope(SECRET, enc_pub, "alice")
    raw = mime.build_message(
        to_addr="bob@example.com", from_addr="alice@example.com",
        subject="test", body=BODY, carrier="header", envelope=env,
        sender_pubkey=crypto.pubkey_of("alice"),
        sender_sigkey=crypto.sig_pubkey_of("alice"))
    check("X-Public-Key header advertised",
          mime.sender_pubkey_from_raw(raw) == crypto.pubkey_of("alice"))
    check("X-Signing-Key header advertised",
          mime.sender_sigkey_from_raw(raw) == crypto.sig_pubkey_of("alice"))
    det, got = mime.extract_from_raw(raw)
    check("carrier detected", det == "header")
    label, inner2 = crypto.try_decrypt(got)
    check("decrypts", label == "alice")
    signed3, sig_b64_3, clean3 = crypto.unwrap_signed(inner2)
    check("signed container survives the round trip",
          signed3 and clean3 == SECRET)
    check("signature verifies after round trip",
          crypto.verify_inner(mime.sender_sigkey_from_raw(raw),
                              sig_b64_3, clean3))

    # legacy header name still honored on receipt
    from email.message import EmailMessage
    legacy = EmailMessage()
    legacy["From"] = "old@example.com"
    legacy["X-Secretservice-Pubkey"] = crypto.pubkey_of("alice")
    legacy.set_content("old mail")
    check("legacy X-Secretservice-Pubkey still read",
          mime.sender_pubkey_from_raw(legacy.as_bytes())
          == crypto.pubkey_of("alice"))

    print("all signing tests passed")


if __name__ == "__main__":
    main()
