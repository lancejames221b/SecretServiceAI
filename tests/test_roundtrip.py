"""Local round-trip tests for secretservice: seal each carrier, extract, decrypt.

Run: python3 tests/test_roundtrip.py
Uses an isolated key directory via SECRETSERVICE_KEYS_DIR; no network, no send.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from secretservice import crypto, mime  # noqa: E402

SECRET = "the midnight rendezvous is at the old lighthouse, bring the ledger"
BODY = ("Hi,\n\nJust following up on yesterday's meeting. The action items "
        "are on track and I will have the notes over by Friday.\n\n"
        "Best,\nLance\n\n-- \nLance James")


def check(name, cond, detail=""):
    print(("PASS" if cond else "FAIL"), "-", name, detail)
    if not cond:
        sys.exit(1)


def main():
    tmp = tempfile.mkdtemp(prefix="ss-test-")
    os.environ["SECRETSERVICE_KEYS_DIR"] = os.path.join(tmp, "keys")

    pub = crypto.generate("testkey")
    check("keygen writes 0600 key file",
          oct(os.stat(crypto.key_path("testkey")).st_mode & 0o777) == "0o600")
    check("pubkey round-trips", crypto.pubkey_of("testkey") == pub)

    for carrier in ("header", "signature", "logo"):
        env = crypto.seal_envelope(SECRET, pub)
        check("envelope format", env.startswith("SS1:"))
        raw = mime.build_message(
            to_addr="a@example.com", from_addr="b@example.com",
            subject="test", body=BODY, carrier=carrier, envelope=env)
        det, got = mime.extract_from_raw(raw)
        check("%s carrier detected" % carrier, det == carrier, "got %r" % det)
        label, plain = crypto.try_decrypt(got)
        check("%s decrypts to original" % carrier,
              plain == SECRET and label == "testkey",
              "(%d byte MIME)" % len(raw))

    # no payload present
    from email.message import EmailMessage
    plain_msg = EmailMessage()
    plain_msg["From"] = "a@example.com"
    plain_msg.set_content("just a normal email")
    det, got = mime.extract_from_raw(plain_msg.as_bytes())
    check("clean email yields no payload", det is None and got is None)

    # wrong key cannot open it
    crypto.generate("otherkey")
    os.environ["SECRETSERVICE_KEYS_DIR"] = os.path.join(tmp, "keys2")
    os.makedirs(os.environ["SECRETSERVICE_KEYS_DIR"], exist_ok=True)
    crypto.generate("unrelated")
    env = crypto.seal_envelope(SECRET, pub)  # sealed to testkey, not present here
    try:
        crypto.try_decrypt(env)
        check("wrong-key decryption fails cleanly", False)
    except ValueError as e:
        check("wrong-key decryption fails cleanly", True, "(%s)" % e)

    # CLI dry-run smoke test: seal via the ss entry point, re-parse the file.
    # Invokes the console-script main() in-process (works installed or not).
    os.environ["SECRETSERVICE_KEYS_DIR"] = os.path.join(tmp, "keys")
    from secretservice.cli import main as ss_main
    dry = os.path.join(tmp, "dry.eml")
    bodyf = os.path.join(tmp, "body.txt")
    with open(bodyf, "w") as f:
        f.write(BODY)
    try:
        ss_main(["seal", "--to-pubkey", pub, "--carrier", "header",
                 "--body-file", bodyf, "--message", SECRET,
                 "--subject", "dry run", "--to", "a@example.com",
                 "--dry-run", dry])
        rc = 0
    except SystemExit as e:
        rc = e.code or 0
    except Exception as e:
        rc = 1
        print("seal raised: %s" % e)
    check("ss seal --dry-run exits 0", rc == 0)
    with open(dry, "rb") as f:
        det, got = mime.extract_from_raw(f.read())
    check("dry-run file carries the payload", det == "header" and got is not None)
    _, plain = crypto.try_decrypt(got)
    check("dry-run payload decrypts", plain == SECRET)

    # Meme carrier round trip: jpg in, sealed png out, extracts and decrypts.
    from PIL import Image
    from secretservice import carriers
    meme_src = os.path.join(tmp, "meme.jpg")
    meme_out = os.path.join(tmp, "meme-secret.png")
    Image.new("RGB", (800, 600), (200, 30, 30)).save(meme_src, format="JPEG")
    img = carriers.meme_embed(crypto.seal_envelope(SECRET, pub), meme_src,
                              pubkey_b64=pub)
    img.save(meme_out, format="PNG")
    env, pk = carriers.meme_extract(Image.open(meme_out))
    check("meme carrier extracts", env is not None and env.startswith("SS1:"))
    check("meme carrier advertises key", pk == pub)
    _, mplain = crypto.try_decrypt(env)
    check("meme payload decrypts", mplain == SECRET)

    print("ALL ROUND-TRIP TESTS PASSED")


if __name__ == "__main__":
    main()
