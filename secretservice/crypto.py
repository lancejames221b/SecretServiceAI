"""Public-key crypto for secretservice.

Uses NaCl sealed boxes (crypto_box_seal): only the recipient's public key is
needed to seal, an ephemeral sender keypair is generated per message, and the
sender stays deniable. Envelope format v1:

    SS1:<base64(sealed_box(utf8 plaintext))>
"""

import base64
import os
import re

from nacl.public import PrivateKey, PublicKey, SealedBox

ENVELOPE_VERSION = "SS1"
DEFAULT_KEYS_DIR = os.path.expanduser("~/.config/secretservice/keys")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def keys_dir():
    """Key directory, overridable via SECRETSERVICE_KEYS_DIR (used by tests)."""
    d = os.environ.get("SECRETSERVICE_KEYS_DIR", DEFAULT_KEYS_DIR)
    os.makedirs(d, exist_ok=True)
    return d


def _check_label(label):
    if not _LABEL_RE.match(label or ""):
        raise ValueError("key label must match [A-Za-z0-9_-], max 64 chars")
    return label


def key_path(label):
    return os.path.join(keys_dir(), _check_label(label) + ".key")


def generate(label):
    """Generate an X25519 keypair. Returns the public key (base64).

    The private key is written with 0600 permissions and is never printed.
    """
    priv = PrivateKey.generate()
    path = key_path(label)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(bytes(priv)).decode("ascii") + "\n")
    return base64.b64encode(bytes(priv.public_key)).decode("ascii")


def load_private(label):
    with open(key_path(label), "r") as f:
        return PrivateKey(base64.b64decode(f.read().strip()))


def load_all_private():
    """Return [(label, PrivateKey)] for every key in the key directory."""
    found = []
    d = keys_dir()
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".key"):
            label = fn[:-4]
            try:
                found.append((label, load_private(label)))
            except Exception:
                continue
    return found


def pubkey_of(label):
    return base64.b64encode(bytes(load_private(label).public_key)).decode("ascii")


def seal_envelope(plaintext, to_pubkey_b64):
    """Seal plaintext to a recipient public key. Returns the SS1 envelope."""
    pub = PublicKey(base64.b64decode(to_pubkey_b64.strip()))
    sealed = SealedBox(pub).encrypt(plaintext.encode("utf-8"))
    return ENVELOPE_VERSION + ":" + base64.b64encode(sealed).decode("ascii")


def open_envelope(envelope, priv):
    """Open an envelope with one private key. Raises on bad format or failure."""
    ver, sep, b64 = envelope.partition(":")
    if ver != ENVELOPE_VERSION or not sep or not b64:
        raise ValueError("not a secretservice v1 envelope")
    sealed = base64.b64decode(b64)
    return SealedBox(priv).decrypt(sealed).decode("utf-8")


def try_decrypt(envelope):
    """Try every known private key. Returns (label, plaintext) or raises."""
    keys = load_all_private()
    if not keys:
        raise ValueError("no private keys found; run 'ss keygen' first")
    for label, priv in keys:
        try:
            return label, open_envelope(envelope, priv)
        except Exception:
            continue
    raise ValueError("payload found but no local key could open it")


# --- optional signing layer (Ed25519) ----------------------------------------
# Sealed boxes prove a message was sealed FOR you and arrived unaltered, but
# carry no sender identity (the sender stays deniable by design). The signing
# layer is opt-in per message: the sender signs the plaintext with an Ed25519
# key, and the signature travels inside the sealed envelope alongside the
# plaintext, so only the recipient ever sees it. Format of the inner text:
#
#     SSS1:<base64(ed25519 signature over utf8 plaintext)>:<plaintext>
#
# The sender's verify key is advertised in the X-Signing-Key header of the
# sealed mail (same discovery path as X-Public-Key) and harvested into
# contacts.json by the watcher.

SIG_VERSION = "SSS1"
SIG_SUFFIX = ".sig"


def sig_key_path(label):
    return os.path.join(keys_dir(), _check_label(label) + SIG_SUFFIX)


def sig_generate(label):
    """Generate an Ed25519 signing keypair. Returns the verify key (base64).

    The signing key is written with 0600 permissions and never printed.
    """
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    fd = os.open(sig_key_path(label), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(bytes(sk)).decode("ascii") + "\n")
    return base64.b64encode(bytes(sk.verify_key)).decode("ascii")


def load_signing(label):
    from nacl.signing import SigningKey
    with open(sig_key_path(label), "r") as f:
        return SigningKey(base64.b64decode(f.read().strip()))


def sig_pubkey_of(label):
    """The verify (public) key for a label's signing key, base64."""
    return base64.b64encode(bytes(load_signing(label).verify_key)) \
        .decode("ascii")


def sign_inner(plaintext, signing_label):
    """Wrap plaintext in a signed SSS1 container."""
    sig = load_signing(signing_label).sign(plaintext.encode("utf-8")) \
        .signature
    return (SIG_VERSION + ":" + base64.b64encode(sig).decode("ascii")
            + ":" + plaintext)


def unwrap_signed(inner):
    """Split a decrypted inner text. Returns (signed, sig_b64, plaintext);
    unsigned text comes back as (False, None, inner)."""
    ver, sep, rest = inner.partition(":")
    if ver != SIG_VERSION or not sep:
        return False, None, inner
    sig_b64, sep2, plaintext = rest.partition(":")
    if not sep2:
        return False, None, inner
    return True, sig_b64, plaintext


def verify_inner(verifykey_b64, sig_b64, plaintext):
    """True iff sig_b64 is a valid Ed25519 signature of plaintext."""
    from nacl.signing import VerifyKey
    try:
        vk = VerifyKey(base64.b64decode(verifykey_b64.strip(), validate=True))
        vk.verify(plaintext.encode("utf-8"),
                  base64.b64decode(sig_b64, validate=True))
        return True
    except Exception:
        return False


def seal_signed_envelope(plaintext, to_pubkey_b64, signing_label):
    """Sign the plaintext, then seal the signed container to the recipient."""
    return seal_envelope(sign_inner(plaintext, signing_label), to_pubkey_b64)
