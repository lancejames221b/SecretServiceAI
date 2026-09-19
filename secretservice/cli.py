"""ss: covert messaging over email. See the secretservice skill for the full guide."""

import argparse
import json as _json
import os
import re as _re
import sys
import time as _time

from . import carriers, crypto, mime, transport

DATA_DIR = os.environ.get("SECRETSERVICE_DATA_DIR",
                           os.path.expanduser("~/.local/share/secretservice"))
WATCH_INBOX_DIR = os.path.join(DATA_DIR, "inbox")
WATCH_SEEN_PATH = os.path.join(DATA_DIR, "watch-seen.json")
CONTACTS_PATH = os.path.join(DATA_DIR, "contacts.json")


def _load_contacts():
    """Return {email: {name, pubkey, sigkey, source, added_at}}. Tolerates the
    legacy flat {email: pubkey} format written by early harvest runs, and
    entries without a sigkey."""
    contacts = {}
    if os.path.exists(CONTACTS_PATH):
        try:
            with open(CONTACTS_PATH, "r", encoding="utf-8") as f:
                raw = _json.load(f)
        except Exception:
            raw = {}
        for addr, val in (raw or {}).items():
            if isinstance(val, dict):
                contacts[addr] = val
            else:
                contacts[addr] = {"name": "", "pubkey": val,
                                  "source": "harvested", "added_at": ""}
    return contacts


def _save_contacts(contacts):
    os.makedirs(os.path.dirname(CONTACTS_PATH), exist_ok=True)
    _write_private_text(CONTACTS_PATH,
                        _json.dumps(contacts, indent=2, sort_keys=True) + "\n")


def _validate_pubkey(pubkey_b64):
    """Return the stripped key or None if it is not a 32-byte base64 key."""
    try:
        raw = __import__("base64").b64decode(pubkey_b64.strip(), validate=True)
        if len(raw) != 32:
            return None
        return pubkey_b64.strip()
    except Exception:
        return None


def _note_contact(from_header, pubkey_b64, sigkey_b64=None):
    """File a harvested sender public key (0600). Validates keys first.
    sigkey is the sender's Ed25519 verify key, harvested from X-Signing-Key.
    """
    pubkey_b64 = _validate_pubkey(pubkey_b64)
    sigkey_b64 = _validate_pubkey(sigkey_b64) if sigkey_b64 else None
    if not pubkey_b64 and not sigkey_b64:
        return
    m = _re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", from_header or "")
    if not m:
        return
    addr = m.group(0).lower()
    contacts = _load_contacts()
    entry = contacts.get(addr, {})
    changed = False
    if pubkey_b64 and entry.get("pubkey") != pubkey_b64:
        entry["pubkey"] = pubkey_b64
        changed = True
    if sigkey_b64 and entry.get("sigkey") != sigkey_b64:
        entry["sigkey"] = sigkey_b64
        changed = True
    if changed:
        entry["name"] = entry.get("name", "")
        entry["source"] = "harvested"
        entry["added_at"] = _time.strftime("%Y-%m-%d")
        contacts[addr] = entry
        _save_contacts(contacts)


def _resolve_recipient_key(to_addr, explicit_pubkey):
    """Recipient key for sealing: explicit --to-pubkey wins, otherwise look
    up the --to address in contacts."""
    if explicit_pubkey:
        key = _validate_pubkey(explicit_pubkey)
        if not key:
            raise SystemExit("error: --to-pubkey is not a valid 32-byte base64 key")
        return key
    addr = to_addr.strip().lower()
    entry = _load_contacts().get(addr)
    if not entry:
        raise SystemExit(
            "error: no public key on file for %s.\n"
            "Have them send their public key (ss-decrypt.py --genkey prints it),\n"
            "then file it with: ss contact-add --email %s --name '<name>' --pubkey '<key>'"
            % (to_addr, to_addr))
    return entry["pubkey"]


def _read_text(path):
    with open(os.path.expanduser(path), "r", encoding="utf-8") as f:
        return f.read()


def _verify_signed(raw, plaintext):
    """Check a decrypted inner text for a signature.

    Returns (signed, verified, signer_key, clean_text). signer_key is the
    advertised Ed25519 verify key from the message headers, or None.
    clean_text is the plaintext with the SSS1 container stripped.
    """
    signed, sig_b64, clean = crypto.unwrap_signed(plaintext)
    if not signed:
        return False, False, None, plaintext
    signer_key = mime.sender_sigkey_from_raw(raw)
    verified = bool(signer_key) and crypto.verify_inner(
        signer_key, sig_b64, clean)
    return True, verified, signer_key, clean


_SIGNAL_LABELS = {
    "header_key": "advertises public key in headers",
    "header_sigkey": "advertises signing key in headers",
    "photo_key": "key hidden in sent photos",
    "sealed": "sent sealed mail",
}


def _addr_of(from_header):
    m = _re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", from_header or "")
    return m.group(0).lower() if m else None


def _from_header_of(raw):
    m = _re.search(br"^From:\s*(.+)$", raw, _re.M | _re.I)
    return m.group(1).decode("ascii", "replace") if m else ""


def _sender_signals_raw(raw):
    """Return {signal: bool} for member detection from raw message bytes."""
    sig = {"header_key": False, "header_sigkey": False,
           "photo_key": False, "sealed": False}
    try:
        if mime.sender_pubkey_from_raw(raw):
            sig["header_key"] = True
        if mime.sender_sigkey_from_raw(raw):
            sig["header_sigkey"] = True
        if mime.photo_keys_from_raw(raw):
            sig["photo_key"] = True
        carrier, _env = mime.extract_from_raw(raw)
        if carrier:
            sig["sealed"] = True
    except Exception:
        pass
    return sig


def _collect_signals(candidates, addr, name, raw=None):
    """Merge contacts-file and live-mail signals for one address."""
    e = candidates.setdefault(addr, {"name": name, "signals": set()})
    if name and not e["name"]:
        e["name"] = name
    c = _load_contacts().get(addr)
    if c:
        if c.get("name") and not e["name"]:
            e["name"] = c["name"]
        e["signals"].add("key on file [%s]" % c.get("source", "?"))
        if c.get("sigkey"):
            e["signals"].add("signing key on file")
    if raw:
        for sig, present in _sender_signals_raw(raw).items():
            if present:
                e["signals"].add(_SIGNAL_LABELS[sig])


def cmd_members(args):
    """Identify secretservice members among email senders.

    A "member" is any sender with a public key on file, or who advertises
    a key in their mail (headers or photos), or who has sent sealed mail.
    Works on a whole batch at once: scan recent mail, or check several
    addresses directly with --emails (checked against contacts and filed
    inbox notes).
    """
    candidates = {}
    if args.emails:
        addrs = [a.strip().lower() for a in args.emails.split(",")
                 if a.strip()]
        for addr in addrs:
            _collect_signals(candidates, addr, "")
        # filed inbox notes: sealed mail already received from them
        if os.path.isdir(WATCH_INBOX_DIR):
            for fn in os.listdir(WATCH_INBOX_DIR):
                if not fn.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(WATCH_INBOX_DIR, fn),
                              encoding="utf-8") as f:
                        sc = _json.load(f)
                except Exception:
                    continue
                addr = _addr_of(sc.get("from", ""))
                if addr in candidates:
                    candidates[addr]["signals"].add("sent sealed mail [filed]")
        # Live check: recent mail from each address, so a member who wrote
        # before the last watch still gets caught. Advertised keys found
        # here are harvested into contacts (learning).
        cfg = transport.load_config()
        if cfg:
            for addr in addrs:
                try:
                    found = transport.imap_search(
                        cfg, "FROM %s" % addr, 3,
                        since_minutes=90 * 24 * 60)
                except Exception as e:
                    print("warning: live check failed for %s: %s"
                          % (addr, str(e)[:120]), file=sys.stderr)
                    continue
                for _uid, raw in found:
                    _collect_signals(candidates, addr, "", raw)
                    pk = mime.sender_pubkey_from_raw(raw)
                    sk = mime.sender_sigkey_from_raw(raw)
                    if pk or sk:
                        _note_contact(addr, pk, sk)
                    for pkb in mime.photo_keys_from_raw(raw):
                        _note_contact(addr, pkb)
                if found:
                    candidates[addr]["signals"].add(
                        "live mail checked (%d message%s, 90d)"
                        % (len(found), "s" if len(found) != 1 else ""))
        else:
            print("(no mail configured: live check skipped - run `ss setup`)")
    else:
        cfg = transport.load_config()
        if not cfg:
            raise SystemExit("error: no mail configured yet - run `ss setup` first")
        try:
            found = transport.imap_search(cfg, args.query, args.max)
        except Exception as e:
            raise SystemExit("error: could not check mail: %s" % str(e)[:200])
        latest_per_sender = {}
        for _uid, raw in found:
            addr = _addr_of(_from_header_of(raw))
            if addr and addr not in latest_per_sender:
                latest_per_sender[addr] = raw
        for addr, raw in latest_per_sender.items():
            _collect_signals(candidates, addr, "", raw)

    if not candidates:
        print("No senders found.")
        return
    for addr in sorted(candidates):
        e = candidates[addr]
        name = e["name"] or "(name unknown)"
        if e["signals"]:
            print("%s <%s>\n  MEMBER -- %s"
                  % (name, addr, ", ".join(sorted(e["signals"]))))
        else:
            print("%s <%s>\n  not identified as a member" % (name, addr))


def cmd_meme_seal(args):
    """Seal a secret into a meme image for texting."""
    secret = _read_text(args.message_file) if args.message_file else args.message
    if not secret or not secret.strip():
        raise SystemExit("error: secret message is empty")
    envelope = crypto.seal_envelope(
        secret, _resolve_recipient_key(args.to, args.to_pubkey))
    pubkey = None
    if args.advertise_key:
        try:
            pubkey = crypto.pubkey_of(args.advertise_key)
        except Exception as e:
            print("warning: could not load key '%s': %s (no key advertised)"
                  % (args.advertise_key, e), file=sys.stderr)
    try:
        img = carriers.meme_embed(envelope, os.path.expanduser(args.image),
                                  pubkey_b64=pubkey)
    except ValueError as e:
        raise SystemExit("error: %s" % e)
    out = os.path.expanduser(args.out)
    img.save(out, format="PNG")
    os.chmod(out, 0o600)
    print("Sealed meme saved to %s" % out)
    print("IMPORTANT: text it AS A FILE / DOCUMENT (Signal: + > File, "
          "WhatsApp: attach > Document).")
    print("Sending it as a photo lets the app recompress it, which destroys")
    print("the hidden message.")


def cmd_meme_open(args):
    """Open a sealed meme image received over texting."""
    from PIL import Image
    img = Image.open(os.path.expanduser(args.image))
    envelope, pubkey = carriers.meme_extract(img)
    if not envelope:
        print("No hidden message found in that image.")
        print("If it was sent as a photo (not as a file), the app probably")
        print("recompressed it. Ask the sender to resend it as a document.")
        return
    if pubkey:
        _note_contact(args.from_addr or "", pubkey)
    try:
        label, plaintext = crypto.try_decrypt(envelope)
    except Exception as e:
        print("%s" % e)
        return
    print("Opened with key: %s\n%s" % (label, plaintext))


def _onboard_file(name):
    """Locate a bundled onboard/decryptor file: installed package data
    first, then the source tree (repo root). Returns a path or None."""
    try:
        from importlib import resources as _res
        p = _res.files("secretservice").joinpath("data", name)
        if p.is_file():
            return str(p)
    except Exception:
        pass
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for cand in (os.path.join(root, "onboard", name),
                 os.path.join(root, "decryptor", name),
                 os.path.join(root, name)):
        if os.path.isfile(cand):
            return cand
    return None


def _read_onboard_file(name):
    p = _onboard_file(name)
    if not p:
        raise SystemExit("error: bundled file '%s' not found" % name)
    with open(p, "rb") as f:
        return f.read()


def cmd_onboard(args):
    """Send the key-exchange intro email with the portable decryptor
    attached. One command: template + personalization + attachments."""
    to_addr = args.to.strip()
    if "@" not in to_addr:
        raise SystemExit("error: --to does not look like an email address")
    to_name = args.name.strip() or to_addr
    cfg = transport.load_config()
    from_name = args.from_name.strip()
    if not from_name and cfg:
        from_name = cfg.get("from_addr") or cfg.get("username") or ""
    if not from_name:
        raise SystemExit("error: pass --from-name 'Your Name' (no mail "
                         "configured and no name given)")
    from_addr = (cfg.get("from_addr") if cfg else "") or args.from_addr \
        or "me@example.com"
    template = _read_onboard_file("intro-email.txt").decode("utf-8")
    dec = _read_onboard_file("ss-decrypt.py")
    readme = _read_onboard_file("README.md")
    sender_pubkey = sender_sigkey = None
    try:
        sender_pubkey = crypto.pubkey_of("personal")
    except Exception:
        pass
    try:
        sender_sigkey = crypto.sig_pubkey_of("personal")
    except Exception:
        pass
    if not sender_pubkey:
        print("warning: no 'personal' key yet - sending without pubkey "
              "header (run `ss setup` first)", file=sys.stderr)
    raw = mime.build_onboard_message(
        to_addr, from_addr, to_name, from_name, template,
        [("ss-decrypt.py", dec, "text", "x-python"),
         ("README.md", readme, "text", "markdown")],
        sender_pubkey=sender_pubkey, sender_sigkey=sender_sigkey)
    dest = transport.send_sealed(raw, to_addr, via=args.via)
    if dest.startswith("smtp:"):
        print("Intro email sent to %s." % to_addr)
    else:
        print("Intro email draft written to %s" % dest)
        print("Send it from any mail client (or show the owner first).")
    print("When they reply with their public key, file it:")
    print("  ss contact-add --email %s --name '%s' --pubkey '<key>'"
          % (to_addr, to_name))


def cmd_setup(args):
    """Guided first-run walkthrough. Pick a path; each one holds your hand."""
    print("Secretservice setup. What do you want to do?\n")
    print("  1) Read sealed messages sent to me (simplest, 2 minutes)")
    print("     Just makes your key. You open messages with the decryptor.")
    print("  2) Full email setup (send and receive sealed email, 5 minutes)")
    print("     Connects your email so the tool sends and watches for you.")
    print("  3) Meme mode (hide secrets in images for texting, 2 minutes)")
    print("     Just makes your key. You seal memes and text them as files.")
    choice = input("\nPick 1, 2, or 3 [1]: ").strip() or "1"

    label = input("\nName for your key [personal]: ").strip() or "personal"
    try:
        pub = crypto.generate(label)
    except FileExistsError:
        pub = crypto.pubkey_of(label)
        print("(key '%s' already exists - keeping it)" % label)

    sig_pub = None
    sig = input("\nAlso create a signing key? Recommended: it proves sealed "
                "messages\ncame from you, which matters when the recipient acts "
                "on them. [Y/n]: ").strip().lower()
    if sig != "n":
        try:
            sig_pub = crypto.sig_generate(label)
        except FileExistsError:
            sig_pub = crypto.sig_pubkey_of(label)
            print("(signing key '%s' already exists - keeping it)" % label)

    if choice == "2":
        _setup_email()
    elif choice == "3":
        print("\nMeme mode: no mail connection needed.")
        print("Seal one with: ss meme-seal --image meme.png --out out.png "
              "--to friend@example.com --message '...'")
        print("(You still need their public key: ss contact-add, or they "
              "send it to you.)")
    # choice 1 (or anything else): key only.

    print("\nThis is your PUBLIC key. Send it to whoever you want sealed")
    print("messages from. It is safe to share - it cannot be used against you:")
    print(pub)
    if sig_pub:
        print("\nThis is your PUBLIC signing key. Share it alongside the key")
        print("above so others can verify your signed messages:")
        print(sig_pub)
        print("\nSign a sealed message any time with:  ss seal ... --sign")
    if choice == "1":
        print("\nWhat happens next: when someone sends you a sealed email, save")
        print("it via Show original / Download original, then run:")
        print("  ss open --file message.eml")
        print("Or use the decryptor: decryptor/ss-decrypt.py --eml message.eml "
              "--key <your-key-file>")


def _setup_email():
    """The email half of the setup wizard (option 2)."""
    import getpass as _getpass

    print("\n--- email connection ---")
    email = input("Your email address: ").strip()
    domain = email.split("@")[-1].lower() if "@" in email else ""
    guess = {"gmail.com": "gmail", "googlemail.com": "gmail",
             "outlook.com": "outlook", "hotmail.com": "outlook",
             "live.com": "outlook", "icloud.com": "icloud",
             "me.com": "icloud", "mac.com": "icloud",
             "yahoo.com": "yahoo"}.get(domain)
    if guess:
        provider = input("Email provider [%s]: " % guess).strip().lower() or guess
    else:
        provider = input("Email provider (gmail/outlook/icloud/yahoo/custom): "
                         ).strip().lower()
    if provider in transport.PROVIDERS:
        p = transport.PROVIDERS[provider]
        smtp_host, smtp_port = p["smtp"]
        imap_host, imap_port = p["imap"]
        print("\nYou will need an APP PASSWORD (not your normal password).")
        print("Make one here: %s\n" % p["help"])
    elif provider == "custom":
        smtp_host = input("SMTP host: ").strip()
        smtp_port = int(input("SMTP port [587]: ").strip() or "587")
        imap_host = input("IMAP host: ").strip()
        imap_port = int(input("IMAP port [993]: ").strip() or "993")
    else:
        raise SystemExit("unknown provider '%s'" % provider)

    username = input("Login username [%s]: " % email).strip() or email
    password = _getpass.getpass("App password (hidden as you type): ").strip()
    if not password:
        raise SystemExit("no app password given - run `ss setup` again when ready")

    cfg = {"from_addr": email, "username": username, "password": password,
           "smtp_host": smtp_host, "smtp_port": smtp_port,
           "imap_host": imap_host, "imap_port": imap_port,
           "provider": provider}

    print("Checking the login...", end=" ", flush=True)
    try:
        import smtplib as _smtplib
        with _smtplib.SMTP(smtp_host, smtp_port, timeout=30) as s:
            s.starttls()
            s.login(username, password)
        print("ok.")
    except Exception as e:
        print("FAILED.")
        raise SystemExit("could not log in: %s\n"
                         "Double-check the app password and run `ss setup` again."
                         % str(e)[:200])

    transport.save_config(cfg)
    print("\nEmail connected. Send a sealed email with:")
    print("  ss seal --to friend@example.com --carrier header "
          "--subject '...' --body '...' --message '...'")
    print("Watch for incoming sealed mail with:  ss watch --since 60")


def cmd_keygen(args):
    pub = crypto.generate(args.name)
    print("Keypair created: %s" % crypto.key_path(args.name))
    print("Private key is 0600 and stays on this machine. Share this public key:")
    print(pub)


def cmd_pubkey(args):
    print(crypto.pubkey_of(args.name))


def cmd_sig_keygen(args):
    pub = crypto.sig_generate(args.name)
    print("Signing keypair created: %s" % crypto.sig_key_path(args.name))
    print("Signing key is 0600 and stays on this machine. Share this verify key")
    print("so others can confirm your signed messages:")
    print(pub)


def cmd_sig_pubkey(args):
    print(crypto.sig_pubkey_of(args.name))


def cmd_photo_embed(args):
    pubkey = args.pubkey.strip() if args.pubkey else crypto.pubkey_of(args.key_label)
    img = carriers.photokey_embed(pubkey, os.path.expanduser(args.image))
    out = os.path.expanduser(args.out)
    img.save(out, format="PNG")
    os.chmod(out, 0o600)
    print("Public key hidden in %s" % out)


def cmd_photo_extract(args):
    from PIL import Image
    img = Image.open(os.path.expanduser(args.image))
    key = carriers.photokey_extract(img)
    if key:
        print(key)
    else:
        print("No hidden public key found.")


def cmd_contacts(args):
    contacts = _load_contacts()
    if not contacts:
        print("No contacts on file yet.")
        return
    for addr in sorted(contacts):
        e = contacts[addr]
        name = e.get("name") or "(name unknown)"
        print("%s <%s>\n  %s [%s]" % (name, addr, e.get("pubkey", "?"),
                                      e.get("source", "?")))


def cmd_contact_add(args):
    key = _validate_pubkey(args.pubkey)
    if not key:
        raise SystemExit("error: --pubkey is not a valid 32-byte base64 key")
    m = _re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", args.email or "")
    if not m:
        raise SystemExit("error: --email does not look like an email address")
    addr = m.group(0).lower()
    contacts = _load_contacts()
    contacts[addr] = {"name": args.name.strip(),
                      "pubkey": key,
                      "source": "manual",
                      "added_at": _time.strftime("%Y-%m-%d")}
    _save_contacts(contacts)
    print("Filed public key for %s <%s>." % (args.name.strip(), addr))


def cmd_seal(args):
    secret = _read_text(args.message_file) if args.message_file else args.message
    if not secret or not secret.strip():
        raise SystemExit("error: secret message is empty")
    body = _read_text(args.body_file) if args.body_file else args.body
    if not body or not body.strip():
        raise SystemExit("error: cover body is empty")

    # Optional signing layer (Ed25519). Off unless --sign is passed.
    sign_label = None
    if args.sign is not None:
        sign_label = args.from_key if args.sign == "__from__" else args.sign
        if not sign_label:
            raise SystemExit("error: --sign needs a key label with a signing "
                             "key (create one with: ss sig-keygen --name <label>)")
        try:
            crypto.load_signing(sign_label)
        except Exception:
            raise SystemExit(
                "error: no signing key for label '%s'. Create one with:\n"
                "  ss sig-keygen --name %s" % (sign_label, sign_label))
        envelope = crypto.seal_signed_envelope(
            secret, _resolve_recipient_key(args.to, args.to_pubkey), sign_label)
    else:
        envelope = crypto.seal_envelope(
            secret, _resolve_recipient_key(args.to, args.to_pubkey))

    cfg = transport.load_config()
    from_addr = (cfg or {}).get("from_addr", "secretservice@localhost")

    sender_pubkey = None
    if args.from_key:
        try:
            sender_pubkey = crypto.pubkey_of(args.from_key)
        except Exception as e:
            print("warning: could not load key '%s': %s (sending without pubkey header)"
                  % (args.from_key, e), file=sys.stderr)

    sender_sigkey = None
    if sign_label:
        try:
            sender_sigkey = crypto.sig_pubkey_of(sign_label)
        except Exception as e:
            print("warning: could not load signing key '%s': %s"
                  % (sign_label, e), file=sys.stderr)

    raw = mime.build_message(
        to_addr=args.to,
        from_addr=from_addr,
        subject=args.subject,
        body=body,
        carrier=args.carrier,
        envelope=envelope,
        logo_path=args.logo,
        sig_name=args.sig_name or "",
        sender_pubkey=sender_pubkey,
        sender_sigkey=sender_sigkey,
        in_reply_to=args.in_reply_to,
        references=args.references,
    )

    if args.dry_run:
        with open(os.path.expanduser(args.dry_run), "wb") as f:
            f.write(raw)
        print("Dry run: MIME written to %s (%d bytes, not sent)"
              % (args.dry_run, len(raw)))
        return

    try:
        dest = transport.send_sealed(raw, args.to, via=args.via)
    except RuntimeError as e:
        raise SystemExit("error: %s" % e)
    if dest.startswith("smtp:"):
        print("Sent to %s." % args.to)
    else:
        print("No mail configured, so the sealed message was saved to:")
        print(dest)
        print("Send it from any mail client (or have a friend forward it).")


def cmd_open(args):
    """Open a sealed message saved as a .eml file (via "Show original" /
    "Download original" in any mail client, desktop or phone)."""
    path = os.path.expanduser(args.file)
    if not os.path.exists(path):
        raise SystemExit("error: file not found: %s" % args.file)
    with open(path, "rb") as f:
        raw = f.read()
    carrier, envelope = mime.extract_from_raw(raw)
    if not envelope:
        print("No hidden payload found in %s." % args.file)
        return
    try:
        label, plaintext = crypto.try_decrypt(envelope)
    except Exception as e:
        print("Carrier: %s\n%s" % (carrier, e))
        return
    signed, verified, _sk, clean = _verify_signed(raw, plaintext)
    if signed:
        sigline = ("\nSignature: VERIFIED (signed by sender)"
                   if verified else
                   "\nSignature: PRESENT BUT UNVERIFIED (key mismatch or tampered)")
    else:
        sigline = "\nSignature: none (unsigned)"
    print("Carrier: %s\nOpened with key: %s%s\n%s"
          % (carrier, label, sigline, clean))


def _write_private_text(path, text):
    """Write a text file readable only by the owner (0600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def cmd_watch(args):
    # Discretion: stdout carries ONLY machine-readable arrival lines.
    # Plaintext is never printed, logged, or spoken anywhere in this path.
    cfg = transport.load_config()
    if not cfg:
        raise SystemExit("error: no mail configured yet - run `ss setup` first")
    os.makedirs(WATCH_INBOX_DIR, exist_ok=True)
    seen = set()
    if os.path.exists(WATCH_SEEN_PATH):
        try:
            with open(WATCH_SEEN_PATH, "r", encoding="utf-8") as f:
                seen = set(_json.load(f))
        except Exception:
            seen = set()

    try:
        found = transport.fetch_unseen(cfg, args.since, args.max)
    except Exception as e:
        raise SystemExit("error: could not check mail: %s" % str(e)[:200])

    arrived = []
    dirty = False
    for uid, raw in found:
        # Identity for dedup: the Message-ID header, falling back to the UID.
        m = _re.search(br"^Message-ID:\s*(.+)$", raw, _re.M | _re.I)
        mid = (m.group(1).decode("ascii", "replace").strip()
               if m else "imap-%s" % uid)
        if mid in seen:
            continue
        safe = _re.sub(r"[^A-Za-z0-9_-]", "_", mid)[:80]
        txt_path = os.path.join(WATCH_INBOX_DIR, safe + ".txt")
        if os.path.exists(txt_path):
            seen.add(mid)
            dirty = True
            continue
        # Key discovery: harvest advertised public keys, from the header
        # or hidden in attached/inline photos. Filed to contacts.json (0600).
        from_m = _re.search(br"^From:\s*(.+)$", raw, _re.M | _re.I)
        from_hdr = from_m.group(1).decode("ascii", "replace") if from_m else ""
        subj_m = _re.search(br"^Subject:\s*(.+)$", raw, _re.M | _re.I)
        subject = subj_m.group(1).decode("ascii", "replace").strip() \
            if subj_m else ""
        pk = mime.sender_pubkey_from_raw(raw)
        sk = mime.sender_sigkey_from_raw(raw)
        if pk or sk:
            _note_contact(from_hdr, pk, sk)
        for pk in mime.photo_keys_from_raw(raw):
            _note_contact(from_hdr, pk)
        carrier, envelope = mime.extract_from_raw(raw)
        if not envelope:
            seen.add(mid)
            dirty = True
            continue
        try:
            label, plaintext = crypto.try_decrypt(envelope)
        except Exception:
            # Payload for someone else's key, or corrupt: note and move on.
            seen.add(mid)
            dirty = True
            continue
        signed, verified, signer_key, clean = _verify_signed(raw, plaintext)
        # Threading context for sealed replies: original Message-ID plus the
        # visible decoy, so a reply can thread under it and read as a natural
        # reply to the cover topic.
        thread = mime.thread_info_from_raw(raw)
        sidecar = {
            "id": mid,
            "from": from_hdr,
            "subject": subject,
            "carrier": carrier,
            "key_label": label,
            "signed": signed,
            "verified": verified,
            "signer_key": signer_key,
            "message_id": thread["message_id"],
            "decoy": thread["decoy"],
            "received_at": _time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        _write_private_text(txt_path, clean)
        _write_private_text(os.path.join(WATCH_INBOX_DIR, safe + ".json"),
                            _json.dumps(sidecar, indent=2) + "\n")
        seen.add(mid)
        dirty = True
        arrived.append(mid)

    if dirty:
        _write_private_text(WATCH_SEEN_PATH,
                            _json.dumps(sorted(seen), indent=2) + "\n")
    for mid in arrived:
        print("SECRET_MESSAGE_ARRIVED:%s" % mid)


def build_parser():
    p = argparse.ArgumentParser(
        prog="ss",
        description="Covert messaging over email: sealed-box encrypted payloads "
                    "hidden in ordinary-looking mail.")
    sub = p.add_subparsers(dest="cmd", required=True)

    su = sub.add_parser("setup", help="guided first-run walkthrough")
    su.set_defaults(func=cmd_setup)

    ob = sub.add_parser("onboard",
                      help="send the key-exchange intro email with the "
                           "portable decryptor attached")
    ob.add_argument("--to", required=True, help="recipient email address")
    ob.add_argument("--name", default="",
                    help="recipient's name for the greeting")
    ob.add_argument("--from-name", default="",
                    help="your name for the sign-off "
                         "(default: configured mail name)")
    ob.add_argument("--from-addr", default="",
                    help="your email address (default: configured)")
    ob.add_argument("--via", default=None, choices=["smtp", "file"],
                    help="send via configured SMTP or write a .eml draft "
                         "(default: smtp if configured, else file)")
    ob.set_defaults(func=cmd_onboard)

    mm = sub.add_parser("meme-seal", help="hide a secret in a meme image for texting")
    mm.add_argument("--image", required=True, help="input image (PNG or JPG)")
    mm.add_argument("--out", required=True, help="output PNG path")
    mm.add_argument("--to", required=True,
                    help="recipient: email on file (ss contact-add) or --to-pubkey")
    mm.add_argument("--to-pubkey", default=None,
                    help="recipient public key (base64); overrides contacts lookup")
    mgrp = mm.add_mutually_exclusive_group(required=True)
    mgrp.add_argument("--message", help="the secret message text")
    mgrp.add_argument("--message-file", help="file containing the secret message")
    mm.add_argument("--advertise-key", default="personal",
                    help="also hide your public key in the image so they can "
                         "write back (default: personal; empty string skips it)")
    mm.set_defaults(func=cmd_meme_seal)

    mo = sub.add_parser("meme-open", help="open a sealed meme image")
    mo.add_argument("--image", required=True, help="the received image file")
    mo.add_argument("--from-addr", default="",
                    help="sender's email, to file their advertised key under")
    mo.set_defaults(func=cmd_meme_open)

    k = sub.add_parser("keygen", help="generate a keypair")
    k.add_argument("--name", required=True, help="key label")
    k.set_defaults(func=cmd_keygen)

    pk = sub.add_parser("pubkey", help="print a public key to share")
    pk.add_argument("--name", required=True, help="key label")
    pk.set_defaults(func=cmd_pubkey)

    sg = sub.add_parser("sig-keygen",
                        help="generate an Ed25519 signing keypair (optional "
                             "signing layer for sealed mail)")
    sg.add_argument("--name", required=True, help="key label")
    sg.set_defaults(func=cmd_sig_keygen)

    sp = sub.add_parser("sig-pubkey",
                        help="print a signing verify key to share")
    sp.add_argument("--name", required=True, help="key label")
    sp.set_defaults(func=cmd_sig_pubkey)

    pe = sub.add_parser("photo-embed",
                        help="hide a public key in a photo's pixels")
    pe.add_argument("--image", required=True, help="input PNG")
    pe.add_argument("--out", required=True, help="output PNG path")
    pgrp = pe.add_mutually_exclusive_group(required=True)
    pgrp.add_argument("--pubkey", help="base64 public key to hide")
    pgrp.add_argument("--key-label", help="key label whose pubkey to hide")
    pe.set_defaults(func=cmd_photo_embed)

    px = sub.add_parser("photo-extract",
                        help="recover a hidden public key from a photo")
    px.add_argument("--image", required=True, help="PNG to inspect")
    px.set_defaults(func=cmd_photo_extract)

    c = sub.add_parser("contacts",
                       help="list known sender public keys")
    c.set_defaults(func=cmd_contacts)

    mm = sub.add_parser(
        "members",
        help="identify which email addresses use secretservice")
    mm.add_argument("--query", default=None,
                    help="IMAP search query for the mailbox scan "
                         "(e.g. 'UNSEEN' or 'SUBJECT secret')")
    mm.add_argument("--max", type=int, default=50,
                    help="max messages to scan in query mode (default 50)")
    mm.add_argument("--emails", default=None,
                    help="comma-separated addresses to check in one run "
                         "(checks contacts, then the local inbox sidecars)")
    mm.set_defaults(func=cmd_members)

    ca = sub.add_parser("contact-add",
                        help="file someone's public key for future sealed mail")
    ca.add_argument("--email", required=True, help="their email address")
    ca.add_argument("--name", required=True, help="their name")
    ca.add_argument("--pubkey", required=True, help="their base64 public key")
    ca.set_defaults(func=cmd_contact_add)

    s = sub.add_parser("seal", help="seal a secret into a cover email and send it")
    s.add_argument("--to-pubkey", default=None,
                   help="recipient public key (base64). If omitted, the key is "
                        "looked up from contacts by the --to address.")
    s.add_argument("--carrier", required=True,
                   choices=mime.CARRIERS, help="hiding method")
    s.add_argument("--logo", default=None, help="PNG to hide payload in (logo carrier)")
    s.add_argument("--sig-name", default="",
                   help="visible name in the signature block (logo carrier)")
    mgrp = s.add_mutually_exclusive_group(required=True)
    mgrp.add_argument("--message", help="the secret message text")
    mgrp.add_argument("--message-file", help="file containing the secret message")
    bgrp = s.add_mutually_exclusive_group(required=True)
    bgrp.add_argument("--body", help="visible cover email text")
    bgrp.add_argument("--body-file", help="file with the visible cover email")
    s.add_argument("--subject", required=True)
    s.add_argument("--to", required=True, help="recipient email address")
    s.add_argument("--via", default=None, choices=["smtp", "file"],
                   help="how to send: smtp (needs `ss setup`) or file "
                        "(save a .eml to send manually). Default: smtp if "
                        "configured, else file.")
    s.add_argument("--from-key", default="personal",
                   help="key label whose public key is advertised in the "
                        "X-Public-Key header (default: personal; "
                        "empty string omits the header)")
    s.add_argument("--sign", nargs="?", const="__from__", default=None,
                   metavar="LABEL",
                   help="sign the secret with an Ed25519 signing key before "
                        "sealing (optional signing layer). Bare --sign uses "
                        "the --from-key label; --sign <label> uses that "
                        "label's key (create one with: ss sig-keygen --name "
                        "<label>).")
    s.add_argument("--in-reply-to", default=None, metavar="MSGID",
                   help="Message-ID being replied to; sets In-Reply-To so a "
                        "sealed reply threads under the original decoy")
    s.add_argument("--references", default=None, metavar="MSGIDS",
                   help="References header chain for a sealed reply "
                        "(space-separated Message-IDs)")
    s.add_argument("--dry-run", default=None, metavar="PATH",
                   help="write the MIME to PATH instead of sending")
    s.set_defaults(func=cmd_seal)

    o = sub.add_parser("open", help="decrypt a sealed message saved as .eml")
    o.add_argument("--file", required=True,
                   help="the saved email file "
                        "(mail app > Show original > Download original)")
    o.set_defaults(func=cmd_open)

    w = sub.add_parser("watch",
                       help="check incoming mail for sealed messages and file them")
    w.add_argument("--since", type=int, required=True,
                   help="look back this many minutes")
    w.add_argument("--max", type=int, default=25, help="max messages to scan")
    w.set_defaults(func=cmd_watch)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
