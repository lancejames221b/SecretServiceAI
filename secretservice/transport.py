"""Email transport for secretservice.

No vendor CLIs, no OAuth projects, no special setup. Sending goes out over
SMTP and watching polls over IMAP, so it works with any email provider that
offers app passwords (Gmail, Outlook, iCloud, Yahoo, ...). Everything the
tool needs is collected once by `ss setup` and stored 0600 on the machine.
"""

import imaplib
import json as _json
import os
import smtplib
import time as _time

CONFIG_PATH = os.path.expanduser("~/.config/secretservice/config.json")

PROVIDERS = {
    "gmail":   {"smtp": ("smtp.gmail.com", 587),
                "imap": ("imap.gmail.com", 993),
                "help": "Google Account > Security > 2-Step Verification > App passwords"},
    "outlook": {"smtp": ("smtp.office365.com", 587),
                "imap": ("outlook.office365.com", 993),
                "help": "Microsoft account > Security > Advanced security options > App passwords"},
    "icloud":  {"smtp": ("smtp.mail.me.com", 587),
                "imap": ("imap.mail.me.com", 993),
                "help": "appleid.apple.com > Sign-In and Security > App-Specific Passwords"},
    "yahoo":   {"smtp": ("smtp.mail.yahoo.com", 587),
                "imap": ("imap.mail.yahoo.com", 993),
                "help": "Yahoo Account Security > App passwords"},
}


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return _json.load(f)


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        _json.dump(cfg, f, indent=2)
    os.chmod(CONFIG_PATH, 0o600)


def _smtp_send(raw_bytes, cfg):
    host, port = cfg["smtp_host"], cfg["smtp_port"]
    with smtplib.SMTP(host, port, timeout=60) as s:
        s.starttls()
        s.login(cfg["username"], cfg["password"])
        s.sendmail(cfg["from_addr"], [cfg["_to"]], raw_bytes)


def send_sealed(raw_bytes, to_addr, via=None):
    """Send a sealed MIME message. Returns 'smtp:<addr>' or a file path."""
    cfg = load_config()
    if via is None:
        via = "smtp" if cfg else "file"
    if via == "smtp":
        if not cfg:
            raise RuntimeError("no mail configured yet - run `ss setup` first, "
                               "or use --via file")
        cfg = dict(cfg)
        cfg["_to"] = to_addr
        _smtp_send(raw_bytes, cfg)
        return "smtp:%s" % to_addr
    # file mode: hand the user a .eml they can send from any mail client
    # (or hand to a friend to forward). Nothing leaves the machine.
    out = os.path.abspath("sealed-%d.eml"
                          % int(_time.time()))
    with open(out, "wb") as f:
        f.write(raw_bytes)
    os.chmod(out, 0o600)
    return out


def _imap_connect(cfg):
    m = imaplib.IMAP4_SSL(cfg["imap_host"], cfg["imap_port"])
    m.login(cfg["username"], cfg["password"])
    return m


def fetch_unseen(cfg, since_minutes=15, max_n=25):
    """Return [(message_id_header, raw_bytes)] for recent unseen mail."""
    return imap_search(cfg, None, max_n, since_minutes=since_minutes,
                       unseen_only=True)


def imap_search(cfg, query=None, max_n=50, since_minutes=None,
                unseen_only=False):
    """Return [(uid, raw_bytes)] for INBOX mail matching an IMAP query.

    `query` is raw IMAP search text (e.g. 'UNSEEN', 'SUBJECT secret',
    'FROM alice@example.com'); None means no filter beyond the window.
    `since_minutes` limits to recent mail; `unseen_only` adds UNSEEN.
    """
    m = _imap_connect(cfg)
    try:
        m.select("INBOX", readonly=True)
        criteria = []
        if query:
            criteria.append("(%s)" % query)
        if since_minutes is not None:
            since_date = _time.strftime(
                "%d-%b-%Y",
                _time.localtime(_time.time() - since_minutes * 60))
            criteria.append('(SINCE "%s")' % since_date)
        if unseen_only:
            criteria.append("UNSEEN")
        search_str = " ".join(criteria) if criteria else "ALL"
        typ, data = m.search(None, search_str)
        uids = (data[0] or b"").split()[-max_n:]
        out = []
        for uid in uids:
            typ, msg = m.fetch(uid, "(RFC822)")
            if typ == "OK" and msg and msg[0]:
                raw = msg[0][1]
                out.append((uid.decode(), raw))
        return out
    finally:
        try:
            m.logout()
        except Exception:
            pass
