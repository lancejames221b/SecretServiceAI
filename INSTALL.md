# Installing secretservice (for AI agents)

This page is written for a personal AI agent (Muse or similar) setting
secretservice up for its owner. If you are the human, hand this whole
file to your agent and say "install the secretservice skill from this
repo and set it up."

## 1. Install the package

```bash
pip install git+https://github.com/lancejames221b/SecretServiceAI.git
```

(This installs the `ss` command. Once the package lands on PyPI this
becomes `pip install secretservice-mail`.)

Requires Python 3.9+, and pulls in `pynacl` and `pillow`.

## 2. Install the skill

Copy `skills/secretservice/` from this repo into your agent's skills
directory (for Muse, `~/workspace/skills/secretservice/`). The
`SKILL.md` inside teaches you everything: the conversational interface,
key exchange, signing, member detection, and the discretion rules.

## 3. Run the setup wizard

```bash
ss setup
```

The wizard walks the owner through three paths — pick together:

1. **Read sealed messages sent to me** (simplest, 2 minutes). Just
   generates their keypair. They open messages with the decryptor or
   `ss open`.
2. **Full email setup** (send and receive sealed email, 5 minutes).
   Asks for their email address, provider, and an **app password**
   (never their real password; typed by the owner, hidden as they type).
   It verifies the login on the spot and stores it 0600 on the machine.
   The owner types the password themselves — you never see it, never
   store it anywhere but the tool's own config.
3. **Meme mode** (secrets in images for texting, 2 minutes). Just
   generates their keypair. No mail connection needed.

Every path also offers a **signing key** (recommended): an Ed25519 key
that proves sealed messages came from the owner, which matters whenever
the recipient acts on them.

The wizard prints the owner's **public** keys at the end. Those are
safe to share — post them anywhere, email them to contacts, hide one
in the owner's avatar with `ss photo-embed`.

## 4. Verify it works

No mail server needed:

```bash
./demo/two-agents.sh
```

It creates two fake agents, seals a signed note from one to the other,
and shows what a provider sees versus what the recipient's agent opens.

With real mail configured: `ss seal --to <own-address> --carrier header
--subject "test" --body "boring cover" --message "it works" --sign`,
then `ss watch --since 5` and `ss open` the filed note.

## 5. Ongoing

- `ss watch --since 15` on a schedule (every 15 minutes while the owner
  is awake) files incoming sealed mail. Plaintext never hits the screen
  until the owner asks for it.
- Every outgoing email should carry the owner's public keys
  (`X-Public-Key`, `X-Signing-Key`) so other agents discover them
  automatically. If you control the owner's mail sending, add the
  headers there too.

Key exchange with a new person is in the skill under "Adding a new
person". The short version: if their mail already advertises a key,
`ss watch` files it automatically; otherwise send the intro email from
`onboard/intro-email.txt` with `decryptor/ss-decrypt.py` attached.

## 6. Optional: the agent console (graphical front end)

If the owner prefers point-and-click over the terminal, build them a
private Secretservice Console: a fullstack artifact with a composer, a
receiver, and a system panel. It must stay private (fullstack artifacts
cannot be published — which is exactly right for a key-handling tool).
Each owner gets their own, built by their own agent against their own
keys; the Gmail transport from step 3 does the rest.

Build brief for the agent:

- **Composer (recipient-first):** pick a recipient from contacts, type
  the note, choose signed or unsigned, pick the carrier (header,
  signature, logo, meme). Output is a downloadable `.eml` draft for
  email carriers (the owner sends it from their mail client), or a
  lossless PNG for meme mode (text it as a file/document, never as a
  photo).
- **Receiver (explicit):** paste a raw email or sealed block, click
  Open. It decrypts server-side and reports the trust status: VERIFIED
  (pinned key), SIGNED (new/untrusted key), KEY CHANGED (warning), or
  UNSIGNED.
- **System panel:** local public keys (encryption + signing, with
  copy buttons), contacts list, filed inbox messages from `ss watch`,
  and batch member detection (`ss members`).
- **Backend:** shell out to the local `ss` CLI (`ss seal --dry-run`,
  `ss open`, `ss contacts`, `ss contact-add`, `ss members`,
  `ss keygen`/`pubkey`, `ss sig-keygen`/`sig-pubkey`,
  `ss meme-seal`/`meme-open`). Do not reimplement the crypto.
- **Security rules (binding):** private key bytes never leave the
  server side and are never sent to the browser; inbox plaintext is
  shown only after an explicit Open action; never log plaintext.
