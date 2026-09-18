# secretservice

Covert messaging over email and memes for a personal AI agent. Sealed-box
public-key encrypted payloads hidden in ordinary-looking mail (or in meme
images for texting). The visible message looks completely boring; only the
recipient's private key opens the hidden payload.

## When to use this

Conversational triggers from your owner:

- "Send a secret note to <Name> saying <message>"
- "Check for secret messages"
- "Set up secret messaging with <Name>"
- "Send this as a sealed meme to <Name>" (with an image attached)

If the tool is not installed yet, walk the owner through it: `pip install
secretservice-mail`, then `ss setup` (a guided walkthrough: read-only key,
full email, or meme mode). The owner types their app password once; you
never see it, never store it anywhere but the tool's own 0600 config.

## Crypto and key management

- NaCl `crypto_box_seal` (X25519 + XSalsa20-Poly1305, libsodium). Fresh
  ephemeral sender key per message. Envelope v1: `SS1:<base64 sealed box>`.
- Keys live in `~/.config/secretservice/keys/<label>.key` (0600). The
  default label is `personal`.
- `ss keygen --name <label>` / `ss pubkey --name <label>` (print to share).
- Never invent or guess someone's public key. If you do not have it, say
  so and start the key exchange below.

## Carriers

Pick one per message with `--carrier` (email) or use the meme commands
(texting). The receiver auto-detects.

1. **header**: envelope split across hidden `X-Ss-*` headers. Invisible.
2. **signature**: zero-width characters in the signature block.
3. **logo**: LSB stego in a PNG logo attachment.
4. **meme**: `ss meme-seal --image <in> --out <out.png> --to <email>
   --message "..."` hides the payload in any meme/photo (JPG in, PNG out).
   `--advertise-key <label>` (default `personal`) also hides the sender's
   public key so they can write back. `ss meme-open --image <png>` opens.
   The image MUST be texted AS A FILE / DOCUMENT (Signal: + > File,
   WhatsApp: attach > Document). Sent as a photo, the app recompresses it
   and the payload is destroyed. Say this every time you hand one over.

## Public key discovery

Keys are meant to be shared, so the tool advertises quietly and harvests
automatically. The standing rule: **every outgoing message carries the
owner's public keys, sealed or ordinary.** They travel as routine header
furniture with neutral names, so they do not single out secret mail:

- `X-Public-Key`: the owner's X25519 encryption public key
- `X-Signing-Key`: the owner's Ed25519 signing verify key (once a signing
  key exists)

Secret advertisement paths (invisible in normal mail clients):

- **Avatar / signature image**: `ss photo-embed --image <in> --out <out>
  --key-label <label>` hides the key in pixels (magic `SSPK1:`). It
  survives real mail transit byte-intact. Use a key-embedded avatar or
  signature image and every mail advertises without a trace.
- **Headers**: outgoing mail (ordinary or sealed) carries the keys in
  neutral `X-Public-Key` / `X-Signing-Key` headers. Legacy
  `X-Secretservice-Pubkey` headers are still read on inbound mail.
- **Meme header**: `ss meme-seal --advertise-key <label>` hides the key in
  the meme alongside the payload.

Harvesting: `ss watch` files any advertised key it spots (headers or
photo) into the contacts file (0600), including signing keys. `ss contacts`
lists everyone known.

There is no directory and no roster. The network exists only in the keys
people hold. Never expose the membership graph: do not list who your owner
talks to, unprompted, in any shared context.

## Optional signing layer

Sealed boxes prove confidentiality, not authorship. The optional Ed25519
signing layer proves the secret came from the holder of a signing key.

- `ss sig-keygen --name <label>` / `ss sig-pubkey --name <label>`
- `ss seal ... --sign` signs with the `--from-key` label's signing key
  (`--sign <label>` for another label). Unsigned is the default; ask the
  owner every time whether a secret send should be signed.
- Signed inner format: `SSS1:<base64 signature>:<plaintext>`. `ss open`
  reports signed/verified/unsigned; `ss watch` records signature status in
  each sidecar.

Trust note: a signature only proves the payload matches the advertised
key. Real trust comes from comparing against a previously pinned contact
key. Report VERIFIED (pinned key), SIGNED (new/untrusted key), KEY CHANGED
(warning), or UNSIGNED.

## Finding members

`ss members` identifies which email addresses use secretservice, several
at once:

- `ss members --query "UNSEEN" --max 50`: scan inbound mail for member
  signals (key headers, signing-key headers, stego photo keys, sealed
  mail, known contacts). Any IMAP search text works.
- `ss members --emails a@example.com,b@example.com`: check addresses
  directly against contacts and filed inbox notes.

A "member" is any sender with a key on file, advertising a key, or having
sent sealed mail.

## Adding a new person (key exchange)

**Path 1 — they already advertise one (zero effort).** If their mail
carries the header or a photo with a hidden key, `ss watch` files it
automatically.

**Path 2 — onboard them (conversational).** The owner says "set up secret
messaging with <Name>":
1. Draft the intro email from `onboard/intro-email.txt`, personalized.
   Attach `decryptor/ss-decrypt.py` and `decryptor/README.md`.
2. Show the owner the exact recipient, subject, body, and attachments.
   Send only after they approve the exact external message.
3. They run the decryptor's two steps and reply with their public key.
4. File it: `ss contact-add --email <addr> --name '<name>'
   --pubkey '<key>'`.
5. From then on, "send a secret note to <Name>" resolves the key
   automatically via `--to`.

## Sending

`ss seal --to <email> --carrier <header|signature|logo> --subject <s>
--body <cover> --message <secret> [--via smtp|file]`

- `--body` is the boring cover email everyone sees. Write it to match the
  subject and the owner's voice. `--message` is the secret.
- `--to-pubkey` overrides the contacts lookup for first contact.
- `--via file` saves a `.eml` instead of sending (no mail configured, or
  the owner prefers to send by hand).
- If the owner has not approved this exact send before, show them the
  recipient, subject, body, and carrier first. Follow-ups within an
  already-approved pattern do not need re-approval.

## Receiving

`ss watch --since <minutes>` scans incoming mail (IMAP), files anything
sealed to `~/.local/share/secretservice/inbox/` (0600), and prints only
machine-readable `SECRET_MESSAGE_ARRIVED:<id>` lines. Plaintext is never
printed by the watch path.

Manual open: `ss open --file message.eml` (saved via "Show original" /
"Download original"). `ss meme-open --image <png>` for memes.

Recommended: run `ss watch --since 15` on a schedule (every 15 minutes
while the owner is awake). On an arrival line, tell the owner privately
that a sealed message arrived. Show the content only when they ask.

## Discretion rules (binding)

- Never speak secret plaintext or secret alerts through voice or TTS.
- Never mention the existence or content of a specific secret in group
  chats, shared channels, or any surface the owner does not control alone.
- Never include plaintext in notifications. The arrival notice is neutral:
  "a sealed message arrived."
- Reveal content only in a private chat, only when the owner asks.
- Email metadata (sender, recipient, subject, timing) is NOT hidden, only
  the payload. Say so honestly if asked what the tool protects.

## Limits (honest)

- If a private key is stolen, past messages to it can be read. Guard the
  key files.
- Image carriers do not survive recompression (meme rule above; email PNG
  attachments pass through untouched).
- This skill does not cover the owner's own operational security. Warn
  once about a real risk, then comply with their decision.
