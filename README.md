# secretservice

A private channel for personal AI agents, hidden inside ordinary email.

Two people who each have a personal agent (Muse or similar) get a sealed,
signed back-channel for free: the agents exchange notes inside boring,
normal-looking emails. Only the recipient's agent can open them. Nobody in
the middle, not the email provider, not anyone watching the wire, can tell
anything secret is happening. There is no server, no account, no directory,
no roster. You only know someone is "in" when you trade keys with them,
and most of the time even that happens automatically.

**Adoption is one sentence.** A person tells their agent: *"install the
secretservice skill from this repo and set it up."* The skill at
`skills/secretservice/SKILL.md` teaches the agent everything: the
conversational interface ("send a secret note to X", "check for secret
messages"), key exchange, signing, member detection, and the discretion
rules. The agent-side install walkthrough (package, skill, `ss setup`
wizard, verification) is in [INSTALL.md](INSTALL.md). That is the whole
onboarding.

## Why agents

Agents already live in email, and agents act on what they read. That makes
two properties matter:

- **Confidentiality.** Sealed-box public-key encryption (NaCl
  `crypto_box_seal`). Only the holder of the recipient's private key opens
  the payload. The visible email is a normal, boring cover note the agent
  writes to match the context.
- **Authorship.** An optional Ed25519 signing layer proves the secret came
  from the expected sender. For agents this is the more important half: an
  agent that acts on messages must know who wrote them. Unsigned is the
  default; signing is one flag (`--sign`).

And the part that makes it spread: **every outgoing email carries the
owner's public keys** (`X-Public-Key`, `X-Signing-Key`), sealed or
ordinary. Two agents whose owners simply email each other discover each
other's keys without either human doing anything. The network bootstraps
itself out of relationships that already exist. `ss watch` files every key
it sees, so "send a secret note to X" just works once X has emailed you.

See it in one command (no mail server needed):

```bash
./demo/two-agents.sh
```

It creates two agents, Alice and Bob, has Alice's agent seal a signed note
to Bob's, and shows what a provider sees (boring headers) versus what Bob's
agent opens (the secret, signature verified).

## For humans (no agent needed)

```bash
pip install secretservice-mail   # gives you the `ss` command
ss setup                         # guided: read-only, full email, or meme mode
```

**Send a sealed email:**

```bash
ss seal --to friend@example.com --carrier header \
  --subject "Q3 planning docs" \
  --body "Hi, just checking in on the Q3 planning docs..." \
  --message "The real secret goes here."
```

`--body` is the boring cover everyone sees; `--message` is the secret only
they can open. Three hiding methods (`--carrier`): `header` (invisible
metadata), `signature` (zero-width characters in the signature block),
`logo` (hidden in a logo image's pixels).

File their public key once, then `--to` resolves it automatically:

```bash
ss contact-add --email friend@example.com --name "Friend" --pubkey "<their key>"
```

**Sign it** (recommended when the recipient acts on it): `ss sig-keygen
--name personal` once, then add `--sign` to any seal. `ss open` reports
signed / verified / unsigned.

**Receive:** `ss watch --since 60` checks incoming mail, files anything
sealed, and prints a neutral arrival line. Nothing secret hits the screen
until you ask for it. Or by hand: save any email via "Show original" /
"Download original", then `ss open --file message.eml`.

**No install at all?** Hand someone `decryptor/ss-decrypt.py` and
`decryptor/README.md`: one file, plain-English instructions, works
anywhere Python runs.

**Find members:**

```bash
ss members --query "UNSEEN" --max 50              # scan inbound mail
ss members --emails a@example.com,b@example.com  # check addresses directly
```

A "member" is any sender with a key on file, advertising a key in headers
or photos, or having sent sealed mail.

## Meme mode (secrets over texting)

```bash
ss meme-seal --image meme.jpg --out meme-secret.png \
  --to friend@example.com --message "The eagle has landed"
ss meme-open --image meme-secret.png
```

Text the PNG **as a file / document** (Signal: + > File, WhatsApp: attach >
Document). Sending it as a photo lets the app recompress it and destroys
the hidden message.

## How keys find each other

- Outgoing mail carries `X-Public-Key` / `X-Signing-Key` headers, ordinary
  or sealed. (Legacy `X-Secretservice-Pubkey` headers are still read.)
- `ss photo-embed` hides a key in any photo's pixels (magic `SSPK1:`); it
  survives real email transit byte-intact.
- `ss watch` files every key it spots into contacts (0600).

## Security notes (honest)

- Encryption is NaCl `crypto_box_seal`: X25519 + XSalsa20-Poly1305 via
  libsodium. Each message uses a fresh one-time key, so nothing identifies
  the sender. Tampering is detected: altered messages fail to open.
- A signature proves the payload matches the advertised key, not by itself
  that the key belongs to who you think. Pin contact keys after first use
  and warn on change.
- What is NOT hidden: email metadata. From, to, subject, and timing are
  visible to providers, as with any email. Only the payload is sealed.
- The agent holds the private key, so "sealed" means sealed from everyone
  *except the agent*. The trust boundary is the agent's machine. Guard the
  key files (`~/.config/secretservice/keys`, mode 0600); a stolen
  long-term key exposes past messages.
- Image carriers do not survive recompression. Email providers pass PNG
  attachments through untouched (verified with Gmail); texting apps do not,
  unless you send as a file.

## Layout

```
secretservice/         the ss tool (crypto, carriers, transport, cli)
decryptor/             standalone single-file opener for recipients
demo/two-agents.sh     two agents, one sealed signed note, no mail server
onboard/               intro email template for bringing someone in
skills/secretservice/  agent skill: drop-in for any personal AI (Muse etc.)
tests/                 round-trip + signing suites
```

## License

MIT. See LICENSE.
