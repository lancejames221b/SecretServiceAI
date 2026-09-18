#!/usr/bin/env bash
# Two personal agents, one sealed conversation. No mail server needed.
#
# Simulates what happens when two people who each have a personal AI agent
# (Muse or similar) end up with a private channel: Alice's agent seals a
# signed note to Bob's agent. Everything travels inside a boring-looking
# email; only Bob's agent can open it, and the signature proves it came
# from Alice's agent.
#
# Usage: ./demo/two-agents.sh
# Requires: the repo installed (pip install -e .) so `ss` is on PATH,
#           or set SS to the ss entry point.
set -euo pipefail

SS="${SS:-ss}"
WORK="$(mktemp -d)"
ALICE_KEYS="$WORK/alice-keys"
BOB_KEYS="$WORK/bob-keys"
ALICE_DATA="$WORK/alice-data"
BOB_DATA="$WORK/bob-data"
trap 'rm -rf "$WORK"' EXIT

alice() { SECRETSERVICE_KEYS_DIR="$ALICE_KEYS" SECRETSERVICE_DATA_DIR="$ALICE_DATA" "$SS" "$@"; }
bob()   { SECRETSERVICE_KEYS_DIR="$BOB_KEYS"   SECRETSERVICE_DATA_DIR="$BOB_DATA"   "$SS" "$@"; }

echo "== 1. Each agent makes its own keys (once, ever) =="
alice keygen --name personal >/dev/null
alice sig-keygen --name personal >/dev/null
bob keygen --name personal >/dev/null
echo "   Alice and Bob each have an encryption keypair and a signing key."

echo "== 2. They learn each other's public keys =="
echo "   (In real life this is automatic: every email carries X-Public-Key"
echo "    and X-Signing-Key headers, and ss watch files them.)"
BOB_PUB="$(bob pubkey --name personal | tail -1)"
alice contact-add \
  --email bob@example.com --name "Bob" --pubkey "$BOB_PUB" >/dev/null
echo "   Alice's agent filed Bob's public key."

echo "== 3. Alice's agent seals a SIGNED note to Bob's agent =="
cd "$WORK"
alice seal \
  --to bob@example.com \
  --carrier header \
  --subject "Q3 planning docs" \
  --body "Hi, just checking in on the Q3 planning docs. Let me know if you need anything from my side." \
  --message "The real terms: we accept, delivery Friday. Do not forward." \
  --sign --via file >/dev/null
EML="$(ls -t sealed-*.eml | head -1)"
echo "   Sealed into $EML"
echo "   What a mail provider sees:"
grep -E "^(To|Subject|X-Public-Key|X-Signing-Key|X-Ss-)" "$EML" | cut -c1-72
echo "   ..."

echo "== 4. Bob's agent opens it =="
bob open --file "$EML"
