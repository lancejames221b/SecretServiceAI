# ss-decrypt: read sealed emails

Someone can send you an email that looks completely ordinary but carries a
secret message only you can read. This little tool opens it. You do not need
an email account of your own connected to anything, and nothing is uploaded
anywhere: everything happens on your computer.

## What you need

- Python 3 (any recent version)
- The `pynacl` library, installed once with: `pip install pynacl`
- This file: `ss-decrypt.py`

## Step 1: make your key

Run this once:

```
python3 ss-decrypt.py --genkey mykey.key
```

It creates `mykey.key` (your private key, only readable by you) and prints
your **public key**, a short block of text. Send that public key to the
person who gave you this tool. They need it to seal messages for you.

Keep `mykey.key` private. Anyone with that file can read your sealed mail.

## Step 2: save the email as a raw file

When a sealed email arrives:

1. Open the message in your mail app's **desktop web version**.
2. Find "Show original" (Gmail: the three dots at the top-right of the
   message) and choose **"Download original"**.
3. Save the file, for example as `message.eml`.

(Use a desktop browser for this step; phone mail apps usually cannot do it.)

## Step 3: decrypt

```
python3 ss-decrypt.py --eml message.eml --key mykey.key
```

The secret message prints to your terminal. The visible email stays exactly
as boring as it looked.

## Troubleshooting

- **"No hidden payload found"**: the file is not the raw original, or the
  message was not sealed. Re-download via "Show original".
- **"your key could not open it"**: the message was sealed for a different
  public key. Make sure the sender used the public key from Step 1.
- **"only 8-bit RGB/RGBA non-interlaced PNG is supported"**: the logo image
  was altered in transit (some mail clients re-encode images). Ask the
  sender to resend using a different hiding method.
