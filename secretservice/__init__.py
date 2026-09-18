"""secretservice: covert messaging over email.

Cover traffic looks like ordinary email. The real message is sealed with the
recipient's public key (NaCl sealed box) and hidden in one of three carriers:
custom headers, zero-width signature steganography, or LSB steganography in a
PNG logo attachment.
"""

__version__ = "1.0.0"
