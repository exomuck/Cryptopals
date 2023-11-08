from binascii import unhexlify


def unhex(str):
    for xor_key in range(256):
        decoded = ''.join(chr(b ^ xor_key) for b in str)
        if any(c.isprintable() or c == '\n' for c in decoded):
            # if decoded[0] == "C": # Use for CTF (Knowing some of the first characters of string)
            print(decoded)


if __name__ == "__main__":
    encoded = unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    unhex(encoded)
