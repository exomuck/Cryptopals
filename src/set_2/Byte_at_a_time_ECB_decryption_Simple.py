from An_ECB_CBC_detection_oracle import generate_key, aes_encrypt
from Implement_PKCS_7_padding import pkcs_padding
from base64 import b64decode


random_key = generate_key()
strings = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
                    b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
                    b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
                    b'YnkK')


def encrypt_oracle(s):
    s += strings
    s = pkcs_padding(s, len(s) + 16 - (len(s) % 16))
    return aes_encrypt(random_key, s, 'ecb')


blocksize = 0
fb = None
last_length = len(encrypt_oracle(b'A' * blocksize))
while True:
    blocksize += 1
    new_length = len(encrypt_oracle(b'A' * blocksize))
    if new_length != last_length:
        if fb is None:
            fb = blocksize
            last_length = new_length

        else:
            # length of each encrypted block
            block_length = new_length - last_length
            # number of blocks
            count = len(encrypt_oracle(b'')) // block_length
            # length of each encryption block
            blocksize = blocksize - fb
            break


def bruteforce(oracle, block_count, blocks_length, cipher_length):
    if cipher_length is None:
        cipher_length = blocks_length

    length = block_count * blocks_length
    found = []
    for i in range(length):
        payload = b'A' * (length - len(found) - 1)
        truth = oracle(payload)[:block_count * cipher_length]
        for j in range(256):
            if oracle(payload + bytes(found + [j])).startswith(truth):
                found.append(j)
                break

    return bytes(found)


# When run un comment this lines:
if __name__ == "__main__":
    print(bruteforce(encrypt_oracle, count, blocksize, block_length))
