def repeated_key_xor(plain_text, key):
    pt = plain_text
    len_key = len(key)
    encoded = []

    for i in range(0, len(pt)):
        encoded.append(pt[i] ^ key[i % len_key])
    return bytes(encoded)


def main():
    plain_text = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
    key = b'ICE'

    print("Expected: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a2"
          "82b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    print("Output: ", repeated_key_xor(plain_text, key).hex())


if __name__ == '__main__':
    main()
