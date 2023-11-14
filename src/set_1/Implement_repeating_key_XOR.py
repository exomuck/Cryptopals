def repeated_key_xor(plain_text, key):
    len_key = len(key)
    encoded = []

    # Duyệt qua từng byte trong chuỗi plain text sau đó thực hiện XOR giữa
    # byte hiện tại và byte tương ứng trong key rồi append vào encoded
    for i in range(0, len(plain_text)):
        encoded.append(plain_text[i] ^ key[i % len_key])
    return bytes(encoded)


def main():
    plain_text = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
    key = b'ICE'
    print("Output: ", repeated_key_xor(plain_text, key).hex())


if __name__ == '__main__':
    main()
