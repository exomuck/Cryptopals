def xor_buffers(buffer1, buffer2):
    if len(buffer1) != len(buffer2):
        raise ValueError("Buffers must have equal length")

    buffer1 = bytes.fromhex(buffer1)  # Convert hex-encoded string to bytes
    buffer2 = bytes.fromhex(buffer2)  # Convert hex-encoded string to bytes

    result = bytearray()
    for byte1, byte2 in zip(buffer1, buffer2):
        xor_byte = byte1 ^ byte2
        result.append(xor_byte)

    print(result.hex())  # Convert the result to a hex-encoded string


if __name__ == "__main__":
    xor_buffers("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
