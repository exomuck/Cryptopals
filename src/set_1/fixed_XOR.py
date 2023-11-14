def xor_buffers(buffer1, buffer2):
    # Kiểm tra độ dài 2 buffer
    if len(buffer1) != len(buffer2):
        raise ValueError("Buffers must have equal length")

    buffer1 = bytes.fromhex(buffer1)  # Đổi hexa sang nhị phân
    buffer2 = bytes.fromhex(buffer2)  # Đổi hexa sang nhị phân

    # Tạo result trống để lưu kết quả sau khi xor
    result = bytearray()

    # Duyệt qua từng byte trong 2 chuỗi
    for byte1, byte2 in zip(buffer1, buffer2):
        # Thực hiện phép xor giữa byte 1 và byte 2
        xor_byte = byte1 ^ byte2
        result.append(xor_byte)

    print(result.hex())  # Đổi nhị phân về lại hex


if __name__ == "__main__":
    xor_buffers("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
