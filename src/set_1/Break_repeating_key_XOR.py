import math
import base64
import statistics
from itertools import combinations

# Globals
COUNTS = [bin(x).count("1") for x in range(256)]
# Tần suất xuất hiện của từng chữ cái trong bảng chữ cái tiếng Anh
FREQ = {'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
        'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
        'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
        'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}


# Phép xor giữa 2 chuỗi byte
def xor_bytes(b1, b2):
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])


# Phép xor giữa chuỗi byte với 1 số nguyên
def xor_bytes_const(b, const):
    return bytes([const ^ _b for _b in b])


# Tính khoảng cách Bhattacharyya (xác suất thống kê)
# https://pypi.org/project/dictances/
# https://safjan.com/understanding-bhattacharyya-distance-and-coefficient-for-probability-distributions/
def bhattacharyya_distance(dist1, dist2):
    bc_coeff = 0
    for letter in FREQ.keys():
        bc_coeff += math.sqrt(dist1[letter] * dist2[letter])

    return -math.log(bc_coeff)


# Đánh giá 1 chuỗi dựa trên tần suất xuất hiện (FREQ)
def score_string(word):
    curr_freq = {letter: 0 for letter in FREQ.keys()}

    num_letters = 0
    for i in word:
        if chr(i).lower() in FREQ.keys():
            curr_freq[chr(i).lower()] += 1
            num_letters += 1

    if num_letters != 0:
        curr_freq = {letter: val / num_letters for letter, val in curr_freq.items()}
    else:
        return 0

    # Dự đoán khoảng cách bằng bhattacharyya_distance()
    distance = bhattacharyya_distance(FREQ, curr_freq)
    return 1 / distance


# Mã hóa chuỗi xor bằng phép xor với 1 key lặp đi lặp lại
def repeating_key_xor(stream, key):
    return bytes([letter ^ key[idx % len(key)] for idx, letter in enumerate(stream)])


# Tính khoảng cách của các số bit khác nhau giữa 2 byte
def hamming_dist(b1, b2):
    diff = xor_bytes(b1, b2)
    count = sum(map(lambda x: COUNTS[x], diff))
    return count


# Kích thước key tạo ra để khoảng cách các số bit khác nhau giữa 2 byte là nhỏ nhất trong các khối data
def eval_key_size(stream, max_key_size):
    # default values
    min_dist = max_key_size * 8
    best_key_size = 2

    # Tìm size hợp lí nhất của key
    for key_size in range(2, max_key_size):
        # Tính khoảng cách giữa các chunk (khối data)
        idx_list = combinations(range(5), 2)
        dist_list = []
        for idx in idx_list:
            block1 = stream[idx[0] * key_size:(idx[0] + 1) * key_size]
            block2 = stream[idx[1] * key_size:(idx[1] + 1) * key_size]
            dist_list.append(hamming_dist(block1, block2))

        # Cập nhật kết quả tốt nhất
        total_dist = statistics.mean(dist_list) / key_size
        if total_dist < min_dist:
            min_dist = total_dist
            best_key_size = key_size

    return best_key_size


# Chia dữ liệu thành các khối có kích thước bằng với kích thước của khóa
def divide_blocks(stream, key_size):
    block_list = [stream[shift::key_size] for shift in range(key_size)]
    return block_list


# Giải mã chuỗi được mã hóa bằng phép xor với 1 byte duy nhất
def decode_single_byte_xor_cypher(src):
    max_score = 0
    best_key = 0
    for i in range(2 ** 8):
        tmp = xor_bytes_const(src, i)
        score = score_string(tmp)

        if score > max_score:
            max_score = score
            best_key = i

    return best_key


def main():
    # Đặt size của key = 40
    KEYSIZE = 40

    # Chuyển từ base64 sang byte, lấy từ file txt
    with open('../../assets/break_repeating_key_xor.txt', 'r') as fh:
        cipher = base64.b64decode(fh.read())

    # Tìm kích thước key hợp lí nhất
    key_size = eval_key_size(cipher, KEYSIZE)

    # Chia các chunk để decode
    block_list = divide_blocks(cipher, key_size)

    # Mỗi block/chunk sẽ có chung 1 key để decode
    key = []
    for block in block_list:
        key.append(decode_single_byte_xor_cypher(block))

    key = bytes(key)
    print(f'{key=}')

    # Chèn key và cipher vào hàm decode sau đó in ra
    word = repeating_key_xor(cipher, key)
    print(f'{word=}')


if __name__ == '__main__':
    main()
