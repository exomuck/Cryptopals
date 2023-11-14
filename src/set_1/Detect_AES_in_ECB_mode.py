from itertools import combinations


# Kiểm tra xem chuỗi có mã hóa bằng ECB không bằng cách chia chuỗi
# thành các khối có kích thước k (trong bài là 16) rồi đếm số lượng
# các cặp khối giống nhau, nếu các cặp giống nhau thì chuỗi đc mã hóa bằng ECB
def detect_aes_in_ecb_score(x, k):
    chunks = [x[i:i + k] for i in range(0, len(x), k)]
    pairs = combinations(chunks, 2)
    matches = 0
    for p in pairs:
        matches += (p[0] == p[1])
    return matches


def main():
    file = '../../assets/Detect_AES_in_ECB_mode.txt'
    text = []
    for line in open(file):
        text.append(line.strip())

    lineCount = 1
    for line in text:
        if detect_aes_in_ecb_score(line, 16) > 0:
            print("Line " + str(lineCount) + " has been encrypted with AES in ECB mode.")
            print(line)
        lineCount += 1


if __name__ == '__main__':
    main()
