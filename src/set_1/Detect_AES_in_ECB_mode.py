from itertools import combinations


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
