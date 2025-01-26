import sys


def xor_bits(bit1, bit2):
    return "1" if bit1 != bit2 else '0'


def xor_strings(msg1, msg2):
    if len(msg1) != len(msg2):
        print("The strings must have the same length")
        exit(-1)
    result = ""
    for i in range(len(msg1)):
        bit1 = int(msg1[i])
        bit2 = int(msg2[i])
        result += xor_bits(bit1, bit2)

    return result


def decode_hex_string_to_bin_string(string):
    # Convert the string into a binary string
    bin_string = ""
    for char in string:
        # https://stackoverflow.com/questions/1425493/convert-hex-to-binary
        hex_value = int(char, 16)
        binary_value = bin(hex_value)[2::].zfill(4)
        bin_string += binary_value

    return bin_string


def xor(hex_string_1, hex_string_2):
    bin_string_1 = decode_hex_string_to_bin_string(hex_string_1)
    bin_string_2 = decode_hex_string_to_bin_string(hex_string_2)

    # XOR bit by bit
    ans = xor_strings(bin_string_1, bin_string_2)

    hex_ans = ""
    for i in range(0, len(ans), 4):
        hex_value = 0
        for j in range(4):
            bit = int(ans[i + j])
            hex_value += bit * pow(2, 3 - j)
        hex_ans += hex(hex_value)[2::]

    return hex_ans


def main():
    if len(sys.argv) != 3:
        # print(f"Correct format: python {sys.argv[0]} <first hex> <second hex>")
        hex_string_1 = "1c0111001f010100061a024b53535009181c"
        hex_string_2 = "686974207468652062756c6c277320657965"
    else:
        hex_string_1 = sys.argv[1]
        hex_string_2 = sys.argv[2]

    ans = xor(hex_string_1, hex_string_2)
    print(ans)


if __name__ == '__main__':
    main()
