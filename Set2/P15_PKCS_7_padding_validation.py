def check_padding(plaintext: bytes):
    padding = plaintext[len(plaintext) - 1]
    for j in range(padding):
        # Check if it's indeed padding
        if plaintext[len(plaintext) - 1 - j] != padding:
            break
        if j == padding - 1:
            # If it is, remove it
            return True

    raise Exception(f"Invalid padding {hex(padding)} for {plaintext}")


def main():
    print(check_padding("ICE ICE BABY\x04\x04\x04\x04".encode()))


if __name__ == '__main__':
    main()
