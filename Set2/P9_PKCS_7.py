def add_padding(input_bytes, block_size: int):
    padding_length = (block_size - (len(input_bytes) % block_size)) % block_size
    padding = chr(padding_length).encode()
    for i in range(padding_length):
        input_bytes += padding

    return input_bytes


def main():
    # Define the key
    key = bytearray(b"YELLOW SUBMARINE")  # 16 bytes long key
    key = add_padding(key, 20)
    print(key)


if __name__ == '__main__':
    main()
