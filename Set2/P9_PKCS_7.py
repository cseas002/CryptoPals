def add_padding(block: bytearray, block_size: int):
    padding = block_size - len(block)
    for i in range(padding):
        block.append(padding)

    print(block)


def main():
    # Define the key
    key = bytearray(b"YELLOW SUBMARINE")  # 16 bytes long key
    add_padding(key, 20)


if __name__ == '__main__':
    main()
