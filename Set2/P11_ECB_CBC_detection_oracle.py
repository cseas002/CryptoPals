import random
from base64 import b64decode
from Set1.P7_AES_ECB import aes_ecb
from P10_AES_CBC import aes_cbc


def generate_random_bytes(length: int):
    return bytes([random.randint(0, 255) for _ in range(length)])


def encryption_oracle(data: bytes, key_length: int):
    key = generate_random_bytes(key_length)

    # # Read the base64-encoded ciphertext from the input file
    # with open(input_file_name, "r") as file:
    #     base64_ciphertext = file.read()
    #
    # # Decode the Base64-encoded content to raw bytes
    # data = b64decode(base64_ciphertext)

    # Append 5-10 bytes randomly in the beginning and the end
    bytes_before = generate_random_bytes(random.randint(5, 10))
    bytes_after = generate_random_bytes(random.randint(5, 10))
    extended_data = bytes_before + data + bytes_after

    # I make this extended data divisible by 16 by adding random padding
    padding_needed = 16 - len(extended_data) % 16
    padding = generate_random_bytes(padding_needed)
    extended_data += padding

    # Encrypt EBC or CBC randomly (50-50 changes)
    if random.random() < 0.5:
        encrypted_data = aes_ecb(extended_data, key, True)
        actual_mode = "ECB"
    else:
        iv = generate_random_bytes(16)
        encrypted_data = aes_cbc(extended_data, key, iv, True)
        actual_mode = "CBC"

    return encrypted_data, actual_mode


def detect_mode(ciphertext: bytes, block_size: int = 16) -> str:
    # Split ciphertext into 16-byte blocks
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    # If there are duplicate blocks, it's ECB; otherwise, it's CBC
    if len(blocks) != len(set(blocks)):  # Python's set is a unique set of elements
        return "ECB"
    else:
        return "CBC"


def main():
    # Since I give "AAAA", some blocks (not the first nor the last) will be the same in ECB
    ciphertext, actual_mode = encryption_oracle(b"A" * 64, 16)
    print(detect_mode(ciphertext))


if __name__ == '__main__':
    main()
