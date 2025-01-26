import sys


# Function to perform repeating-key XOR encryption
def repeating_key_xor(plaintext, key):
    ciphertext = bytearray()
    key_length = len(key)

    # Encrypt each byte of the plaintext
    for i, byte in enumerate(plaintext):
        # XOR the byte with the corresponding key byte (repeating the key as necessary)
        ciphertext.append(byte ^ key[i % key_length])

    return ciphertext


def main():
    if len(sys.argv) != 3:
        print(f"Correct format: python {sys.argv[0]} <plaintext> <key>")
        exit()

    # Read plaintext and key from command-line arguments
    plaintext = sys.argv[1].encode()  # Convert plaintext to bytes
    key = sys.argv[2].encode()  # Convert key to bytes

    # Perform encryption
    ciphertext = repeating_key_xor(plaintext, key)

    # Convert the ciphertext to a hexadecimal string
    ciphertext_hex = ciphertext.hex()

    # Print the result
    print(f"Ciphertext (hex): {ciphertext_hex}")


if __name__ == '__main__':
    main()
