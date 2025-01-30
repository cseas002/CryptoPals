from base64 import b64decode
from Crypto.Cipher import AES
import sys

from Set2.P15_PKCS_7_padding_validation import check_padding


def aes_decrypt_block(block, key):
    """
    Decrypt a single 16-byte block using AES-128.
    Args:
    - block (bytes): The 16-byte ciphertext block.
    - key (bytes): The 16-byte AES key.
    Returns:
    - plaintext (bytes): The decrypted 16-byte plaintext block.
    """
    if len(block) != 16:
        raise ValueError("Block size must be exactly 16 bytes.")
    if len(key) != 16:
        raise ValueError("Key size must be exactly 16 bytes.")

    # Initialize AES cipher in ECB mode for a single block
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)


def aes_encrypt_block(block, key):
    """
    Decrypt a single 16-byte block using AES-128.
    Args:
    - block (bytes): The 16-byte ciphertext block.
    - key (bytes): The 16-byte AES key.
    Returns:
    - plaintext (bytes): The decrypted 16-byte plaintext block.
    """
    if len(block) != 16:
        raise ValueError("Block size must be exactly 16 bytes.")
    if len(key) != 16:
        raise ValueError("Key size must be exactly 16 bytes.")

    # Initialize AES cipher in ECB mode for a single block
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def aes_ecb(ciphertext, key, encrypt: bool, block_size=16):
    """
    Decrypt ciphertext in ECB mode manually by processing block-by-block.
    Args:
    - ciphertext (bytes): The encrypted ciphertext.
    - key (bytes): The 16-byte AES key.
    Returns:
    - plaintext (bytes): The decrypted plaintext.
    """
    plaintext = b""
    # Here we don't care about padding, we assume it's a multiple of 16
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        plaintext += aes_encrypt_block(block, key) if encrypt else aes_decrypt_block(block, key)
        if len(ciphertext) - i < block_size and not encrypt:
            # Remove padding
            padding = plaintext[len(plaintext) - 1]
            if check_padding(plaintext):
                plaintext = plaintext[0:len(plaintext) - padding]

            # for j in range(padding):
            #     # Check if it's indeed padding
            #     if plaintext[len(plaintext) - 1 - j] != padding:
            #         break
            #     if j == padding - 1:
            #         # If it is, remove it
            #         plaintext = plaintext[0:len(plaintext) - padding]
    return plaintext


def aes_ecb_encrypt(ciphertext, key):
    return aes_ecb(ciphertext, key, True)


def aes_ecb_decrypt(ciphertext, key):
    return aes_ecb(ciphertext, key, False)


def main():
    if len(sys.argv) == 1:
        filename = "AES-base64-encrypted-file-EBC.txt"
    elif len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <base64_file>")
        exit()
        filename = "" # not needed
    else:
        filename = sys.argv[1]

    # Define the key
    key = b"YELLOW SUBMARINE"  # 16 bytes long key

    # Read the base64-encoded ciphertext from the input file
    with open(filename, "r") as file:
        base64_ciphertext = file.read()

    # Decode the Base64-encoded content to raw bytes
    ciphertext = b64decode(base64_ciphertext)

    # Decrypt the ciphertext manually in ECB mode
    plaintext = aes_ecb(ciphertext, key, False)

    # Print the decrypted plaintext
    print(f"Decrypted Message:\n{plaintext.decode('utf-8', errors='ignore')}")


if __name__ == "__main__":
    main()
