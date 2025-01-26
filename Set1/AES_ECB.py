from base64 import b64decode
from Crypto.Cipher import AES
import sys


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


def aes_ecb_decrypt(ciphertext, key):
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
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext += aes_decrypt_block(block, key)
    return plaintext


def main():
    if len(sys.argv) == 1:
        filename = "AES-base64-encrypted-file.txt"
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
    plaintext = aes_ecb_decrypt(ciphertext, key)

    # Print the decrypted plaintext
    print(f"Decrypted Message:\n{plaintext.decode('utf-8', errors='ignore')}")


if __name__ == "__main__":
    main()
