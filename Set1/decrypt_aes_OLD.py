import string
import sys
from P7_AES_ECB import aes_ecb_decrypt


def is_printable(plaintext):
    """
    Check if the plaintext contains only printable characters.
    Args:
    - plaintext (bytes): The decrypted plaintext.
    Returns:
    - bool: True if all characters in plaintext are printable, False otherwise.
    """
    return all(chr(byte) in string.printable for byte in plaintext)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <hex_file>")
        exit()

    # Define the key
    key = b"YELLOW SUBMARINE"  # 16 bytes long key

    # Read the hex-encoded ciphertexts from the file
    with open(sys.argv[1], "r") as file:
        hex_ciphertexts = file.read().strip().splitlines()

    # Convert the hex-encoded ciphertexts to bytes
    ciphertexts = [bytes.fromhex(hex_ciphertext) for hex_ciphertext in hex_ciphertexts]

    # Try decrypting each ciphertext and check if it contains printable characters
    for i, ciphertext in enumerate(ciphertexts):
        # Decrypt the ciphertext manually in ECB mode
        plaintext = aes_ecb_decrypt(ciphertext, key)

        for byte in plaintext:
            print(chr(byte), end="")
        print()
        # Check if the decrypted plaintext contains only printable characters
        if is_printable(plaintext):
            print(f"Ciphertext {i} is decrypted successfully with printable characters:")
            print(f"Decrypted Message:\n{plaintext.decode('utf-8', errors='ignore')}")
            break  # Stop after finding the correct ciphertext


if __name__ == "__main__":
    main()