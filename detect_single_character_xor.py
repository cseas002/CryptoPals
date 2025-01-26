import string
import sys
from single_byte_xor_cipher import score_text  # Import the scoring function


# Function to find the best line encrypted with a single-byte XOR cipher
def find_encrypted_line(lines):
    best_score = 0
    best_plaintext = ""
    best_key = None
    best_line_index = None

    for line_index, line in enumerate(lines):
        line = line.strip()  # Remove any extra whitespace or newline characters

        try:
            # Decode the hex string into bytes
            cipher_bytes = bytes.fromhex(line)

            # Try all possible single-byte XOR keys (0-255)
            for key in range(256):
                # XOR each byte with the key
                plaintext_bytes = bytes([byte ^ key for byte in cipher_bytes])

                # Check if the plaintext contains valid printable characters
                if all(chr(byte) in string.printable for byte in plaintext_bytes):
                    # Score the plaintext
                    score = score_text(plaintext_bytes)

                    # Keep track of the best scoring plaintext
                    if score > best_score:
                        best_score = score
                        best_plaintext = plaintext_bytes
                        best_key = key
                        best_line_index = line_index
        except ValueError:
            # Skip lines that cannot be decoded as valid hex strings
            continue

    # Return the best result
    return best_line_index, best_key, best_plaintext


def main():
    if len(sys.argv) != 2:
        print(f"Correct format: python {sys.argv[0]} <file_with_ciphertexts>")
        exit()

    # Read all lines from the input file
    filename = sys.argv[1]
    with open(filename, 'r') as file:
        lines = file.readlines()

    # Find the encrypted line
    best_line_index, best_key, best_plaintext = find_encrypted_line(lines)

    if best_line_index is not None:
        print(f"Encrypted Line Index: {best_line_index + 1}")
        print(f"Best Key: {best_key} ('{chr(best_key)}')")
        print(f"Decrypted Message: {best_plaintext.decode('utf-8')}")
    else:
        print("No valid encrypted line found in the file.")


if __name__ == '__main__':
    main()