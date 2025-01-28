import sys
from collections import defaultdict


def detect_ecb_ciphertext_from_file(hex_ciphertexts):
    # Process each hex ciphertext from the file
    for hex_ciphertext in hex_ciphertexts:
        hex_ciphertext = hex_ciphertext.strip()  # Strip any extra newlines or spaces

        # Convert hex-encoded ciphertext to bytes
        ciphertext = bytes.fromhex(hex_ciphertext)

        # Split the ciphertext into 16-byte blocks
        blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

        # Track seen blocks
        # Create a defaultdict to track how many times each block appears
        # If a block appears more than once, it's likely that we're dealing with ECB encryption
        # defaultdict is a specialized dictionary from Python’s collections module. It’s like a regular dictionary,
        # but it automatically initializes a default value when you access a key that doesn’t exist in the dictionary yet.
        seen_blocks = defaultdict(int)

        # Look for repeating blocks
        for block in blocks:
            seen_blocks[block] += 1
            if seen_blocks[block] > 1:
                return hex_ciphertext  # Return the first ciphertext with repeated blocks

    return None  # If no ECB ciphertext is found


def main():
    if len(sys.argv) == 1:
        filename = "ciphertexts-encoded.txt"
    elif len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <base64_file>")
        exit()
        filename = ""
    else:
        filename = sys.argv[1]

    # Read the base64-encoded ciphertext from the input file
    with open(filename, "r") as file:
        # Read all lines from the file (assuming one ciphertext per line)
        hex_ciphertexts = file.readlines()

    # Call the function to detect ECB mode ciphertext from the file
    ecb_ciphertext = detect_ecb_ciphertext_from_file(hex_ciphertexts)

    if ecb_ciphertext:
        print(f"ECB Ciphertext found: {ecb_ciphertext}")
    else:
        print("No ECB ciphertext detected.")


if __name__ == "__main__":
    main()
