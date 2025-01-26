import string

# English letter frequency (simplified, based on typical English usage)
import sys

frequency = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702, 'f': 2.228,
    'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
    'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929, 'q': 0.095, 'r': 5.987,
    's': 6.327, 't': 9.056, 'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
    'y': 1.974, 'z': 0.074, ' ': 15.0  # Include space as the most frequent character
}


# Function to score plaintext based on character frequency
def score_text(plaintext):
    return sum(frequency.get(chr(byte), 0) for byte in plaintext.lower())


def find_best_key_and_plaintext(cipher_bytes):
    best_score = 0
    best_plaintext = ""
    best_key = None

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

    return best_key, best_plaintext


def main():
    if len(sys.argv) == 1:
        ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    elif len(sys.argv) != 2:
        print(f"Correct format: python {sys.argv[0]} <ciphertext>")
        exit()
        ciphertext = 0
    else:
        ciphertext = sys.argv[1]
    # Decode the hex string into bytes
    cipher_bytes = bytes.fromhex(ciphertext)

    # Try all possible single-byte XOR keys (0-255)
    best_key, best_plaintext = find_best_key_and_plaintext(cipher_bytes)

    # Display the result
    print(f"Best Key: {best_key} ('{chr(best_key)}')")
    print(f"Decrypted Message: {best_plaintext.decode('utf-8')}")


if __name__ == '__main__':
    main()
