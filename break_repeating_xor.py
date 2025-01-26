import base64
import sys
from itertools import combinations
from single_byte_xor_cipher import score_text, find_best_key_and_plaintext


# Function to generate all unique pairs from a list
def generate_pairs(chunks):
    pairs = []
    for i in range(len(chunks)):
        for j in range(i + 1, len(chunks)):
            pairs.append((chunks[i], chunks[j]))
    return pairs


# Function to calculate Hamming distance (number of differing bits)
def hamming_distance(bytes1, bytes2):
    # XOR each byte and count differing bits
    return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(bytes1, bytes2))
    # For strings, we can use ord(b1) ^ ord(b2)
    # zip basically takes the first byte of str1 as b1 and first of str2 as b2, then second, etc.


# Function to guess the keysize based on normalized Hamming distance
def guess_keysize(ciphertext, min_keysize=2, max_keysize=40):
    distances = []  # List to store tuples of (keysize, average normalized distance)

    # 2. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    for keysize in range(min_keysize, max_keysize + 1):
        # 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
        # and find the edit distance between them. Normalize this result by dividing by KEYSIZE.

        # NOTE: I take 4 and take the average (see number 4.)
        end = len(ciphertext) if keysize * 4 > len(ciphertext) else keysize * 4

        # Divide the ciphertext into chunks of size 'keysize'
        chunks = [ciphertext[i:i + keysize] for i in range(0, end, keysize)]

        # 4. The KEYSIZE with the smallest normalized edit distance is probably the key.
        # You could proceed perhaps with the smallest 2-3 KEYSIZE values.
        # Or take 4 KEYSIZE blocks instead of 2 and average the distances.

        # Generate pairs of chunks (first with second, then with third, then fourth, then second with third, etc.)
        pairs = generate_pairs(chunks)

        # Calculate the average normalized distance for this keysize
        total_distance = 0
        for p1, p2 in pairs:
            total_distance += hamming_distance(p1, p2) / keysize

        avg_distance = total_distance / len(pairs)  # Average distance
        distances.append((keysize, avg_distance))

    # Sort by the smallest normalized distance, as smaller values indicate a more likely keysize
    return distances


# Function to break ciphertext into blocks of keysize length
def break_into_blocks(ciphertext, keysize):
    return [ciphertext[i:i + keysize] for i in range(0, len(ciphertext), keysize)]


# Transpose blocks: make a block of first bytes, second bytes, etc.
def transpose_blocks(blocks, keysize):
    transposed = [[] for _ in range(keysize)]
    for block in blocks:
        for i, byte in enumerate(block):
            transposed[i].append(byte)
    return transposed


def find_best_keysize(possible_keysizes):
    # Find the smallest distance
    best_keysize = possible_keysizes[0][0]
    best_distance = possible_keysizes[0][1]

    for keysize, distance in possible_keysizes[1:]:
        if distance < best_distance:
            best_keysize = keysize
            best_distance = distance

    return best_keysize


# Decrypt the repeating-key XOR ciphertext
def decrypt_repeating_key_xor(ciphertext):
    # Step 1: Guess the keysize
    possible_keysizes = guess_keysize(ciphertext)
    best_keysize = find_best_keysize(possible_keysizes)

    # 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    blocks = break_into_blocks(ciphertext, best_keysize)

    # 6. Now transpose the blocks: make a block that is the first byte of every block,
    # and a block that is the second byte of every block, and so on.
    transposed_blocks = transpose_blocks(blocks, best_keysize)

    key = ""
    plaintext = ""
    # 7. Solve each block as if it was single-character XOR. You already have code to do this.
    for block in transposed_blocks:
        best_key, _ = find_best_key_and_plaintext(block)
        # For each block, the single-byte XOR key that produces the best looking histogram
        # is the repeating-key XOR key byte for that block. Put them together and you have the key.
        key += chr(best_key)

    # Decrypt the ciphertext
    for i, byte in enumerate(ciphertext):
        # XOR each ciphertext byte with the ASCII value of the key and then convert the value to char again
        plaintext += chr(byte ^ ord(key[i % len(key)]))

    print(key)
    return key, plaintext


def main():
    if len(sys.argv) != 2:
        print(f"Correct format: python {sys.argv[0]} <base64_encoded_file>")
        exit()

    # Read and decode the base64 file
    with open(sys.argv[1], 'r') as f:
        ciphertext = base64.b64decode(f.read().strip())

    # Decrypt the ciphertext
    key, plaintext = decrypt_repeating_key_xor(ciphertext)

    # Print the results
    print(f"Key: {key}")
    print(f"Decrypted Message: {plaintext}")



if __name__ == '__main__':
    main()
