#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h> // For parsing command-line arguments

#define Nb 4        // Number of culumns. Basically number of words in a block
#define KEY_WORDS 4 // Number of words in the key. Key size / 32
#define ROUNDS 10   // Number of rounds. For AES-128 it's always 10
#define WORD_SIZE 4 // The word size

void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x ", data[i]);
    printf("\n");
}

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// https://en.wikipedia.org/wiki/AES_key_schedule
// https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)
{
    unsigned i, j, k;
    uint8_t previous_word[4]; // Used for the core

    // The first round key is the key itself
    for (i = 0; i < KEY_WORDS; i++)
    {
        for (j = 0; j < WORD_SIZE; j++)
        {
            RoundKey[(i * 4) + j] = Key[(i * 4) + j];
        }
    }

    // All other round keys are found from the previous round keys
    for (i = KEY_WORDS; i < Nb * (ROUNDS + 1); i++)
    {
        k = (i - 1) * 4; // Starting index of the previous word
        for (j = 0; j < WORD_SIZE; j++)
        {
            previous_word[j] = RoundKey[k + j];
        }

        // Now previous_word[0 to 3] is Wi-N

        if (i % KEY_WORDS == 0) // For every beginning of a word
        {
            // RotWord (Basically rotates the bytes in the word)
            const uint8_t u8tmp = previous_word[0];
            previous_word[0] = previous_word[1];
            previous_word[1] = previous_word[2];
            previous_word[2] = previous_word[3];
            previous_word[3] = u8tmp;

            // SubWord (Substitute each byte in the word)
            for (j = 0; j < WORD_SIZE; j++)
            {
                previous_word[j] = sbox[previous_word[j]];
            }

            // XOR only the first byte with initially the first byte of
            // rcon, then the second byte, etc.
            previous_word[0] = previous_word[0] ^ rcon[(i / KEY_WORDS) - 1];
        }

        int current_word_index = i * WORD_SIZE;                // Current word index in the round key
        int previous_word_index = (i - KEY_WORDS) * WORD_SIZE; // Previous word Nk positions earlier

        // So initially the word_pos will be 16 (after the key)
        // and k will be 0 (the first word in the key)
        // Then word_pos will be 20 (after the key)
        // and k will be 4 (the second word in the key)
        for (j = 0; j < WORD_SIZE; j++)
        {
            RoundKey[current_word_index + j] = RoundKey[previous_word_index + j] ^ previous_word[j];
        }
    }
}

void AddRoundKey(uint8_t round, uint8_t state[4][4], const uint8_t *RoundKey)
{
    const int number_of_bytes_in_block = Nb * 4;
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            state[j][i] ^= RoundKey[(round * number_of_bytes_in_block) + (i * 4) + j];
        }
    }
}

void SubBytes(uint8_t state[4][4])
{
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

void ShiftRows(uint8_t state[4][4])
{
    uint8_t temp;

    // Row 1: Rotate left by 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 2: Rotate left by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Rotate left by 3
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// Function to multiply a value by 2 in GF(2^8)
uint8_t MultiplyBy2(uint8_t x)
{
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

// Function to multiply a value by 3 in GF(2^8)
uint8_t MultiplyBy3(uint8_t x)
{
    return MultiplyBy2(x) ^ x;
}

void MixColumns(uint8_t state[4][4])
{
    // [ 2  3  1  1 ]   [ s0 ]
    // [ 1  2  3  1 ] * [ s1 ]
    // [ 1  1  2  3 ]   [ s2 ]
    // [ 3  1  1  2 ]   [ s3 ]
    uint8_t temp[4];
    for (uint8_t i = 0; i < 4; i++)
    {
        // Perform matrix multiplication in GF(2^8)
        temp[0] = MultiplyBy2(state[0][i]) ^ MultiplyBy3(state[1][i]) ^ state[2][i] ^ state[3][i];
        temp[1] = state[0][i] ^ MultiplyBy2(state[1][i]) ^ MultiplyBy3(state[2][i]) ^ state[3][i];
        temp[2] = state[0][i] ^ state[1][i] ^ MultiplyBy2(state[2][i]) ^ MultiplyBy3(state[3][i]);
        temp[3] = MultiplyBy3(state[0][i]) ^ state[1][i] ^ state[2][i] ^ MultiplyBy2(state[3][i]);

        // Copy the result back into the state
        for (uint8_t j = 0; j < 4; j++)
        {
            state[j][i] = temp[j];
        }
    }
}

void Cipher(uint8_t *input, uint8_t *output, const uint8_t *RoundKey, int encrypt)
{
    uint8_t state[4][4];

    // Initialize state with input
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            state[j][i] = input[i * 4 + j];
        }
    }

    if (encrypt)
    {
        AddRoundKey(0, state, RoundKey);

        for (uint8_t round = 1; round < ROUNDS; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(round, state, RoundKey);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(ROUNDS, state, RoundKey);
    }
    else
    {
        // For decryption, we need to start with the last round key

        // I need to implement the inverse of the functions
        // AddRoundKey(ROUNDS, state, RoundKey);
        // ShiftRows(state);
        // SubBytes(state);

        // for (uint8_t round = ROUNDS - 1; round >= 1; round--)
        // {
        //     AddRoundKey(round, state, RoundKey);
        //     MixColumns(state);
        //     ShiftRows(state);
        //     SubBytes(state);
        // }

        // AddRoundKey(0, state, RoundKey);
    }

    // Copy state to output
    for (uint8_t i = 0; i < 4; i++)
    {
        for (uint8_t j = 0; j < 4; j++)
        {
            output[i * 4 + j] = state[j][i];
        }
    }
}

// Main function
int main(int argc, char *argv[])
{
    int opt;
    int mode_encrypt = -1; // -1 means mode not set, 0 = decrypt, 1 = encrypt
    const char *input_file_name = NULL;
    const char *output_file_name = NULL;
    const char *key_file_name = NULL;
    uint8_t roundKey[176]; // Nb * (ROUNDS + 1)
    uint8_t input[16];     // 16 bytes for the input, which is the key + 16 bytes for the every block
    uint8_t output[16];    // 16 bytes for the output, same idea as above
    uint8_t key[16];       // 16 bytes for the key

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "i:o:k:ed")) != -1)
    {
        switch (opt)
        {
        case 'i': // Input file
            input_file_name = optarg;
            break;
        case 'o': // Output file
            output_file_name = optarg;
            break;
        case 'k': // Key file
            key_file_name = optarg;
            break;
        case 'e': // Encryption mode
            mode_encrypt = 1;
            break;
        case 'd': // Decryption mode
            mode_encrypt = 0;
            break;
        default:
            fprintf(stderr, "Usage: %s -i <input_file> -o <output_file> -k <key_file> -e|-d\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    // Validate required arguments
    if (input_file_name == NULL || output_file_name == NULL || key_file_name == NULL || mode_encrypt == -1)
    {
        fprintf(stderr, "Usage: %s -i <input_file> -o <output_file> -k <key_file> -e|-d\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *key_file = fopen(key_file_name, "rb");       // Open the key file in binary mode
    FILE *input_file = fopen(input_file_name, "rb");   // Open the key file in binary mode
    FILE *output_file = fopen(output_file_name, "wb"); // Open the key file in binary mode
    if (!(key_file && input_file && output_file))
    {
        fprintf(stderr, "Error: Could not open files \n");
        return EXIT_FAILURE; // Exit if the file could not be opened
    }

    // printf("%s %s %s %d\n", input_file_name, output_file_name, key_file_name, mode_encrypt);

    // return 0;

    // Read key from the key file
    fread(key, 1, 16, key_file); // 1 is the size of each element, here it's one byte, total of 16 bytes
    KeyExpansion(roundKey, key);

    // // Reset the file pointer to the beginning
    // fseek(input_file_name, 0, SEEK_SET);

    // Read and encrypt blocks
    while (fread(input, 1, 16, input_file) == 16)
    {
        Cipher(input, output, roundKey, mode_encrypt);
        fwrite(output, 1, 16, output_file);
    }

    return EXIT_SUCCESS;
}