#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_MESSAGE_SIZE 10000

// read message from file
char* read_plaintext_file(const char* filename) {

    FILE* file = fopen(filename, "r");

    if (!file) {

        fprintf(stderr, "Could not open file: %s\n", filename);

        exit(1);

    }

    char* buffer = malloc(MAX_MESSAGE_SIZE);

    if (!buffer) {

        fprintf(stderr, "Memory allocation failed\n");

        exit(1);

    }

    size_t read = fread(buffer, 1, MAX_MESSAGE_SIZE - 1, file);

    buffer[read] = '\0';

    fclose(file);

    return buffer;

}

// read key matrix from file

int** read_key_matrix(char* filename, int* key_size) {

    FILE* file = fopen(filename, "r");

    if (!file) {

        fprintf(stderr, "Could not open file: %s\n", filename);

        exit(1);

    }

    int key_dimension;

    fscanf(file, "%d", &key_dimension);

    int** key_array = malloc(key_dimension * sizeof(int*));

    for ( int i = 0; i < key_dimension; i = i + 1 ) {

        key_array[i] = malloc(key_dimension * sizeof(int));

        for (int j = 0; j < key_dimension; j = j + 1 ) {

            fscanf(file, "%d", &key_array[i][j]);

        }

    }

    *key_size = key_dimension;

    fclose(file);

    return key_array;

}

// custom crypto mod function
int mod26(int x) {

    return (x % 26 + 26) % 26;

}

// remove nonalphabetical characters and convert to uppercase
void clean(char* string) {

    char* source = string;
    char* destination = string;

    while (*source) {

        if ( isalpha((unsigned char)*source) ) {

            *destination++ = toupper( (unsigned char)*source );

        }

        source++;

    }

    *destination = '\0';
}

// pad with x's to make compatible with encryption key
void pad(char* string, int block_size) {

    int length = strlen(string);

    int remainder = length % block_size;

    if (remainder != 0) {

        int padding = block_size - remainder;

        for ( int i = 0; i < padding; i = i + 1 ) {

            string[length + i] = 'X';

        }

        string[length + padding] = '\0';

    }

}

// convert characters to numbers 
// starting with a = 0, z = 25)

int* to_numbers(char* string) {

    int len = strlen(string);

    int* nums = malloc(len * sizeof(int));

    for (int i = 0; i < len; i = i + 1) {

        nums[i] = string[i] - 'A';

    }

    return nums;
}

// convert numbers back to characters

void to_chars(int* nums, char* str, int len) {

    for ( int i = 0; i < len; i = i + 1 ) {

        str[i] = nums[i] + 'A';

    }

    str[len] = '\0';

}

// hill cipher encryption

void encrypt_hill(int* input, int* output, int length, int** key, int block_size) {

    for (int i = 0; i < length; i += block_size) {

        for (int row = 0; row < block_size; row++) {

            int sum = 0;

            for (int col = 0; col < block_size; col++) {

                sum += key[row][col] * input[i + col];

            }

            output[i + row] = mod26(sum);

        }

    }
    
}


// rail fence cipher encryption

char* rail_cipher_str(const char* message, int rows) {

    // just return the message if rows are less than 2

    if (rows < 2) {

        char* result = strdup(message);

        return result;

    }

    int len = strlen(message);

    char** rail = malloc(rows * sizeof(char*));

    for (int i = 0; i < rows; i = i + 1) {

        rail[i] = calloc(len, sizeof(char));

    }

    int r = 0, dir = 1;

    for (int i = 0; i < len; i = i + 1) {

        rail[r][i] = message[i];

        if (r == 0) dir = 1;

        else if (r == rows - 1) dir = -1;

        r += dir;

    }

    char* result = malloc(len + 1);

    int idx = 0;

    for (int i = 0; i < rows; i = i + 1) {

        for (int j = 0; j < len; j = j + 1) {

            if (rail[i][j] != '\0') {

                result[idx++] = rail[i][j];

            }

        }

        free(rail[i]);
        
    }

    free(rail);

    result[idx] = '\0';

    return result;

}

// print a string with line breaks
void print_with_line_breaks(const char* str, int line_length) {

    int len = strlen(str);

    for (int i = 0; i < len; i = i + 1) {

        putchar(str[i]);

        if ((i + 1) % line_length == 0) putchar('\n');

    }

    if (len % line_length != 0) putchar('\n');
}


int main(int argc, char* argv[]) {

    if (argc != 5) {

        fprintf(stderr, "Usage: %s <mode> <key_file> <text_file> <rail_depth>\n", argv[0]);
        return 1;

    }

    char* key_filename = argv[2];
    char* text_filename = argv[3];
    int rail_depth = atoi(argv[4]);

    int key_size;

    int** key = read_key_matrix(key_filename, &key_size);

    // print key matrix

    printf("Key matrix:\n");
    for ( int i = 0; i < key_size; i = i + 1 ) {
        for ( int j = 0; j < key_size; j = j + 1 ) {

            printf("%d", key[i][j]);

            if (j != key_size - 1) printf("\t");

        }

        printf("\n");

    }

    printf("\n");

    // read and clean input

    char* message = read_plaintext_file(text_filename);
    clean(message);

    // print the cleaned message before padding
    char* original_cleaned = strdup(message);

    if (!original_cleaned) {

        fprintf(stderr, "Memory allocation failed for original_cleaned\n");
        return 1;

    }

    // pad message for encryption
    pad(message, key_size);

    // print original cleaned (unpadded) message
    printf("Plaintext:\n");
    print_with_line_breaks(original_cleaned, 80);
    printf("\n");

    // encrypt using hill cipher

    int length = strlen(message);
    int* numbers = to_numbers(message);
    int* encrypted = malloc(length * sizeof(int));
    encrypt_hill(numbers, encrypted, length, key, key_size);

    // convert hill encrypted numbers to a string for convenience
    char* encrypted_str = malloc(length + 1);
    to_chars(encrypted, encrypted_str, length);

    // rail fence cipher
    char* ciphertext = rail_cipher_str(encrypted_str, rail_depth);
    printf("Ciphertext:\n");
    print_with_line_breaks(ciphertext, 80);
    printf("\n");
    printf("Depth: %d\n", rail_depth);

    // cleanup time
    free(ciphertext);
    free(encrypted_str);
    free(numbers);
    free(encrypted);
    free(message);
    free(original_cleaned);
    for ( int i = 0; i < key_size; i = i + 1 ) {

        free(key[i]);

    }

    free(key);

    return 0;
}