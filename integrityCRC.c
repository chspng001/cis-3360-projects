/*
Assignment:
integrityCRC - CRC Algorithm Implementation
Author: Phillip Nguyen
Language: C
To Compile:
gcc -O2 -std=c11 -o integrityCRC integrityCRC.c
g++ -O2 -std=c++17 -o integrityCRC integrityCRC.cpp
rustc -O integrityCRC.rs -o integrityCRC
To Execute (on Eustis):
./integrityCRC <message_file> <crc_algorithm>
where:
<message_file> is the path to the input text file
<crc_algorithm> is 3, 4, or 8 (for CRC-3, CRC-4, or CRC-8)
Notes:
- Implements CRC-3, CRC-4, and CRC-8 algorithms
- Processes plain text messages and computes CRC values
- Outputs all intermediate steps and final CRC values
- Tested on Eustis.
Class: CIS3360 - Security in Computing - Fall 2025
Instructor: Dr. Jie Lin
Due Date: Friday, October 10, 2025 at 11:59 PM ET
*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>

// get the entirety of a file and place it into a string

char* file_to_string(const char* filepath) {
    
    FILE *txt = fopen(filepath, "r");
    
    if ( txt == NULL ) {
        
        printf("file doesn't exist\n");
        
        return NULL;
        
    }

    // determine filesize and allocate memory in a buffer
    
    fseek(txt, 0, SEEK_END);
    long txt_filesize = ftell(txt) + 1;
    fseek(txt, 0, SEEK_SET);

    if ( txt_filesize < 0 ) {
        
        fclose(txt);
        
        return NULL;
        
    }

    char *txt_string = malloc(txt_filesize);
    
    if ( txt_string == NULL ) {
        
        fclose(txt);
        
        return NULL;
        
    }

    fgets(txt_string, txt_filesize, txt);

    fclose(txt);
    
    return txt_string;
    
}

// clean a string by removing all non-alphanumeric characters
// retains capital letters

void clean(char *string) {
    
    char *source = string;
    char *dest = string;

    while ( *source != '\0' ) {
        
        if ( isalnum((unsigned char)*source) ) {
            
            *dest++ = *source;
            
        }
        
        source++;
        
    }

    *dest = '\0';
    
}

// takes a character's ascii value, converts to binary and prints it out

void print_ascii_to_binary(unsigned char ch) {
    
    for ( int i = 7; i >= 0; i = i - 1 ) {
        
        printf("%d", ( ch >> i ) & 1);
        
    }
    
    printf(" ");
    
}

// takes a number and prints it out as binary 

void print_binary(uint32_t value, int width) {
    
    for ( int i = width - 1; i >= 0; i = i - 1 ) {
        
        printf("%d", (value >> i) & 1);
        
    }
    
}

// turns a string of ascii characters into the ascii characters' representation in other bases
// 0 = decimal
// 1 = hex
// 2 = binary

void string_to_ascii(char *string, int mode) {
    
    int length = strlen(string);
    
    if ( mode == 0 ) {
    
        for ( int i = 0; i < length; i = i + 1 ) {
        
            if ( i != length - 1 ) {
        
                printf("%d ", string[i]);
        
            }
        
            else {
            
            printf("%d", string[i]);  
            
            }
            
        }
        
    }
    
    if ( mode == 1 ) {
        
        for ( int i = 0; i < length; i = i + 1 ) {
        
            if ( i != length - 1 ) {
        
                printf("%X ", string[i]);
        
            }
        
            else {
            
            printf("%X", string[i]);  
            
            }
            
        }
        
    }
    
    if ( mode == 2 ) {
        
        for ( int i = 0; i < length; i = i + 1 ) {
        
                print_ascii_to_binary(string[i]); 
            
        }
        
    }
    
}

// used for the final hex string print, crc value is appended post-processing below in main

void string_to_ascii_final(char *string) {
    
    int length = strlen(string);
    
    for ( int i = 0; i < length; i = i + 1 ) {
            
        printf("%X", string[i]);
            
    }
        
}

// converts a predefined polynomial char string of 1s and 0s to an integer

uint32_t poly_str_to_int(const char *poly_string) {
    
    uint32_t polynomial = 0;
    
    while (*poly_string) {
        
        polynomial <<= 1;
        
        if (*poly_string == '1') {
            
            polynomial |= 1;
            
        }
        
        poly_string++;
        
    }
    
    return polynomial;
    
}

// computes a crc code for a phrase given the phrase, its length, crc width and crc polynomial as an integer

uint32_t crc_compute(const unsigned char *data, int len, int crc_width, uint32_t polynomial) {
    
    int polynomial_degree = crc_width;
    
    uint32_t crc = 0;
    
    uint32_t topbit = 1 << polynomial_degree; // identify the MSB 
    
    uint32_t mask = (1 << (polynomial_degree + 1)) - 1; // mask is used to ensure that the width of the division doesn't overflow

    for ( int i = 0; i < len; i++) {
        
        unsigned char byte = data[i];
        
        for ( int bit = 7; bit >= 0; bit = bit - 1 ) { 
            
            int bit_val = ( byte >> bit ) & 1;
            
            crc = ( (crc << 1) | bit_val ) & mask;
            
            if ( crc & topbit ) {
                
                crc ^= polynomial;
                
            }
            
        }
        
    }

    // append zeros equal to the degree of the polynomial

    for ( int i = 0; i < polynomial_degree; i = i + 1) {

        crc = ( crc << 1 ) & mask;

        if ( crc & topbit ) {

            crc ^= polynomial;
        }

    }

    // drop highest degree bit
    
    return crc & ( (1 << crc_width) - 1 );

}

int main(int argc, char *argv[])
{

    // sanity checks

    char *phrase = file_to_string(argv[1]);
    
    char *filename = argv[1];

    int crc_mode = atoi(argv[2]);

    if (argc < 2) {

        fprintf(stderr, "Usage: %s <file path>\n", argv[0]);

        return 1;

    }

    if (!phrase) {

        fprintf(stderr, "Could not read file: %s\n", argv[1]);

        return 1;

    }
    
    char polynomial[100];
    
    if (crc_mode == 3) {
            
        strcpy(polynomial, "1101");
        
    } else if (crc_mode == 4) {
        
        strcpy(polynomial, "10110");
        
    } else if (crc_mode == 8) {
        
        strcpy(polynomial, "100110101");
        
    }

    printf("The original message:\n%s", phrase);
    
    // start doing stuff
    
    clean(phrase);

    int phrase_len = strlen(phrase);

    uint32_t polynomial_int = poly_str_to_int(polynomial);

    uint32_t crc = crc_compute((unsigned char*)phrase, phrase_len, crc_mode, polynomial_int);
    
    printf("\nThe preprocessed message (invisible characters removed):\n%s", phrase);
    
    printf("\n\nThe decimal representation of the preprocessed message:\n");
    
    string_to_ascii(phrase, 0);
    
    printf("\n\nThe hex representation of the preprocessed message:\n");

    string_to_ascii(phrase, 1);
    
    printf("\n\nThe binary representation of the preprocessed message:\n");
    
    string_to_ascii(phrase, 2);
    
    printf("\n\nThe binary representation of the original message prepared for CRC computation (padded with %d zeros):\n", crc_mode);
    
    string_to_ascii(phrase, 2);
    
    for ( int i = 0; i < crc_mode; i = i + 1 ) {
        
        printf("0");        
        
    }
    
    printf("\n\nThe crc value for the chosen crc algorithm in binary:\n");
    
    print_binary(crc, crc_mode);
    
    printf("\n\nThe crc value for the chosen crc algorithm in hex:\n%X", crc);
    
    printf("\n\nThe final message is going to be transmitted in hex:\n");
    
    string_to_ascii_final(phrase);
    
    printf("%X", crc);
    
    return 0;
    
}