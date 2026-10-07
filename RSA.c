#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
Assignment:
Optional Homework - RSA Encryption/Decryption Algorithm Implementation
Author: Phillip Nguyen
Language: C
To Compile:
gcc -O2 -std=c99 -o RSA RSA.c -lm
g++ -O2 -std=c++17 -o RSA RSA.cpp -lm
rustc -O RSA.rs -o RSA
To Execute (on Eustis):
./RSA <keypair_file> <input_file>
where:
<keypair_file> is the path to the file containing P, Q, and E values
<input_file> is the path to the plaintext message file
Notes:
- This is an OPTIONAL homework assignment
- Implements RSA encryption and decryption in a single run
- Validates prime numbers P and Q
- Validates that E is relatively prime to phi(N)
- Calculates private key D using Extended Euclidean Algorithm
- Processes only alphanumeric characters
- Encrypts the plaintext and then decrypts it to verify
- Tested on Eustis
Class: CIS3360 - Security in Computing - Fall 2025
Instructor: Dr. Jie Lin
Due Date: Friday, November 07, 2025 at 11:59 PM ET
*/

// returns if a number is prime or not
// 1 = prime, 0 = not prime
    
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verifyPrime(long long number) {
    
    if (number <= 1) {

	return 0;

	}
    
    if (number == 2) {

	return 1;

	}
    
    if (number % 2 == 0) {

	return 0;

	}
    
    for ( long long i = 3; i * i <= number; i += 2 ) {
        
        if (number % i == 0) {

		return 0;

	}
        
    }
    
    return 1;
    
}

long long RSA_modulus(long long first, long long second) {
    
    return first * second;
    
}

long long totient_function(long long first, long long second) {
    
    return (first - 1) * (second - 1);
    
}

long long GCD_function(long long a, long long b) {
    
    while ( b != 0 ) {
        
        long long temp = b;
        b = a % b;
        a = temp;
        
    }
    
    return a;
}

long long extended_GCD_function(long long a, long long b, long long *x, long long *y) {

    if ( a == 0 ) {
        
        *x = 0;
        
        *y = 1;
        
        return b;
        
    }

    long long x1, y1;
    
    long long gcd = extended_GCD_function(b % a, a, &x1, &y1);
    
    *x = y1 - (b / a) * x1;
    
    *y = x1;
    
    return gcd;
    
}

long long mod_inverse_function(long long e, long long totient_n) {
    
    long long x, y;
    
    long long g = extended_GCD_function(e, totient_n, &x, &y);
    
    // inverse doesn't exist
    
    if ( g != 1 ) {
        
        return -1;
        
    }
    
    // normalize the result
    
    return (x % totient_n + totient_n) % totient_n;
}

long long modular_exponentiation(long long base, long long exp, long long mod) {
    
    long long result = 1;
    
    base %= mod;
    
    while (exp > 0) {
        
        if ( exp % 2 == 1 )
        
            result = (result * base) % mod;
            
        exp /= 2;
        
        base = (base * base) % mod;
        
    }
    
    return result;
    
}

long long* read_keypair(const char *filename) {
    
    FILE *file = fopen(filename, "r");
    
    if (!file) {
        
        fprintf(stderr, "Error opening keypair file.\n");
        
        exit(1);
        
    }

    long long *keypair = malloc(3 * sizeof(long long));
    
    char label[10];
    
    for (int i = 0; i < 3; i = i + 1 ) {
        
        fscanf(file, "%[^:]: %lld\n", label, &keypair[i]);
        
    }
    
    fclose(file);
    
    return keypair;
    
}

char* read_plaintext_file(const char *filename, int *length) {
    
    FILE *file = fopen(filename, "r");
    
    if (!file) {
        fprintf(stderr, "Error opening plaintext file.\n");
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *raw_buffer = malloc(file_size + 1);
    
    fread(raw_buffer, 1, file_size, file);
    raw_buffer[file_size] = '\0';
    fclose(file);

    char *buffer = malloc(file_size + 1);
    
    int j = 0;
    
    // remove whitespace
    
    for ( long i = 0; i < file_size; i = i + 1 ) {
        
        if ( !isspace((unsigned char)raw_buffer[i]) ) {
            
            buffer[j++] = raw_buffer[i];
            
        }
        
    }
    
    buffer[j] = '\0'; // null terminate
    
    *length = j;

    free(raw_buffer);
    
    return buffer;
    
}

long long* encryption(const char *plaintext, int length, long long E, long long N) {
    
    long long *ciphertext = malloc(length * sizeof(long long));
    
    for ( int i = 0; i < length; i = i + 1 ) {
        
        ciphertext[i] = modular_exponentiation((long long)plaintext[i], E, N);
        
    }
    
    return ciphertext;
    
}

char* decryption(const long long *ciphertext, int length, long long D, long long N) {
    
    char *plaintext = malloc(length + 1);
    
    for ( int i = 0; i < length; i = i + 1 ) {
        
        plaintext[i] = (char)modular_exponentiation(ciphertext[i], D, N);
        
    }
    
    plaintext[length] = '\0';
    
    return plaintext;
    
}

int main(int argc, char **argv) {
    
    if ( argc != 3 ) {
        
        fprintf(stderr, "usage: %s <keypair file> <plaintext file>\n", argv[0]);
        
        return 1;
        
    }

    // read keypair
    long long *keypair = read_keypair(argv[1]);
    long long P = keypair[0], Q = keypair[1], E = keypair[2];

    // check primes
    if ( verifyPrime(P) != 1 ) { 
        
        printf("P:\nError: %lld is not a prime number\n", P); 
        exit(1);}
        
    else printf("P:\n%lld is a prime number\n\n", P);

    if ( verifyPrime(Q ) != 1) { 
        
        printf("Q:\nError: %lld is not a prime number\n", Q); 
        exit(1);
        
    }
    
    else printf("Q:\n%lld is a prime number\n\n", Q);

    // calculate modulus and totient
    
    long long N = RSA_modulus(P, Q);
    
    long long totient = totient_function(P, Q);
    
    printf("N:\n%lld\n\n", N);
    
    printf("Totient of N:\n%lld\n\n", totient);

    // validate E
    
    if (GCD_function(E, totient) != 1) {
        
        printf("E:\nError: %lld is not relatively prime to  φ(N) = %lld\n", E, totient);
        exit(1);
        
    }
    printf("E:\n%lld is relatively prime to %lld\n\n", E, totient);

    // calculate D
    
    long long D = mod_inverse_function(E, totient);
    printf("D:\n%lld\n\n", D);

    // print key pairs
    
    printf("Public key pair:\n(%lld, %lld)\n\n", E, N);
    printf("Private key pair:\n(%lld, %lld)\n\n", D, N);

    // read plaintext
    
    int plaintext_len;
    
    char *plaintext = read_plaintext_file(argv[2], &plaintext_len);
    printf("Plaintext:\n%s\n\n", plaintext);

    // encrypt
    
    long long *ciphertext = encryption(plaintext, plaintext_len, E, N);
    
    printf("Encrypted message:\n");
    
    for ( int i = 0; i < plaintext_len; i = i + 1 ) {
        
        printf("%lld", ciphertext[i]);
        
        if (i < plaintext_len - 1) {
            
            printf(" ");
            
        }
        
    }
    printf("\n\n");

    // Decrypt
    char *decrypted = decryption(ciphertext, plaintext_len, D, N);
    
    printf("Decrypted message:\n");
    
    for ( int i = 0; i < plaintext_len; i = i + 1 ) {
        
        printf("%c", decrypted[i]);
        
        if ( i < plaintext_len - 1 ) { 
            
            printf(" ");
            
        }
        
    }
    
    printf("\n");

    free(keypair);
    free(plaintext);
    free(ciphertext);
    free(decrypted);
    return 0;
    
}