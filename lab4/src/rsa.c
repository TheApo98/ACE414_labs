#include "rsa.h"
#include "utils.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *primes = (size_t*)malloc(sizeof(int)*limit);

	/* TODO */	
	int p_index = 0; 

	// Array with size limit+1...
	// the stored value dictates if index is prime (0=false, 1=true) 
	int *prime = (int*)malloc(sizeof(int)*(limit+1));
    // memset(prime, 1, sizeof(prime));
    for (size_t i = 0; i < limit+1; i++)
    {
        *(prime+i) = 1;
    }
 
	// Check every number from 2 up to limit
    for (int p = 2; p  <= limit; p++)
    {
		// if the value in prime[] is true, the it's a prime
        if (prime[p] == 1)
        {
			// store the prime in the returned array...
            primes[p_index] = p;
			// ...and increase the size of that array
			p_index++;
			// Mark the position for all composite numbers 
            for (int i = p * p; i <= limit; i += p)
                prime[i] = 0;
        }
    }

	// Free temp array
	free(prime);

	// Set the prime array size
	*primes_sz = p_index;
	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	while(a!=b)
    {
        if(a > b)
            a -= b;
        else
            b -= a;
    }
    return a;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
	size_t e;

	/* TODO */

	return e;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{

	/* TODO */

}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;

	/* TODO */

}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */

}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */

}
