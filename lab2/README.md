# Assignment_2

In this assignment you are going to develop a symmetric encryption tool in C, using the OpenSSL toolkit https://www.openssl.org/. The purpose of this assignment is to provide you the opportunity to get familiar with the very popular general-purpose cryptography toolkit and acquire hands-on experience in implementing simple cryptographic applications. The tool will provide encryption, decryption, CMAC signing and CMAC verification functionality.

## Compilation

To compile the code, use the following command:

```bash
make
```

## GCC version
To get the version of the gcc compiler, run:
```bash
# Command 
    gcc --version

# Result
    gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
```

## Usage
```bash
./assign_2 -h
./assign_2: option requires an argument -- 'h'

Usage:
    assign_2 -i in_file -o out_file -p passwd -b bits [-d | -e | -s | -v]
    assign_2 -h

Options:
 -i    path    Path to input file
 -o    path    Path to output file
 -p    psswd   Password for key generation
 -b    bits    Bit mode (128 or 256 only)
 -d            Decrypt input and store results to output
 -e            Encrypt input and store results to output
 -s            Encrypt+sign input and store results to output
 -v            Decrypt+verify input and store results to output
 -h            This help message
```

<p>&nbsp;</p>

## Functions

<p>&nbsp;</p>

## License
<p style="color:red;">Apostolos Gioumertakis</p>