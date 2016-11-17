# CS 3600 Project 3 - RSA 

#### Authors: Samuel K. Grush

My implementation for Project 3 for *CS 3600 Computer Security*. 

*__intro_text__*


## Installation

Only depends on Python standard libraries.
Compatible with Python 2 and 3.


## Usage

```ShellSession
./rsa.py [-h] [-o OUTFILE] {encrypt,decrypt,keygen} ...
```

To use the script in **interactive mode** as defined by the project spec,
don't use any subcommands, e.g. `./rsa.py` or `./rsa.py -o out.txt`.

For encryption, use `./rsa.py encrypt` and pass the message *m*, modulus *N*,
and public exponent *e* through some combination of arguments.

For decryption, use `./rsa.py decrypt` and pass the ciphertext *c*, modulus *N*,
and private exponent *d* through some combination of arguments.

For key generation, use `./rsa.py keygen -p [bits]` where *bits* is the
optional size of *N* (defaults to 1024).

