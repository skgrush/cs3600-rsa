# CS 3600 Project 3 - RSA 

#### Authors: Samuel K. Grush

My implementation for Project 3 for *CS 3600 Computer Security*. 

Python scripts/modules implementing the basics of the RSA cryptosystem, the
primality functions that support it, and the [euclidean.py][git-euclidean]
module.



## Installation

Only depends on Python standard libraries. Compatible with Python 3\*.

\* `int.from_bytes()` requires Python 3.2+. *If support is every added for
Python 2, `random.getrandbits()` requires Python 2.4+.*


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


[git-euclidean]: https://github.com/skgrush/cs3600-euclidean/
