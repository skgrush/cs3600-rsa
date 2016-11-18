# CS 3600 Project 3 - RSA 

#### Authors: Samuel K. Grush

My implementation for Project 3 for *CS 3600 Computer Security*. 

Python scripts/modules implementing the basics of the RSA cryptosystem, the
primality functions that support it, and the [euclidean.py](euclidean.py) module
from my project 2 implementation [cs3600-euclidean][git-euclidean].



## Installation

Only depends on Python standard libraries. Compatible with Python 3.2+ (see
[Python Version Limitations](#python-version-limitations) below).


## Usage
```ShellSession
./rsa.py [-h] [-o OUTFILE] {encrypt,decrypt,keygen} ...
```

### Interactive Mode
```ShellSession
./rsa.py [-h]
```
To use the script in interactive mode as outlined in *§2 Expected Outcomes*
of the project specifications, run the program without subcommands.

### Encryption
```ShellSession
./rsa.py [-h] [-o OUTFILE] encrypt (-F PUBFILE|(-N MODULUS -e EXPONENT))
                                   (-f MSGFILE|-m MESSAGE)
```
For encryption, use the `encrypt` subcommand and pass the message *m*, 
modulus *N*, and public exponent *e* through some combination of parameters.
Run `./rsa.py encrypt -h` for more information.

### Decryption
```ShellSession
./rsa.py [-h] [-o OUTFILE] decrypt (-F PRIVFILE|(-N MODULUS -d EXPONENT))
                                   (-f CIPHFILE|-c CIPHERTEXT)
```
For decryption, use the `decrypt` subcommand and pass the ciphertext *c*,
modulus *N*, and private exponent *d* through some combination of parameters.
Run `./rsa.py decrypt -h` for more information.

### Key Generation
```ShellSession
./rsa.py [-h] [-o PRIVFILE] keygen -p [bits] [--pub-out PUBFILE]
```
For key generation, use the `keygen` command and `-p/--pair` to generate a 
public-/private-key pair, with an optional integer argument for the bit length
of the modulus (defaults to 1024).

If no other parameters are passed then *N*, *e*, and *d* are printed to the
screen. The public and private keys may be written to files using `-o/--outfile`
for the private key and `--pub-out` for the public key.


## Python Version Limitations

* [int.from_bytes][python-intfrombytes] and 
[int.to_bytes][python-inttobytes] require Python 3.2 or later. Used by
`integerize()` and `deintegerize()` in [rsa.py](rsa.py).

* [random.getrandbits][python-randomgetrandbits] requires Python 2.4 or later.
Used by `getPrimeRandom()` in [prime.py](prime.py).



[python-intfrombytes]: https://docs.python.org/3/library/stdtypes.html?#int.from_bytes
[python-inttobytes]: https://docs.python.org/3/library/stdtypes.html?#int.to_bytes
[python-randomgetrandbits]: https://docs.python.org/2/library/random.html?#random.getrandbits
[git-euclidean]: https://github.com/skgrush/cs3600-euclidean/
