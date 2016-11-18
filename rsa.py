#!/usr/bin/env python3
"""Python module and script implementing the basics of the RSA cryptosystem.

Run with no arguments for interactive mode.
"""

import random

import euclidean
import prime

DEFAULT_ENCODING = 'UTF-8'
DEFAULT_BYTEORDER = 'little'
DEFAULT_kbits = 1024

class RSAError(Exception):
    pass

class MessageNotCoprimeError(RSAError):
    pass

class MessageTooLarge(RSAError):
    pass

def integerize(value):
    """Converts a value's bytes to an integer.
    
    If the value is a string or bytes, it is converted to an integer based
    on its bytes in-memory.
    
    Arguments:
        value: may be a string, bytes, or integer.
    Returns:
        int: On success
        None: On failure
    """
    #convert strings to bytes
    if isinstance(value,str):
        if value.isdigit():
            return int(value)
        value = bytes(value, DEFAULT_ENCODING)
    
    #convert bytes to integers
    if isinstance(value, (bytes,bytearray)):
        value = int.from_bytes(value, byteorder=DEFAULT_BYTEORDER, signed=False)
    
    if isinstance(value,int):
        return int(value)
    
    return None


def deintegerize(value,length=None):
    """Converts an integer's bytes to a string.
    
    Arguments:
        value (int): Integer bytes to be converted to a string.
        length (int,optional): Length in bytes of the string.
    
    Returns:
        bytes: the string as bytes
    """
    if not isinstance(value,int):
        raise TypeError("'value' argument must be an int")
    
    return value
    
    if length is None or length <= 0:
        #byte length = round up (bit-length / 8)
        length = (value.bit_length()+7) // 8
    
    return value.to_bytes(length, byteorder=DEFAULT_BYTEORDER, signed=False)


## 
## RSA FUNCTIONS
## 

def generate_e(p, q):
    """Find a suitable public exponent 'e' based on *p* and *q*.
    
    *p* and *q* should be prime numbers.
    """
    totient_N = (p-1)*(q-1)
    
    for i in (65537, 257, 17, 5):
        if euclidean.extendedEuclidean( totient_N, i )[0] == 1:
            return i
    
    #try all the odds
    i=3
    while True:
        if euclidean.extendedEuclidean( totient_N, i )[0] == 1:
            return i
        i+=2


def generate_d(p, q, e):
    """Generate the private exponent 'd' based on *p*, *q*, and *e*.
    
    *p* and *q* should be prime numbers, and *e* should be relatively prime
    to (p-1)*(q-1).
    """
    totient_N = (p-1)*(q-1)
    
    # ModMultInv of b (under mod a) is x from (1 = e*x + N*y)
    d = euclidean.extendedEuclidean( e, totient_N )[1]
    
    return d


def keygen(k_bits):
    """Generate RSA public- and private-key pair for *k_bit*-length N. 
    
    Arguments:
        k_bits (int): Desired size of N.
    
    Returns:
        ( (N,e), (N,d) ), tuple of public- and private-key tuples.
    """
    # 1/2*k_bits <= p_bits < 3/4*k_bits
    p_bits = int(k_bits/2) + random.randint( 0, int(k_bits/4) )
    q_bits = k_bits - p_bits
    
    # generate p,q
    p = prime.getPrimeRandom(p_bits)
    q = prime.getPrimeRandom(q_bits)
    
    N = p*q
    e = generate_e(p, q)
    d = generate_d(p, q, e)
    
    return (N,e), (N,d)
    

def encrypt(N, e, message):
    """RSA encryption function.
    
    Arguments:
        N (int): the modulus.
        e (int): the public exponent.
        message (str or int): message to be encrypted.
    
    Returns:
        An integer, the ciphertext.
    
    Raises:
        TypeError: If 'message' isn't integerizable.
        MessageNotCoprimeError: If 'message' and N are not co-prime.
    """
    int_message = integerize( message )
    
    if int_message is None:
        raise TypeError("argument 'message' should be an int or string, " \
                        "not a {}.".format( type(message).__name__ ) )
    
    if int_message >= N:
        raise MessageTooLarge
    
    if euclidean.extendedEuclidean( N, int_message )[0] != 1:
        raise MessageNotCoprimeError
    
    return pow( int_message, e, N )


def decrypt(N, d, ciphertext, msg_length=None):
    """RSA decryption function.
    
    Arguments:
        N (int): the modulus.
        d (int): the private exponent.
        ciphertext (int): the encrypted ciphertext.
        msg_length (int,optional): the expected length of the message.
    
    """
    if ciphertext >= N:
        raise MessageTooLarge
    
    message = pow( ciphertext, d, N )
    
    return deintegerize( message, msg_length )


def interactiveInput():
    try:    _input = raw_input
    except: _input = input
    
    try:
        pqe_inpPath = _input("Enter the name of the file that contains p, q and e: ")
        p, q, e = map(int, euclidean.readFromFile(pqe_inpPath, 3) )
        
        d = generate_d(p, q, e)
        
        dN_outPath= _input("Enter the output file name to store d and N: ")
        with open(dN_outPath, mode='w') as dN_outFile:
            dN_outFile.write("{}\n{}".format(d,p*q))
        
        x_inpPath= _input("Enter the name of the file that contains x to be encrypted using (N,e): ")
        with open(x_inpPath) as x_inpFile:
            x = x_inpFile.read()
        
        Ex = encrypt( p*q, e, x )
        
        Ex_outPath= _input("Enter the output file name to store E(x): ")
        with open(Ex_outPath, mode='w') as Ex_outFile:
            Ex_outFile.write(str(Ex))
        
        c_inpPath= _input("Enter the name of the file that contains c to be decrypted using d: ")
        with open(c_inpPath) as c_inpFile:
            c = c_inpFile.read()
        
        c = int(c.rstrip())
        
        Dc = decrypt(p*q, d, c)
        
        Dc_outPath= _input("Enter the output file name to store D(c): ")
        with open(Dc_outPath, mode='bw') as Dc_outFile:
            Dc_outFile.write(str(Dc))
    
    except KeyboardInterrupt:
        print("\nEarly exit due to keyboard interrupt")
        exit(2)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) == 1:
        # interactive mode
        interactiveInput()
        exit(0)
    
    
    import argparse
    
    parser = argparse.ArgumentParser(description=__doc__)
    
    parser.add_argument('-o','--outfile', type=argparse.FileType('a'), 
            help="Where to output the data. Default: stdout")
    
    subparsers = parser.add_subparsers(dest='subparser')
    
    ## ENCRYPT
    parser_enc = subparsers.add_parser('encrypt',help="Encrypt a message.",
            description="You must provide the message, modulus N, and " \
            "exponent e by some means.")
    parser_enc.add_argument('-F','--pubfile', type=argparse.FileType('r'), 
            help="Get *N* and *e* from a newline-separated file.")
    parser_enc.add_argument('-N','--modulus', type=int, help="The modulus *N*.")
    parser_enc.add_argument('-e','--exponent',type=int, 
            help="The public exponent *e*.")
    parser_enc.add_argument('-m','--message', type=str, 
            help="The message to be encrypted.")
    parser_enc.add_argument('-f','--message-file', type=argparse.FileType('r'),
            help="Get the message from this file.")
    
    ## DECRYPT
    parser_dec = subparsers.add_parser('decrypt',help="Decrypt a message.",
            description="You must provide the ciphertext, modulus N, and " \
            "exponent d by some means.")
    parser_dec.add_argument('-F','--privfile', type=argparse.FileType('r'),
                          help="Get *N* and *d* from a newline-separated file.")
    parser_dec.add_argument('-N','--modulus', type=int, help="The modulus *N*.")
    parser_dec.add_argument('-d','--exponent',type=int, 
            help="The private exponent *d*.")
    parser_dec.add_argument('-c','--ciphertext', type=str, 
            help="The ciphertext to be decrypted.")
    parser_dec.add_argument('-f','--ciphertext-file',type=argparse.FileType('r'),
            help="Get the ciphertext from this file.")
    
    ## KEYGEN
    parser_gen = subparsers.add_parser('keygen',help="Generate keys.",
            description="By default N, e, and d are printed. If given, the " \
            "private key is written to -o/--outfile and the public key is " \
            "written to --pub-out.")
    parser_gen.add_argument('-p','--pair', type=int, nargs='?', metavar='bits',
                            help="Generate a public-/private-key pair. " \
                            "Optional argument is the desired size of N in " \
                            "bits. Defaults to %(const)s.", 
                            default=None, const=DEFAULT_kbits)
    parser_gen.add_argument('--pub-out', type=argparse.FileType('w'),
                            help="File to output the public key to. Default " \
                            "is stdout. Will overwrite the file!")
    
    ARGS = parser.parse_args()
    
    if ARGS.subparser == 'encrypt':
        
        message = ARGS.message
        if message is None:
            if ARGS.message_file is None:
                parser_enc.error("No message given. Use either -m/--message " \
                             "or -f/--message-file.")
            
            message = ARGS.message_file.read()
            ARGS.message_file.close()
        
        N,e = ARGS.modulus,ARGS.exponent
        if N is None or e is None:
            if ARGS.pubfile is None:
                parser_enc.error("Missing N or e. Use either -N/--modulus " \
                                 "and -e/--exponent, or -F/--pubfile.")
            
            _N,_e = map(int, euclidean.readFromFile(ARGS.pubfile,2))
            
            if N is None: N = _N
            if e is None: e = _e
        
        c = encrypt(N, e, message)
        
        if ARGS.outfile:
            ARGS.outfile.write(str(c))
        else:
            print(c)
    
    
    elif ARGS.subparser == 'decrypt':
        
        c = ARGS.ciphertext
        if c is None:
            if ARGS.ciphertext_file is None:
                parser_enc.error("No message given. Use either " \
                             "-c/--ciphertext or -f/--ciphertext-file.")
            
            c = ARGS.ciphertext_file.read()
            ARGS.ciphertext_file.close()
        
        c = int(c)
        
        N,d = ARGS.modulus,ARGS.exponent
        if N is None or d is None:
            if ARGS.privfile is None:
                parser_enc.error("Missing N or e. Use either -N/--modulus " \
                                 "and -d/--exponent, or -F/--privfile.")
            
            _N,_d = map(int, euclidean.readFromFile(ARGS.privfile,2))
            
            if N is None: N = _N
            if d is None: d = _d
        
        m = decrypt(N, d, c)
        
        if ARGS.outfile:
            ARGS.outfile.write( str(m,DEFAULT_ENCODING) )
        else:
            print(m)
    
    
    elif ARGS.subparser == 'keygen':
        
        if ARGS.pair is not None:
            
            pub,priv = keygen(ARGS.pair)
            
            if None in (ARGS.outfile, ARGS.pub_out):
                print("N = {}".format(pub[0]))
            
            if ARGS.pub_out is None:
                print("e = {}".format(pub[1]))
            else:
                ARGS.pub_out.write("{}\n{}".format(*pub))
            
            if ARGS.outfile is None:
                print("d = {}".format(priv[1]))
            else:
                ARGS.outfile.write("{}\n{}".format(*priv))
            
            exit(0)
        
        else:
            parser_gen.print_help()
    
    else:
        # unknown subparser
        parser.print_help()
        exit(2)
