#!/usr/bin/env python3
"""Python module and script implementing the basics of the RSA cryptosystem."""

import math
import random

import euclidean

DEFAULT_ENCODING = 'UTF-8'
DEFAULT_BYTEORDER = 'little'

class RSAError(Exception):
    pass

class MessageNotCoprimeError(RSAError):
    pass


isodd = lambda x: bool(x&1)
"""lambda: returns True if argument is odd, else False."""



def totient(n):
    """Euler's Totient Function using Euler's product formula"""
    result = n
    p = 2
    
    while p < math.sqrt(n):
        
        if n % p == 0:
            while n % p == 0:
                n = int(n/p)
            result *= (1 - 1.0/p)
        
        p+=1
    
    if n > 1:
        result *= 1.0 - 1.0/n
    
    return int(result)


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
    
    if length is None or length <= 0:
        #byte length = round up (bit-length / 8)
        length = (value.bit_length()+7) // 8
    
    return value.to_bytes(length, byteorder=DEFAULT_BYTEORDER, signed=False)


def _millerRabinIterations(w):
    """Calculates the number of Miller-Rabin iterations to do for w."""
    return max( 5,  int(22 * math.log(w.bit_length())) - 112 )


def millerRabinPPT(w,iterations=None):
    """Implementation of Miller-Rabin Probabilistic Primality Test.
    
    If *iterations* is not specified, it is determined by 
    _millerRabinIterations().
    
    Arguments:
        w (int): integer to be tested.
        iterations (int,optional): number of iterations of the test.
    
    Returns:
        bool: True if PROBABLY prime, False if definitely not prime.
    
    References:
        Based on algorithm defined by FIPS 186-4, Appendix C.3.1.
        http://dx.doi.org/10.6028/NIST.FIPS.186-4
    """
    w = int(w)
    
    ## SPECIAL CASES
    if w < 2:
        return False
    elif w == 3:
        return True
    elif not isodd(w):
        return False
    
    if iterations is None:
        iterations = _millerRabinIterations(w)
    
    
    #1. Let a be the largest integer such that 2^a divides w-1
    a = int( math.log2(w-1) )
    while a > 0:
        if ((w-1) % pow(2,a)) == 0: # 2^a divides w-1
            break
        a -= 1
    
    #2. m = (w-1)/2^a
    m = (w-1)//pow(2,a)
    
    #3. wlen = len(w)
    wlen = w.bit_length()
    
    #4. For i=1 to iterations do
    for i in range(iterations):
        #4.1. Obtain a string b of wlen bits from an RBG
        #       Ensure that 1 < b < w-1
        #4.2. If ((b<=1)or(b>=w-1)) then go to step 4.1
        b = 0
        while not (1 < b and b < w-1): ##PROBLEM: loops forever if w<=3
            b = random.getrandbits(wlen)
        
        #4.3. z = b^m mod w
        z = pow(b, m, w)
        
        #4.4. If ((z=1)or(z=w-1)) then go to step 4.7 [Continue]
        if z==1 or z==w-1:
            continue
        
        #4.5. For j=1 to a-1 do
        continueOuter = False
        for j in range(a):
            #4.5.1. z = z^2 mod w
            z = z**2 % w
            
            #4.5.2. If (z=w-1), then go to step 4.7 [Continue loop #4]
            if z == w-1:
                continueOuter = True
                break
            #4.5.3. If (z=1), then go to step 4.6 [Return False]
            if z == 1:
                return False
        if continueOuter:
            continue
        
        return False
    
    return True



def getPrimeRandom(k_bits):
    """Generates a prime random k_bits-length integer.
    """
    if k_bits <= 1:
        raise ValueError("number of bits must be greater than 1")
    
    while True:
        k = random.getrandbits(k_bits)
        if millerRabinPPT(k):
            return k


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
    d = euclidean.extendedEuclidean( e, N )[1]
    
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
    p = getPrimeRandom(p_bits)
    q = getPrimeRandom(q_bits)
    
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
    
    if euclidean.extendedEuclidean( N, int_message )[0] != 1:
        raise MessageNotCoprimeError
    
    return pow( message, e, N )


def decrypt(N, d, ciphertext, msg_length=None):
    """RSA decryption function.
    
    Arguments:
        N (int): the modulus.
        d (int): the private exponent.
        ciphertext (int): the encrypted ciphertext.
        msg_length (int,optional): the expected length of the message.
    
    """
    message = pow( ciphertext, d, N )
    
    return deintegerize( message, msg_length )


def interactiveInput():
    try:    _input = raw_input
    except: _input = input
    
    try:
        pqe_inpPath = _input("Enter the name of the file that contains p, q and e:")
        p, q, e = map(int, euclidean.readFromFile(pqe_inpPath, 3) )
        
        d = generate_d(p, q, e)
        
        dN_outPath= _input("Enter the output file name to store d and N:")
        with open(dN_outPath, mode='w') as dN_outFile:
            for val in (d, '\n', N):
                dN_outFile.write(val)
        
        x_inpPath= _input("Enter the name of the file that contains x to be encrypted using (N,e):")
        x = euclidean.readFromFile(x_inpPath, 1)
        
        Ex = encrypt( p*q, e, x )
        
        Ex_outPath= _input("Enter the output file name to store E(x):")
        with open(Ex_outPath, mode='w') as Ex_outFile:
            Ex_outFile.write(Ex)
        
        c_inpPath= _input("Enter the name of the file that contains c to be decrypted using d:")
        c = euclidean.readFromFile(c_inpPath, 1)
        
        Dc = decrypt(p*q, d, c)
        
        Dc_outPath= _input("Enter the output file name to store D(c):")
        with open(Dc_outPath, mode='w') as Dc_outFile:
            Dc_outFile.write(Dc)
    
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
                            "bits. Defaults to 2048.", default=2048)
    parser_gen.add_argument('--pub-out', type=argparse.FileType('w'),
                            help="File to output the public key to. Default " \
                            "is stdout. Will overwrite the file!")
    
    ARGS = parser.parse_args()
    
    print(ARGS)
    
    if ARGS.subparser == 'encrypt':
        
        message = ARGS.message
        if message is None:
            if ARGS.message_file is None:
                parser_enc.error("No message given. Use either -m/--message " \
                             "or -f/--message-file.")
            
            message = ARGS.message_file.read()
            ARGS.message_file.close()
        
        N,e = ARGS.N,ARGS.e
        if N is None or e is None:
            if ARGS.pubfile is None:
                parser_enc.error("Missing N or e. Use either -N/--modulus " \
                                 "and -e/--exponent, or -F/--pubfile.")
            
            _N,_e = map(int, euclidean.readFromFile(ARGS.pubfile,2))
            
            if N is None: N = _N
            if e is None: e = _e
        
        c = encrypt(N, e, message)
        
        if ARGS.outfile:
            ARGS.outfile.write(c)
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
        
        N,d = ARGS.N,ARGS.d
        if N is None or d is None:
            if ARGS.privfile is None:
                parser_enc.error("Missing N or e. Use either -N/--modulus " \
                                 "and -d/--exponent, or -F/--privfile.")
            
            _N,_d = map(int, euclidean.readFromFile(ARGS.pubfile,2))
            
            if N is None: N = _N
            if d is None: d = _d
        
        m = decrypt(N, d, c)
        
        if ARGS.outfile:
            ARGS.outfile.write(m)
        else:
            print(m)
    
    
    elif ARGS.subparser == 'keygen':
        
        if ARGS.pair is not None:
            
            pub,priv = keygen(ARGS.pair)
            
            if None in (ARGS.outfile, ARGS.pub_out):
                print("N = {}".format(N)
            
            if ARGS.pub_out is None:
                print("e = {}".format(e)
            else:
                for val in (N,'\n',e):
                    ARGS.pub_out.write(val)
            
            if ARGS.outfile is None:
                print("d = {}".format(d)
            else:
                for val in (N,'\n',d):
                    ARGS.outfile.write(val)
            
            exit(0)
        
        else:
            parser_gen.print_help()
    
    else:
        # unknown subparser
        parser.print_help()
        exit(2)
