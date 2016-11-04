#!/usr/bin/env python3

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

def keygen(k_bits):
    """Generate RSA public- and private-key pair.
    
    Arguments:
        k_bits (int): Desired size of N.
    
    Returns:
        ( (N,e), (N,d) ), tuple of public- and private-key tuples.
    """
    # k_bits/2 <= p_bits < 3k_bits/4
    p_bits = int(k_bits/2) + random.randint( 0, int(k_bits/4) )
    q_bits = k_bits - p_bits
    
    # generate p,q
    p = getPrimeRandom(p_bits)
    q = getPrimeRandom(q_bits)
    
    # generate N
    N = p*q
    totient_N = (p-1)*(q-1)
    
    # generate e
    e = None
    for i in (65537, 257, 17, 5):
        if euclidean.extendedEuclidean( totient_N, i ):
            e = i
            break
    if e is None:
        i=3
        while True:
            if euclidean.extendedEuclidean( totient_N, i):
                e = i
                break
            i+=2
    
    # generate d
    # ModMultInv of b under a  ==  x from (1 = e*x + N*y)
    d = euclidean.extendedEuclidean( e, N )[1]
    
    return (N,e), (N,d)
    

def encrypt(N, e, message):
    """RSA encryption function.
    
    Arguments:
        pubkey (tuple): public key (N,e) for encryption.
        message (str or int): message to be encrypted.
    
    Returns:
        An integer, the ciphertext.
    
    Raises:
        TypeError: If 'message' isn't integerizable.
        MessageNotCoprimeError: If 'message' and N are not co-prime.
    """
    message = integerize( message )
    
    if message is None:
        raise TypeError("argument 'message' should be an int or string, " \
                        "not a {}.".format( type(message).__name__ ) )
    
    if euclidean.extendedEuclidean( N, message )[0] != 1:
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


