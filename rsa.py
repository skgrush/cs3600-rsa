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


hrange = lambda x: range(1, x+1)


def exp(x, n): # x^n
    """Calculates x^n in (hopefully) log(n) time"""
    #simple cases
    if n == 0:
        return 1
    if n == 1:
        return x
    #even
    if not n % 2:
        return exp( x*x, n//2 )
    #odd
    else:
        return x * exp( x*x, (n-1)//2 )


def exp_m(x, n, m): # x^n % m
    """Calculates x^n(%m) in (hopefully) log(n) time"""
    #simple cases
    if n == 0:
        return 1
    if n == 1:
        return x%m
    
    #fast-exponentiation
    y = x if (n%2) else 1
    n = int(n/2)
    
    while n > 0:
        x = x**2 % m
        if n%2: #odd
            y = x if (y==1) else (y*x % m)
        n = int(n/2)
    
    return y


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


def millerRabinIterations(w):
    """Calculates the number of Miller-Rabin iterations to do for w.
    
    Algorithm is 22*log(0.0062*len(w)), but returns a minimum of 5.
    """
    if w == 0:
        return 5
    
    return max( 5,
                int( 22 * math.log(0.0062 * w.bit_length()) )
              )


def millerRabinPPT(w,iterations):
    """Implementation of Miller-Rabin Probabilistic Primality Test.
    
    Arguments:
        w (int): integer to be tested.
        iterations (int): number of iterations of the test.
    
    Returns:
        bool: True if PROBABLY prime, False if definitely not prime.
    
    Note:
        Based on algorithm defined in page 70, section C.3.1 of
        http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
    """
    w = int(w)
    
    if w % 2 == 0:  #even
        return False
    if w < 0:       #negative
        w = abs(w)
    if w in (1,3):  #special cases
        return True
    elif w in (0,):
        return False
    
    #1. Let a be the largest integer such that 2^a divides w-1
    a = int( math.log2(w-1) )
    while a > 0:
        if (w-1)%exp(2,a) == 0: # 2^a divides w-1
            break
        a -= 1
    
    #2. m = (w-1)/2^a
    m = (w-1)/exp(2,a)
    
    #3. wlen = len(w)
    wlen = w.bit_length()
    
    #4. For i=1 to iterations do
    for i in hrange(iterations):
        #4.1. Obtain a string b of wlen bits from an RBG
        #       Ensure that 1 < b < w-1
        #4.2. If ((b<=1)or(b>=w-1)) then go to step 4.1
        b = 0
        while b<=1 or b>=w-1: ##PROBLEM: loops forever if w<=3
            b = random.getrandbits(wlen)
        
        #4.3. z = b^m mod w
        z = exp_m(b, m, w)
        
        #4.4. If ((z=1)or(z=w-1)) then go to step 4.7
        if z==1 or z==w-1:
            continue
        
        #4.5. For j=1 to a-1 do
        for j in hrange(a-1):
            #4.5.1. z = z^2 mod w
            z = z**2 % w
            
            #4.5.2. If (z=w-1), then go to step 4.7
            #4.5.3. If (z=1), then go to step 4.6
            if z in (1,w-1):
                break
        
        if z == w-1:
            continue
        if z == 1:
            return False
    
    return True



def getPrimeRandom(k_bits):
    """Generates a prime random k_bits-length integer.
    """
    
    while True:
        k = random.getrandbits(k_bits)
        
        


## 
## RSA FUNCTIONS
## 

def keygen(k_bits):
    # p-length = [k/2, 3k/4]
    p_bits = int(k_bits/2) + random.randint( 0, int(k_bits/4) )
    q_bits = k_bits - p_bits
    
    p = getPrimeRandom(p_bits)
    q = getPrimeRandom(q_bits)
    
    


def encrypt(pubkey, message):
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
    
    N,e = pubkey
    
    if euclidean.extendedEuclidean( N, message )[0] != 1:
        raise MessageNotCoprimeError
    
    return exp_m( message, e, N ) # message^e % N


def decrypt(privkey, N, ciphertext, msg_length=None):
    """RSA decryption function.
    
    Arguments:
        privkey (int): the private key 'd'.
        N (int): the 'N' of the public key.
        ciphertext (int): the encrypted ciphertext.
        msg_length (int,optional): the expected length of the message.
    
    """
    message = exp_m( ciphertext, privkey, N ) #ciphertext^d % N
    
    return deintegerize( message, msg_length )


