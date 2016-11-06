#!/usr/bin/env python3

import math
import random

isodd = lambda x: bool(x&1)
"""lambda: returns True if argument is odd, else False."""



def _millerRabinIterations(w):
    """Calculates the number of Miller-Rabin iterations to do for w."""
    #return max( 5,  int(22 * math.log(w.bit_length())) - 112 )
    return 10


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
    
    
    # Let a be the largest integer such that 2^a divides w-1
    a = int( math.log2(w-1) )
    while a > 0:
        if ((w-1) % (2<<a-1)) == 0: # 2^a divides w-1
            break
        a -= 1
    
    m = (w-1)//(2<<a-1)
    
    for _ in range(iterations):
        b = random.randrange(2,w-1)
        
        z = pow(b, m, w)
        
        if not (z==1 or z==w-1):
            
            continueOuter = False
            for _ in range(a):
                z = pow(z,2,w)
                
                if z == w-1:
                    continueOuter = True
                    break
                
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
