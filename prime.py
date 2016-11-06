#!/usr/bin/env python3

import math
import random

isodd = lambda x: bool(x&1)
"""lambda: returns True if argument is odd, else False."""



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
            z = pow(z,2,w)
            
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
