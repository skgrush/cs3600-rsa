#!/usr/bin/env python3

import math

def exp(x, n):
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


def exp_m(x, n, m):
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


def keygen(k_bits):
    #bits_of_p = int(k_bits/2)
    #bits_of_q = k_bits - bits_of_p
    pass


def encrypt(pubkey, message):
    """RSA encryption function.
    
    Arguments:
        pubkey: tuple (N,e) for encryption.
        message: String or integer to be encrypted.
    
    Returns:
        An integer, the ciphertext.
    """
    pass
    
