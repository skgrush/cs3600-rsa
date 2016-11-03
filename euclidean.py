#!/usr/bin/env python3
"""Find two numbers' GCD and its linear combination.
usage: euclidean.py [a b | INPUT OUTPUT]

 Pass no arguments for interactive mode.
 Pass two integer arguments 'a' and 'b' to see their GCD and linear combination.
 pass two path arguments 'INPUT' and 'OUTPUT' to read 'a' and 'b' from a file.
"""

import sys

def euclideanGCD( a, b ):
    """Calculates the Greatest Common Denominator of two integers using
    the Euclidean algorithm.
    
    Arguments should be integers.
    Returns GCD(a,b)
    
    Note:
        This function will likely hit the recursion limit for big numbers.
    """
    return abs(a) if ( b == 0 ) else euclideanGCD( b, a%b )


def extendedEuclidean( a, b ):
    """Calculate the GCD and linear combination of two integers using
    the Extended Euclidean algorithm.
    
    Arguments should be integers.
    Returns (r,s,t) such that (r = a*s + b*t)
    -
    Based on pseudocode from
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """
    
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = int(b), int(a)
    
    while r:
        quotient = old_r // r #integer division
        old_r, r = r, (old_r - quotient*r)
        old_s, s = s, (old_s - quotient*s)
        old_t, t = t, (old_t - quotient*t)
    
    return (old_r, old_s, old_t)


def readFromFile(inputfile):
    """Read two lines from path *inputfile* and return them.
    
    Exits on failure.
    """
    a,b = None,None
    
    try:
        with open(inputfile, 'r') as ifl:
            a = ifl.readline().strip()
            b = ifl.readline().strip()
        
    except Exception as err:
        print(type(err).__name__, err)
        exit(-1)
    
    if not a or not b:
        print("\nERROR: Not enough arguments in", repr(inputfile))
        exit(1)
    
    return a,b



if __name__ == "__main__":
    
    if '-h' in sys.argv or '--help' in sys.argv:
        print(__doc__)
        exit(0)
    
    
    inputfile, outputfile = '',''
    a, b = 0, 0
    
    
    if len(sys.argv) == 3 and sys.argv[1].isdigit() and sys.argv[2].isdigit():
        a, b = sys.argv[1:3]
    
    else:
        if len(sys.argv) == 3:
            inputfile, outputfile = sys.argv[1:3]
        
        else:
            inputfile = input("Enter the name of the input file that " \
                              "contains a and b: ")
            outputfile= input("Enter the name of the output file to store " \
                              "the GCD of a and b, and the linear " \
                              "combination of GCD(a,b): ")
        
        a, b = readFromFile(inputfile)
    
    
    try:
        a, b = int(a), int(b)
    
    except ValueError:
        print("\nERROR: Arguments should be integers.")
        exit(1)
    
    
    gcdAndCoeffs = extendedEuclidean(a, b)
    
    
    if outputfile:
        
        # Write the results to a file
        with open(outputfile, 'w') as ofl:
            
            for i in gcdAndCoeffs:
                ofl.write( str(abs(i)) )
                ofl.write( '\n' )
        
        print("Output written to",repr(outputfile))
    
    else:
        # Output the results
        print("The linear combination of GCD(a,b) is: " \
              "{2[0]} = {0}*{2[1]} + {1}*{2[2]}".format( a, b, gcdAndCoeffs )
             )
