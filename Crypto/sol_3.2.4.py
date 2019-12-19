import sys
from pbp import decrypt
from Crypto.PublicKey import RSA
import math
import numpy as np
from fractions import gcd

def ex_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = ex_gcd(b%a, a)
        return g, y - (b // a)*x, x

def get_private(e, p, q):
    g, d, t = ex_gcd(e, (p-1)*(q-1))
    if g == 1:
        return d % ((p-1)*(q-1))

# https://facthacks.cr.yp.to/product.html
def producttree(X):
    result = [X]
    while len(X) > 1:
        X = [np.prod(X[i*2:(i+1)*2]) for i in range((len(X)+1)/2)]
        result.append(X)
    return result

# https://facthacks.cr.yp.to/remainder.html
def remaindersusingproducttree(n,T):
    result = [n]
    for t in reversed(T):
        result = [result[i/2] % t[i] for i in range(len(t))]
        print result
    return result

def remainders(n,X):
    return remaindersusingproducttree(n,producttree(X))

moduli_file = sys.argv[1]
ciphertext_file = sys.argv[2]
output_file = sys.argv[3]

with open(moduli_file) as f:
    moduli = f.read().strip().splitlines()
    moduli = [int(moduli[i], 16) for i in range(0, len(moduli))]

with open(ciphertext_file) as f:
    ciphertext = f.read()


e = 65537L
P = producttree(moduli)[-1][0]
Z = remainders(P, [moduli[i]**2 for i in range(len(moduli))])
p_all = [gcd(moduli[i], Z[i]/moduli[i]) for i in range(len(moduli))]

for i in range(len(moduli)):
    mod = moduli[i]
    p = p_all[i]
    q = mod / p
    if p == 1 or q == 1:
        continue
    d = get_private(e,p,q)
    try:
        rsakey = RSA.construct((mod,e,d))
        plaintext = decrypt(rsakey, ciphertext)
        print i, 'Correct RSA Key!'
        f = open(output_file,"w")
        f.write(plaintext)
        f.close()
        break
    except ValueError:
        print i, 'Wrong RSA Key'

