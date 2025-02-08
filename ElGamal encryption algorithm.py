"""
**Step 1: Compute the Greatest Common Divisor (GCD)**

Input: Two integers a and b

Output: Greatest common divisor (GCD) of a and b

If a < b, swap a and b.

If b divides a perfectly, return b.

Otherwise, recursively compute GCD(b, a % b).

**Step 2: Generate a Large Prime Number**

**Input:** Number of bits (bits)

**Output:** A prime number p


Repeat until a prime number is found:

**a.** Generate a random number p of bits size.

**b.** If p passes the Miller-Rabin Primality Test, return p.

**Step 3: Check if a Number is Prime (Miller-Rabin Test)**

**Input:**Integer n, number of iterations k

**Output:** True if n is prime, otherwise False

If n < 2, return False.

Repeat k times:

**a.** Choose a random number a in the range [2, n-1].

**b.** If a^(n-1) mod n ≠ 1, return False.

If n passes all tests, return True.

**Step 4: Generate a Private Key**

**Input:** Prime number q

**Output:** A private key key

Select a random integer key in the range [2, q-1].

Repeat until GCD(q, key) = 1.

Return key.

**Step 5: Compute Modular Exponentiation (power(a, b, c))**

**Input:** Base a, exponent b, modulus c

**Output:** (a^b) mod c

Initialize x = 1 and y = a.

While b > 0:

**a.** If b is odd, update x = (x * y) mod c.

**b.** Update y = (y * y) mod c.

**c.** Reduce b = b // 2.

Return x.

**Step 6: Compute Modular Inverse (mod_inverse(a, m))**

**Input:** Integer a, modulus m

**Output:** Modular inverse of a under m

Initialize m0 = m, x0 = 0, x1 = 1.

While a > 1:

**a.** Compute quotient q = a // m.

**b.** Update m, a = a % m, m.
**c.** Update x0, x1 = x1 - q * x0, x0.

If x1 < 0, adjust x1 = x1 + m0.

Return x1.

**Step 7: Encrypt a Message**

**Input:** Message msg, prime q, public key h, generator g

**Output:** Ciphertext (c1, c2, k)

Generate a random private key k.

Compute c1 = (g^k) mod q.

Compute shared secret s = (h^k) mod q.

Convert each character in msg to ASCII and encrypt:

a. Compute c2[i] = (ASCII(char) * s) mod q.

Return (c1, c2, k).

**Step 8: Decrypt a Message**

**Input:** Ciphertext (c1, c2), private key key, prime q

**Output:** Original message msg

Compute shared secret s = (c1^key) mod q.

Compute modular inverse s_inv = mod_inverse(s, q).

Convert each encrypted character back:

**a.** Compute char = (c2[i] * s_inv) mod q.

**b.** Convert to ASCII.

Return decrypted message msg.


**Step 9: Main Function (Execution Flow)**

Get user input msg.

Generate a large prime q.

Select a random generator g.

Generate private key key.

Compute public key h = (g^key) mod q.

Encrypt msg to get (c1, c2, k).

Display public values and encrypted message.

Decrypt (c1, c2) to retrieve original message.

Display decrypted message.

"""

import random

def gcd(a, b):
    if a < b:
        return gcd(b, a)  
    elif a % b == 0:
        return b  
    else:
        return gcd(b, a % b)  

# Generates a large prime number for encryption using Miller-Rabin Primality Test
def gen_large_prime(bits=512):
    while True:
        p = random.getrandbits(bits)  
        if is_prime(p): 
            return p

# Miller-Rabin Primality Test to verify if a number is prime
def is_prime(n, k=5):
    if n < 2:
        return False
    for _ in range(k):
        a = random.randint(2, n - 1)  
        if pow(a, n - 1, n) != 1:  
            return False
    return True  

# Generates a private key for ElGamal encryption
def gen_key(q):
    key = random.randint(2, q - 1)  
    while gcd(q, key) != 1:  
        key = random.randint(2, q - 1)  
    return key


def power(a, b, c):
    x = 1  
    y = a  
    while b > 0:
        if b % 2 != 0:  
            x = (x * y) % c
        y = (y * y) % c  
        b //= 2  
    return x % c


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1  
    while a > 1:
        q = a // m  
        m, a = a % m, m  
        x0, x1 = x1 - q * x0, x0  
    return x1 + m0 if x1 < 0 else x1  

# Encrypts a message using ElGamal encryption
def encrypt(msg, q, h, g):
 
    k = gen_key(q)  #
    c1 = power(g, k, q)  
    c2 = []  
    s = power(h, k, q)  

    for char in msg:
        c2.append((ord(char) * s) % q)  

    return (c1, c2, k)  

# Decrypts an ElGamal-encrypted message
def decrypt(c1, c2, key, q):
    
    s = power(c1, key, q)  
    s_inv = mod_inverse(s, q)  

    decrypted_msg = ''.join([chr((c * s_inv) % q) for c in c2])  
    return decrypted_msg

# Driver function to demonstrate ElGamal encryption and decryption
def main():
    msg = input("Enter the message to be encrypted: ")
    if not msg:
        print("Error: Message cannot be empty.")
        return

    q = gen_large_prime(bits=512)  
    g = random.randint(2, q) 

    key = gen_key(q) 
    h = power(g, key, q)  

    print(f"Public Base (g): {g}")
    print(f"Public Key (h = g^x mod p): {h}")

    c1, c2, k = encrypt(msg, q, h, g) 
    print(f"Encrypted Message: c1={c1}, c2={c2}")

    decrypted_msg = decrypt(c1, c2, key, q)  
    print(f"Decrypted Message: {decrypted_msg}")

if __name__ == '__main__':
    main()