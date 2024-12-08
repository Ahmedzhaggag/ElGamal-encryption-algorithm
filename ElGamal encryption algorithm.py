import random
from sympy import mod_inverse, isprime  # Import isprime to validate primes

# GCD function to compute greatest common divisor
def gcd(a, b):
    """
    Computes the greatest common divisor (GCD) of two numbers a and b using the Euclidean algorithm.

    Args:
        a (int): First number
        b (int): Second number

    Returns:
        int: The GCD of a and b
    """
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)

# Generating large random prime number q
def gen_large_prime(bits=512):
    """
    Generates a large random prime number of specified bit size.

    Args:
        bits (int): The number of bits for the prime number (default is 512).

    Returns:
        int: A large prime number.
    """
    while True:
        p = random.getrandbits(bits)
        if isprime(p):  # Validate the primality of the number
            return p

# Generating a private key
def gen_key(q):
    """
    Generates a private key for ElGamal encryption.

    Args:
        q (int): The large prime number used in key generation.

    Returns:
        int: The generated private key.
    """
    key = random.randint(2, q-1)
    while gcd(q, key) != 1:  # Ensure the key is coprime with q
        key = random.randint(2, q-1)
    return key

# Modular exponentiation function (Efficient)
def power(a, b, c):
    """
    Efficiently computes a^b mod c using binary exponentiation.

    Args:
        a (int): The base number.
        b (int): The exponent.
        c (int): The modulus.

    Returns:
        int: The result of a^b mod c.
    """
    x = 1
    y = a
    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c
        y = (y * y) % c
        b = b // 2
    return x % c

# Encryption function for ElGamal
def encrypt(msg, q, h, g):
    """
    Encrypts a message using the ElGamal encryption scheme.

    Args:
        msg (str): The plaintext message to be encrypted.
        q (int): The large prime number.
        h (int): The public key of the receiver (g^a mod p).
        g (int): The base for the encryption.

    Returns:
        tuple: The encrypted message as a tuple (c1, c2, k), where
               c1 is the public part of the encryption,
               c2 is the encrypted message, and k is the sender's private key.
    """
    en_msg = []
    k = gen_key(q)  # Random private key for the sender
    c1 = power(g, k, q)  # c1 = g^k mod p
    c2 = []  # c2 will store encrypted message
    
    # Shared secret for encryption
    s = power(h, k, q)
    
    for char in msg:
        # Encrypt each character by multiplying ASCII value with s
        c2.append((ord(char) * s) % q)

    return c1, c2, k  # Return c1 (public part), c2 (encrypted message), and the sender's private key

# Decryption function for ElGamal
def decrypt(c1, c2, key, q):
    """
    Decrypts the ElGamal encrypted message using the receiver's private key.

    Args:
        c1 (int): The first part of the ciphertext.
        c2 (list of int): The second part of the ciphertext (encrypted message).
        key (int): The receiver's private key.
        q (int): The large prime number.

    Returns:
        str: The decrypted message.
    """
    # Calculate the shared secret using c1^key mod p
    s = power(c1, key, q)
    
    # Inverse of s modulo q (to recover original message)
    s_inv = mod_inverse(s, q)
    
    # Decrypt each character in the encrypted message
    decrypted_msg = ''.join([chr((c * s_inv) % q) for c in c2])
    
    return decrypted_msg

# Driver code
def main():
    """
    Main function to take input, perform encryption and decryption,
    and display the results to the user.
    """
    # Taking input message
    msg = input("Enter the message to be encrypted: ")

    if not msg:
        print("Error: The message cannot be empty.")
        return

    print("Original Message:", msg)

    # Large prime q and base g
    q = gen_large_prime(bits=512)  # Using a large prime number for q
    g = random.randint(2, q)

    # Receiver's private key generation
    key = gen_key(q)
    h = power(g, key, q)  # Public key for the receiver (g^a mod p)

    print("Public Base (g) used:", g)
    print("Public Key (g^a) used:", h)

    # Encrypting the message
    c1, c2, k = encrypt(msg, q, h, g)
    print("Encrypted Message (c1, c2):", c1, c2)

    # Decrypting the message using the private key
    decrypted_msg = decrypt(c1, c2, key, q)
    print("Decrypted Message:", decrypted_msg)

if __name__ == '__main__':
    main()