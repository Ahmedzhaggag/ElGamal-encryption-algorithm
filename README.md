

Step 1: Compute the Greatest Common Divisor (GCD)

Input: Two integers a and b

Output: Greatest common divisor (GCD) of a and b

If a < b, swap a and b.

If b divides a perfectly, return b.

Otherwise, recursively compute GCD(b, a % b).
Step 2: Generate a Large Prime Number

Input:Number of bits (bits)

Output: A prime number p


Repeat until a prime number is found:

a.Generate a random number p of bits size.

b. If p passes the Miller-Rabin Primality Test, return p.

Step 3: Check if a Number is Prime (Miller-Rabin Test)

Input:Integer n, number of iterations k

Output: True if n is prime, otherwise False

If n < 2, return False.

Repeat k times:

a. Choose a random number a in the range [2, n-1].

b. If a^(n-1) mod n ≠ 1, return False.

If n passes all tests, return True.

Step 4: Generate a Private Key

Input:Prime number q

Output: A private key key

Select a random integer key in the range [2, q-1].

Repeat until GCD(q, key) = 1.

Return key.

Step 5: Compute Modular Exponentiation (power(a, b, c))

Input: Base a, exponent b, modulus c

Output: (a^b) mod c

Initialize x = 1 and y = a.

While b > 0:

a. If b is odd, update x = (x  y) mod c.

b. Update y = (y  y) mod c.

c. Reduce b = b // 2.

Return x.

Step 6: Compute Modular Inverse (mod_inverse(a, m))

Input: Integer a, modulus m

Output: Modular inverse of a under m

Initialize m0 = m, x0 = 0, x1 = 1.

While a > 1:

a. Compute quotient q = a // m.

b. Update m, a = a % m, m.
c. Update x0, x1 = x1 - q  x0, x0.

If x1 < 0, adjust x1 = x1 + m0.

Return x1.

Step 7: Encrypt a Message

Input: Message msg, prime q, public key h, generator g

Output: Ciphertext (c1, c2, k)

Generate a random private key k.

Compute c1 = (g^k) mod q.

Compute shared secret s = (h^k) mod q.

Convert each character in msg to ASCII and encrypt:

a. Compute c2[i] = (ASCII(char)  s) mod q.

Return (c1, c2, k).

Step 8: Decrypt a Message

Input: Ciphertext (c1, c2), private key key, prime q

Output: Original message msg

Compute shared secret s = (c1^key) mod q.

Compute modular inverse s_inv = mod_inverse(s, q).

Convert each encrypted character back:

a. Compute char = (c2[i]  s_inv) mod q.

b. Convert to ASCII.

Return decrypted message msg.


Step 9: Main Function (Execution Flow)

Get user input msg.

Generate a large prime q.

Select a random generator g.

Generate private key key.

Compute public key h = (g^key) mod q.

Encrypt msg to get (c1, c2, k).

Display public values and encrypted message.

Decrypt (c1, c2) to retrieve original message.

Display decrypted message.

Pseudocode

FUNCTION gcd(a, b):

    IF a < b:

        RETURN gcd(b, a)  # Ensure a >= b

    ELSE IF a % b == 0:

        RETURN b  # Base case: when b divides a perfectly

    ELSE:

        RETURN gcd(b, a % b)  # Apply Euclidean algorithm recursively

FUNCTION gen_large_prime(bits):

    WHILE True:

        p ← Generate a random 'bits'-bit number

        IF is_prime(p) THEN RETURN p

FUNCTION is_prime(n, k):

    IF n < 2 THEN RETURN False

    FOR i FROM 1 TO k:

        a ← Random integer in range [2, n-1]

        IF pow(a, n-1, n) ≠ 1 THEN RETURN False

    RETURN True  # Likely prime


FUNCTION gen_key(q):

    key ← Random integer in range [2, q-1]

    WHILE gcd(q, key) ≠ 1:

        key ← Random integer in range [2, q-1]  # Ensure key is coprime with q

    RETURN key

FUNCTION power(a, b, c):

    x ← 1

    y ← a

    WHILE b > 0:

        IF b is odd:

            x ← (x  y) mod c

        y ← (y  y) mod c

        b ← b // 2

    RETURN x mod c


FUNCTION mod_inverse(a, m):

    m0, x0, x1 ← m, 0, 1

    WHILE a > 1:

        q ← a // m

        m, a ← a % m, m

        x0, x1 ← x1 - q  x0, x0

    IF x1 < 0 THEN x1 ← x1 + m0

    RETURN x1

FUNCTION encrypt(msg, q, h, g):

    k ← gen_key(q)  # Generate sender's random private key

    c1 ← power(g, k, q)  # Compute c1 = g^k mod q

    s ← power(h, k, q)  # Compute shared secret

    c2 ← EMPTY LIST

    FOR each character in msg:

        Append (ASCII value of character  s) mod q to c2

    RETURN (c1, c2, k)


FUNCTION decrypt(c1, c2, key, q):

    s ← power(c1, key, q)  # Compute shared secret

    s_inv ← mod_inverse(s, q)  # Compute modular inverse of shared secret

    decrypted_msg ← ""

    FOR each encrypted character in c2:

        Append character ((encrypted_char  s_inv) mod q) to decrypted_msg

    RETURN decrypted_msg

FUNCTION main():

    PRINT "Enter the message to be encrypted:"

    msg ← User input

    IF msg is empty:

        PRINT "Error: Message cannot be empty."

        RETURN
    

    q ← gen_large_prime(512)  # Generate large prime q

    g ← Random integer in range [2, q]
    
    key ← gen_key(q)  # Generate private key

    h ← power(g, key, q)  # Compute public key

    PRINT "Public Base (g):", g

    PRINT "Public Key (h = g^x mod p):", h

    (c1, c2, k) ← encrypt(msg, q, h, g)

    PRINT "Encrypted Message: c1 =", c1, " c2 =", c2

    decrypted_msg ← decrypt(c1, c2, key, q)

    PRINT "Decrypted Message:", decrypted_msg

CALL main()
