#цей файл майже повністю створений АІ для пошуку та аналізу помилок

import hashlib
from Crypto.Cipher import AES

p = 257
A = 201
B = 45
ciphertext_hex = "febe49ef11b07faaec4a1c77cc5ab5f1bd8c4967d68092e6bd6ea8f9e928ef6f"
ciphertext = bytes.fromhex(ciphertext_hex)

b = 69

# Now we need to find Alice's private key a
# We know: x1 = m^a = 201
# But we don't know m yet...

# In Shamir's protocol, the shared secret is the original message m
# Let's find m by working backwards

# We have:
# x1 = m^a = 201
# x2 = m^(ab) = 45
# x3 = m^b (this would be sent back to Bob)

# But we don't have x3 directly. Instead, we have an AES ciphertext.
# Maybe the shared secret m was used to derive the AES key?

# Let me try to find a such that we get a consistent story
# We need to find a and m such that:
# m^a ≡ 201 mod p
# m^(ab) ≡ 45 mod p

print("\n=== FINDING CONSISTENT a AND m ===")

# Since we know b = 69, we have:
# m^(a*69) ≡ 45 mod p
# But we also have: m^a ≡ 201 mod p
# So: (m^a)^69 ≡ 201^69 ≡ 45 mod p (which we already verified)

# The shared secret m should be such that when used with PBKDF2, it decrypts the ciphertext
# Let's brute force m (the shared secret)

print("Brute forcing the shared secret m...")

for m in range(1, p):
    # Test if this m could be the shared secret
    # We need to check if there exists an a such that m^a ≡ 201 mod p
    a_candidates = []
    for a in range(1, p):
        if pow(m, a, p) == 201:
            a_candidates.append(a)
    
    # If we found at least one a that works, test this m as shared secret
    if a_candidates:
        # Test m as the shared secret for AES
        secret_str = str(m)
        secret_bytes = secret_str.encode('utf-8')
        
        aes_key = hashlib.pbkdf2_hmac("sha256", secret_bytes, b'\x00' * 16, 200000, 32)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        
        # Check if it produces readable text
        try:
            # Try direct decode
            text = decrypted.decode('utf-8')
            if text.isprintable() and len(text.strip()) > 3:
                print(f"FOUND: m = {m}, a candidates = {a_candidates}")
                print(f"Plaintext: '{text}'")
                break
        except:
            # Try with padding removal
            try:
                pad_len = decrypted[-1]
                if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
                    unpadded = decrypted[:-pad_len]
                    text = unpadded.decode('utf-8')
                    if text.isprintable() and len(text.strip()) > 3:
                        print(f"FOUND: m = {m}, a candidates = {a_candidates}")
                        print(f"Plaintext: '{text}'")
                        break
            except:
                pass

print("\n=== ALTERNATIVE APPROACH ===")
# Maybe the shared secret is not m, but something derived from the protocol
# In some variants, the shared secret is g^(ab) mod p, just like DH

# We know b = 69 from the Shamir's protocol relationship
# Let's find a using the standard discrete log with g=3

def find_discrete_log(target, p, g):
    for x in range(1, p):
        if pow(g, x, p) == target:
            return x
    return None

# If we use g=3 as the base:
a_standard = find_discrete_log(A, p, 3)  # This gives a=101
print(f"Standard discrete log a = {a_standard}")

# But this might not be the right a for Shamir's protocol!
# In Shamir's protocol, the base is the message m, not g

# Let me try a different approach: find a such that the protocol makes sense
# We know: 201^69 ≡ 45 mod p (verified)
# We need: there exists some m such that m^a = 201 and m^(ab) = 45

# This means: m = 201^(a^{-1} mod (p-1))
# And also: m = 45^((ab)^{-1} mod (p-1))

# Let's find a by ensuring these are consistent
print("\n=== FINDING a FOR CONSISTENT SHAMIR'S PROTOCOL ===")

for a in range(1, p):
    # Check if gcd(a, p-1) = 1 (required for inverse to exist)
    import math
    if math.gcd(a, p-1) != 1:
        continue
    
    # Calculate a^{-1} mod (p-1)
    a_inv = pow(a, -1, p-1)
    
    # Calculate m from x1: m = 201^(a^{-1}) mod p
    m1 = pow(201, a_inv, p)
    
    # Calculate m from x2: m = 45^((ab)^{-1}) mod p
    ab_inv = pow(a * b, -1, p-1)
    m2 = pow(45, ab_inv, p)
    
    # If both give the same m, we found a consistent solution
    if m1 == m2:
        print(f"Consistent solution: a = {a}, m = {m1}")
        
        # Test this m as shared secret
        secret_str = str(m1)
        secret_bytes = secret_str.encode('utf-8')
        
        aes_key = hashlib.pbkdf2_hmac("sha256", secret_bytes, b'\x00' * 16, 200000, 32)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        
        # Check if it produces readable text
        try:
            text = decrypted.decode('utf-8')
            if text.isprintable() and len(text.strip()) > 3:
                print(f"SUCCESS! Plaintext: '{text}'")
                break
        except:
            try:
                pad_len = decrypted[-1]
                if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
                    unpadded = decrypted[:-pad_len]
                    text = unpadded.decode('utf-8')
                    if text.isprintable() and len(text.strip()) > 3:
                        print(f"SUCCESS! Plaintext: '{text}'")
                        break
            except:
                pass

print("\n=== QUICK BRUTE FORCE ===")
# If the above doesn't work, let's just brute force all possible shared secrets
# but only test those that could be valid in Shamir's protocol context

for shared_secret in range(1, p):
    secret_str = str(shared_secret)
    secret_bytes = secret_str.encode('utf-8')
    
    aes_key = hashlib.pbkdf2_hmac("sha256", secret_bytes, b'\x00' * 16, 200000, 32)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    
    # Check for common plaintext patterns
    try:
        text = decrypted.decode('utf-8', errors='replace')
        if 'the' in text.lower() or 'flag' in text.lower() or 'secret' in text.lower():
            print(f"Interesting: shared_secret={shared_secret}, text='{text}'")
    except:
        pass