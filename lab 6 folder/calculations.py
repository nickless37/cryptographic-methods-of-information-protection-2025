p = 257
APVal = 201
BPVal = 45
ciphertext_hex = "febe49ef11b07faaec4a1c77cc5ab5f1bd8c4967d68092e6bd6ea8f9e928ef6f"
ciphertext = bytes.fromhex(ciphertext_hex)

import hashlib
from Crypto.Cipher import AES
import math

def findB():
    for b in range(1, p):
        if pow(201, b, 257) == 45:
            # print(f"Found b = {b} such that 201^{b} ≡ 45 mod 257")
            break
    # print(f"201^69 mod 257 = {pow(201, 69, 257)}")  #checkup
    return b

# b = findB()
# print(f"B:  {b}")
#useless

def is_text(decrypted):
    """Check if decrypted text contains common English keywords"""
    try:
        text = decrypted.decode('utf-8', errors='ignore')
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in ['the', 'flag', 'secret', 'message', 'complete'])
    except:
        return False

def decrypt_and_check(shared_secret):
    """Decrypt with given shared secret and check if result is valid text"""
    secret_str = str(shared_secret)
    secret_bytes = secret_str.encode('utf-8')
    aes_key = hashlib.pbkdf2_hmac("sha256", secret_bytes, b'\x00' * 16, 200000, 32)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    
    if is_text(decrypted):
        try:
            # Remove PKCS#7 padding
            pad_len = decrypted[-1]
            if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
                plaintext = decrypted[:-pad_len].decode('utf-8')
            else:
                plaintext = decrypted.decode('utf-8')
            return plaintext
        except:
            return decrypted.decode('utf-8', errors='replace')
    return None

# BF 1:
print("=== BRUTE FORCE 1: Shamir's m and a pairs ===")
found_solution = False

for m in range(1, p): 
    a_candidates = [a for a in range(1, p) if pow(m, a, p) == 201]
    
    if a_candidates: 
        result = decrypt_and_check(m)  
        if result:
            print(f"SUCCESS: m = {m}, a_candidates = {a_candidates}")
            print(f"Plaintext: '{result}'")
            found_solution = True
            break

if not found_solution:
    # BF 2: 
    print("\n=== BRUTE FORCE 2: Consistent Shamir's protocol ===")
    b = 69  # получено ранее
    
    for a in range(1, p):
        if math.gcd(a, p-1) != 1:  
            continue
            
        a_inv = pow(a, -1, p-1)
        m1 = pow(201, a_inv, p)  
        ab_inv = pow(a * b, -1, p-1)
        m2 = pow(45, ab_inv, p)  
        
        if m1 == m2: 
            result = decrypt_and_check(m1) 
            if result:
                print(f"SUCCESS: a = {a}, m = {m1}")
                print(f"Plaintext: '{result}'")
                found_solution = True
                break

if not found_solution:
    # BF3 :
    print("\n=== BRUTE FORCE 3: Simple shared secret test ===")
    for shared_secret in range(1, p):
        result = decrypt_and_check(shared_secret)  # Use improved text detection
        if result:
            print(f"SUCCESS: Shared secret = {shared_secret}")
            print(f"Plaintext: '{result}'")
            found_solution = True
            break

if not found_solution:
    print("No solution found with any brute force method")