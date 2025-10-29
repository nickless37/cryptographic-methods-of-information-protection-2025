import hashlib
from Crypto.Cipher import AES

p = 257
A = 201
B = 45
ciphertext_hex = "febe49ef11b07faaec4a1c77cc5ab5f1bd8c4967d68092e6bd6ea8f9e928ef6f"
ciphertext = bytes.fromhex(ciphertext_hex)

print("=== FINAL SOLUTION ===")

# The shared secret is 45
shared_secret = 45
print(f"Shared secret: {shared_secret}")

# Derive AES key using PBKDF2
secret_str = str(shared_secret)
secret_bytes = secret_str.encode('utf-8')

aes_key = hashlib.pbkdf2_hmac(
    "sha256",
    secret_bytes,
    b'\x00' * 16,
    200000,
    32
)

print(f"AES key: {aes_key.hex()}")

# Decrypt the ciphertext
cipher = AES.new(aes_key, AES.MODE_ECB)
decrypted_padded = cipher.decrypt(ciphertext)

# Remove PKCS#7 padding
pad_len = decrypted_padded[-1]
plaintext = decrypted_padded[:-pad_len]

print(f"Decrypted plaintext: '{plaintext.decode('utf-8')}'")