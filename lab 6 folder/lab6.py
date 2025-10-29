#якщо ця строка не видалена: VS code почав неправильно визначати шлях посеред роботи
#      python "C:\Users\Home\Desktop 2\cript\labs\Новая папка\cryptographic-methods-of-information-protection-2025\lab 6 folder\lab6.py"

import hashlib
from Crypto.Cipher import AES

print("task 1")
# 1: так як грубі розрахунки ірраціональні для подібних змінних, я буду розв'язувати задачу за способом великих та малих кроків
p = 257
g = 3
y = 110 #n = 110

m = int(p**0.5)+1 #число, більше за корінь з p (p^0.5) 

#малі кроки:
baby = {pow(g, j, p): j for j in range(m)}  #pow- функція на 3 змінні: основа, експонента(степінь), модуль. цикл виконує цю функцію, беручи j з діапазону м

#великі кроки
inv = pow(g, -m, p)

value = y
for i in range(m):
    if value in baby:
        x = i*m + baby[value]
        print("x =", x)
        break
    value = (value * inv) % p


#2

Email = "dtimokhin"

alice_priv = ord(Email[0])   # ASCII 1
bob_priv   = ord(Email[1])   # ASCII 2

p_hex = (
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

p = int(p_hex, 16)
g = 2

Alice_public_value = pow(g, alice_priv, p)   
Bob_public_value = pow(g, bob_priv, p)
s_from_alice = pow(Bob_public_value, alice_priv, p)
s_from_bob   = pow(Alice_public_value, bob_priv, p)

assert s_from_alice == s_from_bob, "Shared secrets do not match - something is wrong." 

shared = s_from_alice

print("task 2")
print("Alice's public value", hex(Alice_public_value))
print("Bob's public value", hex(Bob_public_value))
print("shared secret", hex(shared))

#3

# p = 257 , g = 3
#  Alice’s public value: A = 201 
# # Bob’s public value: B = 45
# Ciphertext: febe49ef11b07faaec4a1c77cc5ab5f1bd8c4967d68092e6bd6ea8f9e928ef6f
# Encryption scheme: Shared secret is used to derive an AES key via PBKDF2:

p = 257
APVal = 201
BPVal = 45
Ciphertext = "febe49ef11b07faaec4a1c77cc5ab5f1bd8c4967d68092e6bd6ea8f9e928ef6f"

#перетворю перше завдання в функцію

# def Logarithm(y , p , g):
#     # p = 257
#     # g = 3

#     m = int(p**0.5)+1

#     baby = {pow(g, j, p): j for j in range(m)}

#     inv = pow(g, -m, p)

#     value = y
#     for i in range(m):
#         if value in baby:
#             return i*m + baby[value]
#             # print("x =", x)
#             break
#         value = (value * inv) % p
#     # return x
    

# keyA = Logarithm(APVal, 257 , 3) 

# Secret = pow(BPVal, keyA, p2)

#useless


Secret = 45 # отримано брутфорсом в інших файлах, описано у logic.md

shared_secret_str = str(Secret)
Secret_bytes = shared_secret_str.encode('utf-8')

AES_Key = hashlib.pbkdf2_hmac(
    "sha256",
    Secret_bytes,  # This should be the decimal string as bytes
    b'\x00' * 16,        # salt
    200000,              # iterations
    32                   # key length
)

CiphertextByte = bytes.fromhex(Ciphertext)
ciphertype = AES.new(AES_Key, AES.MODE_ECB)
pt_padded = ciphertype.decrypt(CiphertextByte)

# прибираю PKCS#7 padding
pad_len = pt_padded[-1]
plaintext = pt_padded[:-pad_len]


print("task 3")
print("secret",Secret)
print("decrypted:", plaintext.decode())


