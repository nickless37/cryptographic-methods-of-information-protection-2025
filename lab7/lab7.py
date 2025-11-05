import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import binascii
import os
from Crypto.Signature import pss


Email = "dtimokhin"

def Q1():
    p = 11
    q = 13
    e = 7
    m1 = 9

    n = p*q

    fn = (p-1)*(q-1)

    c = pow(m1,e,n)

    d = pow(e,-1,fn) #так як d*e≡1(mod fn), d≡e^-1(mod fn)  

    m2 = pow(c, d,n)

    # print(n,fn,c,d,m2)

    print("task 1:")
    print("c=",c,"m=",m2)


def Q2():
    p = 530881
    q = 552721
    e = 65537

    n = p*q

    fn = (p-1)*(q-1)

    print("task 2:")

    if math.gcd(e, fn) == 1:
        d = pow(e,-1,fn)
        m = int.from_bytes(Email.encode('utf-8'), byteorder='big')
        c = pow(m,e,n)
        m2 = pow(c,d,n)
        print("m1=",m,"m2=",m2)
        # вводні p i q не прості і мають спільний дільник, як наслідок треба використовувати іншу формулу. так як формула неправильна- м1 і м2 будуть відрізнятися, що, як я зрозумів, передбачено задачею
    else:
        print("error: invalid gcd")




def Q3(): 
    # у цій роботі для розвитку і аналізу процесу я розіб'ю функцію шифрування на модулі

    def generate_rsa_keypair():
        key = RSA.generate(2048, e=65537)
        return key

    def custom_oaep_encrypt_with_seed(public_key, message, seed=None):

        if seed is None:
            seed = os.urandom(32)
        
        cipher = PKCS1_OAEP.new(
            key=public_key,
            hashAlgo=SHA256,
            mgfunc=lambda x, y: PKCS1_OAEP.MGF1(x, y, SHA256)
        )
    
        ciphertext = cipher.encrypt(message)
        
        return ciphertext, seed

    def manual_oaep_encrypt_with_seed(public_key, message, seed):

        hLen = 32  # SHA-256 довжина хешу
        k = 256    # 2048 bits = 256 bytes
        mLen = len(message)
        
        if mLen > k - 2 * hLen - 2:
            raise ValueError("Message too long")
        
        lHash = SHA256.new(b"").digest()
        
        PS = b'\x00' * (k - mLen - 2 * hLen - 2)
        
        DB = lHash + PS + b'\x01' + message
        
        dbMask = MGF1(seed, k - hLen - 1, SHA256)

        maskedDB = bytes(DB[i] ^ dbMask[i] for i in range(len(DB)))
        
        seedMask = MGF1(maskedDB, hLen, SHA256)
        
        maskedSeed = bytes(seed[i] ^ seedMask[i] for i in range(len(seed)))
        
        EM = b'\x00' + maskedSeed + maskedDB
        
        m = bytes_to_int(EM)
        c = pow(m, public_key.e, public_key.n)
        ciphertext = int_to_bytes(c, k)
        
        return ciphertext, seed

    def MGF1(seed, mask_len, hash_class):
        hLen = hash_class.digest_size
        T = b""
        counter = 0
        
        while len(T) < mask_len:
            C = int_to_bytes(counter, 4)
            T += hash_class.new(seed + C).digest()
            counter += 1
        
        return T[:mask_len]

    def bytes_to_int(b):
        return int.from_bytes(b, byteorder='big')

    def int_to_bytes(i, length=None):
        if length is None:
            length = (i.bit_length() + 7) // 8
        return i.to_bytes(length, byteorder='big')

    def main():

        email = b"dtimokhin"
        
        key = generate_rsa_keypair()
        
        seed = os.urandom(32)  # 256-bit seed
        
        ciphertext, used_seed = manual_oaep_encrypt_with_seed(key.publickey(), email, seed)
        
        ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')
        seed_hex = binascii.hexlify(used_seed).decode('utf-8')
        
        private_key_pem = key.export_key(format='PEM').decode('utf-8')


        print(f"\n1. CIPHERTEXT (hex):")
        print(ciphertext_hex)
        
        print(f"\n2. PRIVATE KEY (PEM format):")
        print(private_key_pem)
        
        print(f"\n3. SEED USED IN OAEP PADDING (hex):")
        print(seed_hex)
        
        print(f"\n4. checkup:")
        print("Decryption Test:")

        
        try:
            builtin_cipher = PKCS1_OAEP.new(key=key, hashAlgo=SHA256)
            test_encrypted = builtin_cipher.encrypt(email)
            decrypted = builtin_cipher.decrypt(test_encrypted)
            
            print(f"Original email: {email.decode('utf-8')}")
            print(f"Decrypted email: {decrypted.decode('utf-8')}")
            print(f"Built-in OAEP decryption successful: {email == decrypted}")
            
            print(f"Manual OAEP ciphertext length: {len(ciphertext)} bytes")
            print(f"Seed used: {seed_hex}")
            
        except Exception as e:
            print(f"Decryption error: {e}")

    main()
        

def Q4():
    p = 17
    g = 3
    x = 5 
    m = 7
    k = 4
    

    y = pow(g,x,p)

    c1 = pow(g,k,p)

    c2 = m * pow(y,k,p) % p

    # m2 = c2 * pow(c1**x, -1,p)       x
    c1_1 = pow(c1,x,p)
    c1_2 = pow(c1_1,-1,p)
    m2 = (c2*c1_2)%p

    print("m1=", m,"m2=",m2)

    print(f"\npublic key component: y=",y)
    print(f"\nciphertext pair: c1 =",c1,"c2=",c2)





# Q1()
# Q2()
#Q3()
Q4()