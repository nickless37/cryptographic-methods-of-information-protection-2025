import hashlib
import math

#використані формули наведені у директорії formulas
def birthday_exact(m: int, N: int) -> float:
    # точна ймовірність хача б 1 колізії через формулу 1
    p_no = 1.0
    for k in range(N):
        p_no *= (1 - k / m)
    return 1 - p_no

def birthday_approx(m: int, N: int) -> float:
    # приблизна ймовірність хача б 1 колізії через формулу 2 (наближення)
    return 1 - math.exp(-N * (N - 1) / (2 * m))

def expected_collisions(m: int, N: int) -> float:
    # очікувана кількість колізій через формулу 3
    return N * (N - 1) / (2 * m)


#1.1
m1 = 365
for N in [23,50]:
    exact = birthday_exact(m1, N)
    approx = birthday_approx(m1, N)
    expected = expected_collisions(m1, N)



#//////////////////////ex2

Email = "dtimokhin"
Email2 = "xtimokhin"

EmailHash = hashlib.md5(Email.encode('utf-8'))
EmailHash2 = hashlib.md5(Email2.encode('utf-8'))

HashDigets =''.join(f'{byte:08b}' for byte in EmailHash.digest())
HashDigets2 =''.join(f'{byte:08b}' for byte in EmailHash2.digest())

print("Email Hash:", EmailHash.hexdigest())
print("Email2 Hash:", EmailHash2.hexdigest())

print(HashDigets)
print(HashDigets2)

difference = sum(bit1 != bit2 for bit1, bit2 in zip(HashDigets, HashDigets2))

print (difference , "out of 128")  #приблизно половина

def sha256_file(path, chunk_size=8192): #функція для 2.2   #chunk_size- розмір блоку, який буде оборблено за раз при створенні кешу, що використовується для уникнення переповнення RAM, зазвичай 8Кб / 8192б, не впливає на результат 
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

FilePath = "lab 5 folder\src\AES.pdf"
HashValue = sha256_file(FilePath)
print(f"SHA-256: {HashValue}")

