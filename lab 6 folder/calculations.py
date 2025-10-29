p = 257
APVal = 201
BPVal = 45
Ciphertext = "febe49ef11b07faaec4a1c77cc5ab5f1bd8c4967d68092e6bd6ea8f9e928ef6f"

def findB():
    for b in range(1, p):
        if pow(201, b, 257) == 45:
            # print(f"Found b = {b} such that 201^{b} ≡ 45 mod 257")
            break
    # print(f"201^69 mod 257 = {pow(201, 69, 257)}")  #checkup
    return b

b = findB()
print(f"B:  {b}")