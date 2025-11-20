from pathlib import Path
# Elliptic Curve: y^2 = x^3 + x  over F_43
 
print ("\ntask 1")

p = 43

def inv_mod(a, p):
    return pow(a, p - 2, p) #за малою теоремою фермі

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    
    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P != Q:
        m = (y2 - y1) * inv_mod((x2 - x1) % p, p) % p
    else:
        m = (3 * x1 * x1 + 1) * inv_mod((2 * y1) % p, p) % p

    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1 - x3) - y1) % p

    return (x3, y3)

points = []

for x in range(p):
    rhs = (x**3 + x) % p  

    for y in range(p):
        if (y*y) % p == rhs:
            points.append((x, y))

print("\nTotal affine points:", len(points))
print(points)






P = (4, 5)
Q = (5, 1)
R = point_add(P, Q)

print("\n(4,5) + (5,1) =", R)

print ("\ntask 2")


from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

SCRIPT_DIR = Path(__file__).parent

PRIVATE_KEY_FILE = SCRIPT_DIR / "src" / "privkey.der"

# PRIVATE_KEY_FILE = "privkey.der" на момент першого тесту файл було розташовано у тій же категорії, що і програма.  

with open(PRIVATE_KEY_FILE, "rb") as f:
    key = ECC.import_key(f.read())

message = b"Write me: d.timokin_FIT_13_23_b_d@knute.edu.ua" 


h = SHA256.new(message)

signer = DSS.new(key, "deterministic-rfc6979")
signature = signer.sign(h)


print("\nSignature (hex):", signature.hex())

def checkup():
    from Crypto.Signature import DSS

    pub_key = key.public_key()
    verifier = DSS.new(pub_key, "deterministic-rfc6979")

    try:
        verifier.verify(h, signature)
        print("test passed")
    except ValueError:
        print("erro")

# checkup()