# Elliptic Curve: y^2 = x^3 + x  over F_43
 
print ("\ntask1")

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