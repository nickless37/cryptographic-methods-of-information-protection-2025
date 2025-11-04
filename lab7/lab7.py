import math
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










Q1()
Q2()