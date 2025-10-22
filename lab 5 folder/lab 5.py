import hashlib

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

print (difference , "out of 128")