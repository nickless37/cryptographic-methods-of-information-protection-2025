from Crypto.Cipher import ARC4  #ARC4 - алгоритм RC4 без авторського права та бренду
from Crypto.Cipher import Salsa20

Email = "dtimokhin"
text = Email.encode('utf-8') 
# у RC4 текст не має обмежень по довжені, тому не треба обрізати або доповнювати текст як у минулій роботі 


def TaskOne():
    key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF") # unhexlify має той же ефект, що і bytes.fromhex
    CipherType = ARC4.new(key)
    cipherText = CipherType.encrypt(text)
    print("result(hex):", cipherText.hex())

    # перевірка
    # decipher = ARC4.new(key)   #Для розшифрування треба створювати новий об'єкт, бо у цьому шифрі об'єкт шифру змінюється при використанні
    # decrypted = decipher.decrypt(cipherText)
    # print("Decrypted:", decrypted.decode())

def TaskTwo():
    keydata = bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F901112131415161718192A2B2C2D2E2F30")
    CipherType = Salsa20.new(key=keydata)
    noncedata = CipherType.nonce #nonce- 8 байт, які необхідні для розшифрування 
    cipherText = CipherType.encrypt(text)
    print("result(hex): ",cipherText.hex())
    print("Nonce (hex):", noncedata.hex())

    #checkup
    # decipher = Salsa20.new(key=keydata, nonce=noncedata)
    # decrypted = decipher.decrypt(cipherText)
    # print("Decrypted:", decrypted.decode()) 

print("Task 1")
TaskOne()
print("Task 2")
TaskTwo()