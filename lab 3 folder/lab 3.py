from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from binascii import unhexlify
from PIL import Image
import os  #для роботи з директоріями
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256


Email = "dtimokhin"
text = Email[:8].encode('utf-8') 

if len(text) < 8:
    text = text.ljust(8, b'\0') 
#print(text)


def TaskOne():
    #keyHex =  b'133457799BBCDFF1'    b'' напряму пеертворює текст в байти, перетворюючи кожен символ в байтове представлення ASCII-символів, в даному випадку перетворить хеш в 16 байтів символів
    keyHex = "133457799BBCDFF1"

    keyByte = unhexlify(keyHex)
    #print(keyByte)

    ChipherType = DES.new(keyByte, DES.MODE_ECB)

    result = ChipherType.encrypt(text)

    # print("Result: ", repr(result))
    print("task 1")
    print("Result in hex: ", result.hex())  #можна також додати .upper() для перетворення ллітер у верхній регістер, але не відомо в якому форматі приймає відповідь
    # print("Raw text: ", Email)
    # print("text: ", repr(text))
    # print("key (hex): ", repr(keyHex))
    # print("key (byte): ", repr(keyByte))


def TaskTwo():
    Key1 = unhexlify("0123456789ABCDEF")
    Key2 = unhexlify("23456789ABCDEF01")
    Key3 = unhexlify("456789ABCDEF0123")

    key = Key1 + Key2 + Key3
    ChipherType = DES3.new(key, DES3.MODE_ECB)

    result = ChipherType.encrypt(text)

    print("Task 2")
    print("Result in hex: ", result.hex())


def TaskThree():
    text2 = Email[:16].encode('utf-8') 
    if len(text2) < 16:
        text2 = text2.ljust(16, b'\0')

    key = unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
    ChipherType = AES.new(key, AES.MODE_ECB)
    result = ChipherType.encrypt(text2)
    print("Task 3")
    print("Result in hex: ", result.hex())

def Task4():

    ImgPath = os.path.join("res", "tux-72.png")
    img = Image.open(ImgPath).convert("RGB")


    P = img.tobytes()
    width, height = img.size
    length = len(P)
    
    P_padded = pad(P, 16)

    key = Email.encode('ascii')
    key = key.ljust(16, b'\0')

    cipher_ecb = AES.new(key, AES.MODE_ECB)
    C_ecb = cipher_ecb.encrypt(P_padded)

    iv = bytes.fromhex("451652008A75BF26D4B86AEE5A2CDF81")

    cipher_cbc = AES.new(key, AES.MODE_CBC, iv=iv)
    C_cbc = cipher_cbc.encrypt(P_padded)

    # EBC
    img_ecb = Image.frombytes("RGB", (width, height), C_ecb[:length])
    img_ecb.save(os.path.join("output", "tux_ecb.png"))                                           

    # CBC
    img_cbc = Image.frombytes("RGB", (width, height), C_cbc[:length])
    img_cbc.save(os.path.join("output", "tux_cbc.png"))

    sha_ecb = sha256(C_ecb).hexdigest()
    sha_cbc = sha256(C_cbc).hexdigest()

    print("task 4")
    print("SHA-256 ECB:", sha_ecb)
    print("SHA-256 CBC:", sha_cbc)




TaskOne()
TaskTwo()
TaskThree()
Task4()
