from Crypto.Cipher import ARC4  #ARC4 - алгоритм RC4 без авторського права та бренду
from Crypto.Cipher import Salsa20
import random

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


#/////////////////////////////////////////////////

class strumok:
    #так як розробка шифру "струмок" відповідно до стандартів криптостійкості можна прирівняти до дипломної роботи, я спробую написати значно спрощенну, менш стійку версію, що повторює принцип
    
    def KeyStreamGenerator(key: str, length: int) -> bytes:
        #у цій функції ключ перетворюється у потік байтів за певним алгоритмом. я використаю генератор псевдовипадкових чисел з сідом, але оригіінальний шифр значно складніший.
        random.seed(key) #ініціалізація рандомайзера
        return bytes([random.randint(0,255) for _ in range(length)]) #повертає список байтів(зі значенням від 0 до 255), у якому кількість байтів відповідає довжині тексту

    def encrypt(Text: str , key: str) -> bytes:
        TextByte = Text.encode('utf-8') #перетворення тексту в байти як і в минулих завданнях
        stream = strumok.KeyStreamGenerator(key, len(TextByte)) #виклик функції створення потокового ключа
        ciphered = bytes([b ^ s for b, s in zip(TextByte, stream)]) #b ^ s  -- попарна операція XOR над байтами тексту(b) та потоковим ключем(s), одна з двох основних частин шифру(друга- це створення потокового ключа), zip створює пари байтів з двох списків, структура for b, s in надає значення пар змінним та виконує операцію для всіх створених у zip пар. завершує шифрування функція bytes, яка переносить отриманий список в формат байтів, пайтон бере на себе багато перетворень без потреби в їх прописанні, якщо в інакшому випадку можлива помилка, наприклад при операціях міг змінитися формат чисел та списку
        return ciphered

    def decrypt(CipheredText: bytes, key: str) -> str:
        stream = strumok.KeyStreamGenerator(key, len(CipheredText)) #виклик функції створення потокового ключа
        TextByte = bytes([c ^ s for c, s in zip(CipheredText, stream)]) #операція XOR. вона обернена сама до себе, тому тут змін робити не треба. потоковий ключ буде тим же, бо random.seed створює псевдовипадковий результат, тобто при одному сиді(кеу) буде один результат
        return TextByte.decode('utf-8', errors='ignore') #перетворення байтів в текст з ігноруванням помилок

def StrumokTest():

    #тест
    PlainText = "перевірка шифру з використанням кирилиці"
    Key = "Keyword"


    print("Початковий текст:",PlainText, "key:", Key)
    STText = strumok.encrypt(PlainText, Key)
    print(STText)
    DecText = strumok.decrypt(STText, Key)
    print(DecText)

StrumokTest()