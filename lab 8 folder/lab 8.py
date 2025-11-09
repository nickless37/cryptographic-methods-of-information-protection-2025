import base64
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC

# IMAGE_PATH = Path("./src/tux-72.png")           path error
# MODIFIED_IMAGE_PATH = Path("./src/ImageModified.png")
# PRIVATE_KEY_PATH = Path("./src/private_key.pem")
# PUBLIC_KEY_PATH = Path("./src/public_key.pem")

SCRIPT_DIR = Path(__file__).parent

IMAGE_PATH = SCRIPT_DIR / "src" / "tux-72.png"
MODIFIED_IMAGE_PATH = SCRIPT_DIR / "src" / "ImageModified.png"
PRIVATE_KEY_PATH = SCRIPT_DIR / "src" / "private_key.pem"
PUBLIC_KEY_PATH = SCRIPT_DIR / "src" / "public_key.pem"

priv_key = RSA.import_key(PRIVATE_KEY_PATH.read_bytes())
pub_key = RSA.import_key(PUBLIC_KEY_PATH.read_bytes())

image_data = IMAGE_PATH.read_bytes()
h = SHA256.new(image_data)

signature = pkcs1_15.new(priv_key).sign(h)
signature_b64 = base64.b64encode(signature).decode('utf-8')

print("Task 1")

print("signature (Base64):")
print(signature_b64)

try:
    pkcs1_15.new(pub_key).verify(h, signature)
    print("\nVerification Success (original image)")
except (ValueError, TypeError):
    print("\nVerification Failed (original image)")

b = bytearray(image_data)
b[len(b)//2] ^= 0xFF  # зміна зображення
MODIFIED_IMAGE_PATH.write_bytes(b)
h_mod = SHA256.new(bytes(b))

try:
    pkcs1_15.new(pub_key).verify(h_mod, signature)
    print("Verification Success (modified image) — unexpected")
except (ValueError, TypeError):
    print("Verification Failed (modified image) — as expected.")
    #в результаті навіть найменшої зміни при порівнянні файлів алгоритм бачить відмінність і не може верифікувати 


key = bytes.fromhex("5c8cd96c1749adb5f9ba379cfc546ec90d2b82dc927f6067dd444fb20e73ef32")

def compute_hmac(path: Path) -> str:
    data = path.read_bytes()
    hmac_obj = HMAC.new(key, digestmod=SHA256)
    hmac_obj.update(data)
    return hmac_obj.hexdigest()

original_hmac = compute_hmac(IMAGE_PATH)
modified_hmac = compute_hmac(MODIFIED_IMAGE_PATH)

print("task2")
print("\noriginal hmac =", original_hmac)
print("\nmodified hmac =", modified_hmac)

if original_hmac == modified_hmac:  #ймовірно я неправильно зрозумів завдання, але я не знайшов іншого способу перевірки
    print("verification success, task error")
else:
    print("verification error, task success")