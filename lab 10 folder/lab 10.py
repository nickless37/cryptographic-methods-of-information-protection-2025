from PIL import Image
import numpy as np
import wave


def hide_message(img_path, out_path, message):
    # img = Image.open(img_path).convert("RGB")
    img = Image.open(img_path)
    if img.mode == "RGBA":
        white_bg = Image.new("RGB", img.size, (255, 255, 255))
        img = Image.alpha_composite(white_bg.convert("RGBA"), img)
        img = img.convert("RGB")

    pixels = np.array(img).flatten()
    
    message_bytes = message.encode('utf-8') + b'\x00'  #пустий байт позначає кінець повідомлення
    bits = np.unpackbits(np.frombuffer(message_bytes, dtype=np.uint8))
    
    if len(bits) > len(pixels):
        raise ValueError("Message too long for image")
    
    pixels[:len(bits)] &= 0b11111110       # обнуленняLSB
    pixels[:len(bits)] |= bits             # запис бітів
    
    img_out = Image.fromarray(pixels.reshape(img.size[1], img.size[0], 3))
    img_out.save(out_path)
    print("file saved")

def extract_message(stego_img_path):
    img = Image.open(stego_img_path).convert("RGB")
    data = np.array(img).flatten()
    bits = data & 1
    bytes_out = np.packbits(bits)
    end_idx = np.where(bytes_out == 0)[0]
    if len(end_idx) > 0:
        bytes_out = bytes_out[:end_idx[0]]
    return bytes(bytes_out).decode('utf-8', errors='ignore')



from pathlib import Path


SCRIPT_DIR = Path(__file__).parent  #треба було вказати раніше, але на момент написання минулих робіт я не вважав цю деталь важливою. капсове найменування змінних у пайтон (і більшості інших мов) позначає її як константу. у пайтон це не впливає на код і використовується для позначення незмінних деталей лише для програміста. програма може змінити таку змінну при виконанні 

RAWIMG = SCRIPT_DIR / "src" / "clear img.png"

SRC = SCRIPT_DIR / "src" / "edited img.png"
SRC2 = SCRIPT_DIR / "src" / "tux_stego.png"

# test
print("\nTask 1")

hide_message(RAWIMG, SRC, "any testing text і кирилиця")

# print("hiden testing message:", extract_message(SRC))

print("hiden message:", extract_message(SRC2))
# за виключенням заднього фону, який будується при перетворенні форматів, видимих відмінностей нема



def hide_message_audio(input_wav, output_wav, message):
    input_wav = str(input_wav)
    output_wav = str(output_wav)
    
    with wave.open(input_wav, 'rb') as wav:
        params = wav.getparams()
        frames = wav.readframes(params.nframes)

    samples = np.frombuffer(frames, dtype=np.int16).copy()

    message_bytes = message.encode('utf-8') + b'\x00'
    bits = np.unpackbits(np.frombuffer(message_bytes, dtype=np.uint8))

    if len(bits) > len(samples):
        raise ValueError("Message too long for this audio file")

    #LSB 
    samples_uint16 = samples.astype(np.uint16)
    samples_uint16[:len(bits)] = (samples_uint16[:len(bits)] & 0xFFFE) | bits
    samples = samples_uint16.astype(np.int16)

    with wave.open(output_wav, 'wb') as wav_out:
        wav_out.setparams(params)
        wav_out.writeframes(samples.tobytes())

    print("Message hidden successfully in audio.")

def extract_message_audio(stego_wav):
    stego_wav = str(stego_wav)
    
    with wave.open(stego_wav, 'rb') as wav:
        frames = wav.readframes(wav.getnframes())

    samples = np.frombuffer(frames, dtype=np.int16)
    bits = (samples.astype(np.uint16) & 1).astype(np.uint8)
    bytes_out = np.packbits(bits)
    # пошук до пустого байта
    end_idx = np.where(bytes_out == 0)[0]
    if len(end_idx) > 0:
        bytes_out = bytes_out[:end_idx[0]]

    return bytes(bytes_out).decode('utf-8', errors='ignore')



# test2

SRCA = SCRIPT_DIR / "src" / "raw_audio.wav"
SRCAEDITED = SCRIPT_DIR / "src" / "edited_audio.wav"
SRCA2 = SCRIPT_DIR / "src" / "Labs_data_sample_hidden.wav"

print("\nTask 2")

hide_message_audio(SRCA, SRCAEDITED, "any testing text і кирилиця")


# print("hiden in audio testing message:", extract_message_audio(SRCAEDITED))
# у створеному файлі помітних пошкоджень або змін нема
print("hiden audio message:", extract_message_audio(SRCA2))