from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

KEY = b'ThisIsASecretKey'  # 16 bytes for AES-128, change it for real app

def encrypt_file(input_file_path, output_file_path):
    with open(input_file_path, 'rb') as f:
        data = f.read()

    cipher = AES.new(KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))

    with open(output_file_path, 'wb') as f:
        f.write(cipher.iv)        # Write IV at the start of file
        f.write(ct_bytes)

def decrypt_file(encrypted_path, output_path):
    with open(encrypted_path, 'rb') as f:
        iv = f.read(16)
        ct = f.read()

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)

    with open(output_path, 'wb') as f:
        f.write(pt)