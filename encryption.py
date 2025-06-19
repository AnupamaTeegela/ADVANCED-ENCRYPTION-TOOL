from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import os

class AdvancedEncryptionTool:
    def __init__(self, password):
        self.salt = b'static_salt_16b'  # Use random salt and store it securely in production
        self.key = PBKDF2(password, self.salt, dkLen=32, count=100_000)

    def pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + chr(pad_len) * pad_len

    def unpad(self, data):
        return data[:-ord(data[-1:])]

    def encrypt(self, plaintext):
        plaintext = self.pad(plaintext)
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, b64_ciphertext):
        raw = base64.b64decode(b64_ciphertext)
        iv = raw[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(raw[16:])
        return self.unpad(decrypted.decode())

# --- Example Usage ---
if __name__ == "__main__":
    password = input("Enter password for encryption: ")
    tool = AdvancedEncryptionTool(password)

    text = input("Enter text to encrypt: ")
    encrypted = tool.encrypt(text)
    print("Encrypted:", encrypted)

    decrypted = tool.decrypt(encrypted)
    print("Decrypted:", decrypted)
