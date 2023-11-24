#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class SymmetricKey:
    def __init__(self):
        self.key = None
    
    def generate(self):
        self.key = get_random_bytes(32)

        return self.key
    
    def importKey(self, key):
        self.key = key

        return self.key
    
    def encrypt(self, message):
        cipher          = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message)

        return cipher.nonce + tag + ciphertext

    def decrypt(self, message):
        nonce      = message[:16]
        tag        = message[16:32]
        ciphertext = message[32:]

        cipher = AES.new(self.key, AES.MODE_EAX, nonce)

        return cipher.decrypt_and_verify(ciphertext, tag)