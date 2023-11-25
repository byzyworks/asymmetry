#!/usr/bin/env python3

from cryptography.hazmat.backends              import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives            import hashes
from cryptography.hazmat.primitives            import serialization

class AsymmetricKey:
    def __init__(self):
        self.key = None

    def importPassword(self, passFile):
        if passFile == None:
            return None
        with open(passFile, "rb") as f:
            return f.read().rstrip()

    def importKey(self, keyPath, doEncrypt = True, passFile = None):
        # Import the key
        if doEncrypt:
            with open(keyPath, "rb") as key_file:
                self.key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend = default_backend()
                )
        else:
            with open(keyPath, "rb") as key_file:
                self.key = serialization.load_pem_private_key(
                    key_file.read(),
                    password = self.importPassword(passFile),
                    backend  = default_backend()
                )

        return self.key
    
    def encrypt(self, message):
        return self.key.encrypt(
            message,
            padding.OAEP(
                mgf       = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label     = None
            )
        )

    def decrypt(self, message):
        return self.key.decrypt(
            message,
            padding.OAEP(
                mgf       = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label     = None
            )
        )