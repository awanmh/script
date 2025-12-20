from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(password)

if __name__ == "__main__":
    password = b"password123"
    salt = os.urandom(16)
    
    key = derive_key(password, salt)    
    print("Derived key:", key)