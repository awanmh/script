from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from typing import Tuple

def generate_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates a pair of RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(public_key: rsa.RSAPublicKey, message: bytes) -> bytes:
    """Encrypts a message using the public key."""
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decrypts a ciphertext using the private key."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_keys()
    
    # Message to encrypt
    original_message = b"Hello RSA"
    print(f"Original: {original_message}")

    # Encrypt
    encrypted_message = encrypt_message(public_key, original_message)
    print(f"Encrypted: {encrypted_message.hex()[:32]}...") # Print partial hex for brevity

    # Decrypt
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"Decrypted: {decrypted_message}")

