from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from typing import Tuple

def generate_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates a pair of RSA private and public keys."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """Signs a message using the private key and PSS padding."""
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> None:
    """Verifies the signature of a message using the public key."""
    public_key.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_keys()
    
    # Message to sign
    message = b"Important message to sign"
    print(f"Message: {message}")

    # Sign
    signature = sign_message(private_key, message)
    print(f"Signature: {signature.hex()[:32]}...")

    # Verify
    try:
        verify_signature(public_key, signature, message)
        print("Signature verified!")
    except Exception as e:
        print(f"Verification failed: {e}")