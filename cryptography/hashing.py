import hashlib

def hash_data(data: bytes) -> str:
    """Hashes data using SHA-256 and returns the hex digest."""
    return hashlib.sha256(data).hexdigest()

if __name__ == "__main__":
    data = b"Important Data"
    digest = hash_data(data)
    print("SHA-256 Hash:", digest)