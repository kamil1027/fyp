import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def validate_password(encoded_password, salt, stored_password):
    try:
        combined = (stored_password + salt).encode('utf-8')
        hashed_password = hashlib.sha256(combined).hexdigest()
        return encoded_password == hashed_password
    except Exception as e:
        print(f"Error decoding password: {e}")
        return None

def decrypt_password(encrypted_password, key):
    encrypted_password, nonce = encrypted_password.split(':')
    chacha = ChaCha20Poly1305(key)
    decrypted_password = chacha.decrypt(bytes.fromhex(nonce), bytes.fromhex(encrypted_password), None)
    return decrypted_password.decode()
