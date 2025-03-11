from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def encrypt_password(password):
    # Create an AES cipher
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the password
    encrypted_password = cipher.encrypt(password)
    
    return key.hex(), iv.hex(), encrypted_password.hex()

def decrypt_password(key, iv, encrypted_password):
    # Create an AES cipher
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    
    decrypted_password = (cipher.decrypt(encrypted_password.encode())).decode()
    
    return decrypt_password


plain_test_message = input("\nPlease enter a plain text message: ")
key, iv, encrypted_password = encrypt_password(plain_test_message)
decrypted_password = decrypt_password(key, iv, encrypted_password)


# prints
print("Encrypted: ", encrypted_password)
print("Decrypted :", decrypted_password)