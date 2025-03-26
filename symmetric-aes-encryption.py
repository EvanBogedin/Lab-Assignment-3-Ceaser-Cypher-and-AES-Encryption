from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def encrypt_password(password):
    # Create an AES cipher
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Add padding to the password
    padding_length = 16 - (len(password) % 16)
    padded_password = password + chr(padding_length) * padding_length
    encrypted_password = cipher.encrypt(padded_password.encode())
    return key.hex(), iv.hex(), encrypted_password.hex()

def decrypt_password(key, iv, encrypted_password):
    # Convert key and iv from hex to bytes
    key_bytes = bytes.fromhex(key)
    iv_bytes = bytes.fromhex(iv)
    
    # Create an AES cipher
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    
    # Decrypt the encrypted password
    decrypted_padded_password = cipher.decrypt(bytes.fromhex(encrypted_password)).decode()
    
    # Remove padding from the decrypted password
    padding_length = ord(decrypted_padded_password[-1])
    decrypted_password = decrypted_padded_password[:-padding_length]
    return decrypted_password
# user input
plain_test_message = input("\nPlease enter a plain text message: ")

key, iv, encrypted_password = encrypt_password(plain_test_message)
decrypted_password = decrypt_password(key, iv, encrypted_password)
decrypted_password = decrypt_password(key, iv, encrypted_password)

# prints
print("Encrypted: ", encrypted_password)
print("Decrypted :", decrypted_password)