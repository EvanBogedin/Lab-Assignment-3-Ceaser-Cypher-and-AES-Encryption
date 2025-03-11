from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# Generate RSA keys
def generate_keys():
    # Generate a new RSA key pair (public and private keys) with a key size of 2048 bits
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt data using RSA
def encrypt_data(data, public_key):
    recipient_key = RSA.import_key(public_key)
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
    return enc_session_key, cipher_aes.nonce, tag, ciphertext

# Decrypt data using RSA
def decrypt_data(enc_session_key, nonce, tag, ciphertext, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data.decode("utf-8")

# User input
plain_text_message = input("\nPlease enter a plain text message: ")

# Encryption and decryption
private_key, public_key = generate_keys()
enc_session_key, nonce, tag, encrypted_message = encrypt_data(plain_text_message, public_key)
decrypted_message = decrypt_data(enc_session_key, nonce, tag, encrypted_message, private_key)

# Prints
print("Encrypted: ", encrypted_message)
print("Decrypted: ", decrypted_message)